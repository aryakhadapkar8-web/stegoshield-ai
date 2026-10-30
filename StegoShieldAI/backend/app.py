import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory, abort
from werkzeug.utils import secure_filename

import database
from encryption import EncryptionEngine, VaultCipher
from steganography import SteganographyEngine
from audio_stego import AudioSteganographyEngine
from video_stego import VideoSteganographyEngine
from text_stego import TextSteganographyEngine
from quality_analysis import QualityAnalyzer
from capacity import CapacityCalculator
from detection import SteganalysisDetector

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, '..', 'frontend'))
TEMPLATE_FOLDER = os.path.join(FRONTEND_DIR, 'templates')
STATIC_FOLDER = os.path.join(FRONTEND_DIR, 'static')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
OUTPUT_FOLDER = os.path.join(BASE_DIR, 'output')
ALLOWED_IMAGE_EXT = {'png', 'jpg', 'jpeg', 'bmp', 'webp'}
ALLOWED_AUDIO_EXT = {'wav'}
ALLOWED_VIDEO_EXT = {'mp4', 'avi', 'mkv', 'mov'}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

app = Flask(
    __name__,
    template_folder=TEMPLATE_FOLDER,
    static_folder=STATIC_FOLDER
)

def load_app_secret() -> str:
    env_key = os.environ.get("STEGOSHIELD_SECRET_KEY", "").strip()
    if env_key:
        return env_key
    secret_path = os.path.join(BASE_DIR, ".secret_key")
    if os.path.exists(secret_path):
        with open(secret_path, "r", encoding="utf-8") as handle:
            stored = handle.read().strip()
            if stored:
                return stored
    generated = os.urandom(32).hex()
    with open(secret_path, "w", encoding="utf-8") as handle:
        handle.write(generated)
    return generated

app.secret_key = load_app_secret()
VaultCipher.init(app.secret_key)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32 MB upload limit

database.init_db()

def remember_output(filename: str) -> None:
    if not filename:
        return
    allowed = list(session.get("allowed_outputs") or [])
    if filename not in allowed:
        allowed.append(filename)
        session["allowed_outputs"] = allowed

def log_user_operation(**kwargs) -> None:
    user_id = session.get("user_id")
    if not user_id:
        return
    database.log_operation(user_id=user_id, **kwargs)

def image_stego_score(path: str) -> float:
    try:
        return float(SteganalysisDetector.analyze_image(path)["stego_score"])
    except Exception:
        return 0.0

def allowed_file(filename: str, allowed_set: set) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_set

# ----------------- PAGE ROUTES -----------------

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/encode', methods=['GET', 'POST'])
def encode():
    if request.method == 'POST':
        file = request.files.get('cover_file')
        secret_message = request.form.get('secret_message', '').strip()
        passphrase = request.form.get('passphrase', '').strip()

        if not file or file.filename == '':
            flash("Please upload a valid cover file.", 'error')
            return redirect(request.url)

        if not secret_message:
            flash("Secret message cannot be empty.", 'error')
            return redirect(request.url)

        if not passphrase:
            flash("Security encryption key is required.", 'error')
            return redirect(request.url)

        try:
            filename = secure_filename(file.filename)
            unique_id = uuid.uuid4().hex[:8]
            ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'png'

            input_path = os.path.join(app.config['UPLOAD_FOLDER'], f"cov_{unique_id}_{filename}")
            file.save(input_path)

            encrypted_payload = EncryptionEngine.encrypt_payload(secret_message, passphrase)
            stego_score = 0.0
            media_kind = "Encode"

            if ext in ALLOWED_IMAGE_EXT:
                out_filename = f"stego_{unique_id}.png"
                output_path = os.path.join(app.config['OUTPUT_FOLDER'], out_filename)
                SteganographyEngine.embed_data(input_path, encrypted_payload, output_path)
                stego_score = image_stego_score(output_path)
                media_kind = "Encode-Image"
            elif ext in ALLOWED_AUDIO_EXT:
                out_filename = f"stego_{unique_id}.wav"
                output_path = os.path.join(app.config['OUTPUT_FOLDER'], out_filename)
                AudioSteganographyEngine.embed_data(input_path, encrypted_payload, output_path)
                media_kind = "Encode-Audio"
            elif ext in ALLOWED_VIDEO_EXT:
                out_filename = f"stego_{unique_id}.mp4"
                output_path = os.path.join(app.config['OUTPUT_FOLDER'], out_filename)
                VideoSteganographyEngine.embed_data(input_path, encrypted_payload, output_path)
                media_kind = "Encode-Video"
            else:
                out_filename = f"stego_{unique_id}.png"
                output_path = os.path.join(app.config['OUTPUT_FOLDER'], out_filename)
                SteganographyEngine.embed_data(input_path, encrypted_payload, output_path)
                stego_score = image_stego_score(output_path)
                media_kind = "Encode-Image"

            remember_output(out_filename)
            log_user_operation(
                action_type=media_kind,
                filename=filename,
                output_filename=out_filename,
                payload_size=len(encrypted_payload),
                stego_score=stego_score,
                status='Success'
            )

            flash("Payload encrypted and successfully embedded inside media container!", 'success')
            return render_template('encode.html', output_file=out_filename, media_type=ext.upper())

        except Exception as e:
            flash(f"Encoding Failure: {str(e)}", 'error')
            return redirect(request.url)

    return render_template('encode.html')

@app.route('/decode', methods=['GET', 'POST'])
def decode():
    if request.method == 'POST':
        file = request.files.get('stego_file')
        passphrase = request.form.get('passphrase', '').strip()

        if not file or file.filename == '':
            flash("Please upload a stego file.", 'error')
            return redirect(request.url)

        if not passphrase:
            flash("Decryption key is required.", 'error')
            return redirect(request.url)

        try:
            filename = secure_filename(file.filename)
            unique_id = uuid.uuid4().hex[:8]
            ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''

            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"stego_in_{unique_id}_{filename}")
            file.save(temp_path)

            if ext in ALLOWED_AUDIO_EXT:
                extracted_bytes = AudioSteganographyEngine.extract_data(temp_path)
                stego_score = 0.0
            elif ext in ALLOWED_VIDEO_EXT:
                extracted_bytes = VideoSteganographyEngine.extract_data(temp_path)
                stego_score = 0.0
            else:
                extracted_bytes = SteganographyEngine.extract_data(temp_path)
                stego_score = image_stego_score(temp_path) if ext in ALLOWED_IMAGE_EXT else 0.0

            decrypted_text = EncryptionEngine.decrypt_payload(extracted_bytes, passphrase)

            log_user_operation(
                action_type='Decode',
                filename=filename,
                output_filename=None,
                payload_size=len(extracted_bytes),
                stego_score=stego_score,
                status='Success'
            )

            flash("Secret payload extracted and decrypted successfully!", 'success')
            return render_template('decode.html', decrypted_message=decrypted_text)

        except Exception as e:
            flash(f"Extraction Error: {str(e)}", 'error')
            return redirect(request.url)

    return render_template('decode.html')

@app.route('/steganography/image', methods=['GET', 'POST'])
def image_stego():
    if request.method == 'POST':
        file = request.files.get('image')
        secret_message = request.form.get('secret_message', '').strip()
        passphrase = request.form.get('passphrase', '').strip()

        if not file or not secret_message or not passphrase:
            flash("All fields (Image, Secret Message, Key) are required.", 'error')
            return redirect(request.url)

        try:
            filename = secure_filename(file.filename)
            unique_id = uuid.uuid4().hex[:8]
            input_path = os.path.join(app.config['UPLOAD_FOLDER'], f"img_cov_{unique_id}_{filename}")
            file.save(input_path)

            encrypted_payload = EncryptionEngine.encrypt_payload(secret_message, passphrase)
            out_filename = f"stego_img_{unique_id}.png"
            output_path = os.path.join(app.config['OUTPUT_FOLDER'], out_filename)
            SteganographyEngine.embed_data(input_path, encrypted_payload, output_path)

            analysis = SteganalysisDetector.analyze_image(output_path)
            quality = QualityAnalyzer.full_analysis(
                input_path, output_path,
                os.path.join(app.config['OUTPUT_FOLDER'], f"diff_{unique_id}.png")
            )

            remember_output(out_filename)
            log_user_operation(
                action_type='Encode-Image',
                filename=filename,
                output_filename=out_filename,
                payload_size=len(encrypted_payload),
                stego_score=float(analysis.get('stego_score', 0)),
                status='Success'
            )

            return render_template(
                'image_stego.html',
                output_file=out_filename,
                cover_file=os.path.basename(input_path),
                analysis=analysis,
                quality=quality
            )
        except Exception as e:
            flash(f"Image Encoding Error: {str(e)}", 'error')
            return redirect(request.url)

    return render_template('image_stego.html')

@app.route('/steganography/audio', methods=['GET', 'POST'])
def audio_stego():
    if request.method == 'POST':
        file = request.files.get('audio')
        secret_message = request.form.get('secret_message', '').strip()
        passphrase = request.form.get('passphrase', '').strip()

        if not file or not secret_message or not passphrase:
            flash("Audio WAV file, secret message, and key are required.", 'error')
            return redirect(request.url)

        try:
            filename = secure_filename(file.filename)
            unique_id = uuid.uuid4().hex[:8]
            input_path = os.path.join(app.config['UPLOAD_FOLDER'], f"aud_cov_{unique_id}_{filename}")
            file.save(input_path)

            encrypted_payload = EncryptionEngine.encrypt_payload(secret_message, passphrase)
            out_filename = f"stego_audio_{unique_id}.wav"
            output_path = os.path.join(app.config['OUTPUT_FOLDER'], out_filename)
            AudioSteganographyEngine.embed_data(input_path, encrypted_payload, output_path)

            cap = AudioSteganographyEngine.get_audio_capacity(output_path)
            remember_output(out_filename)
            log_user_operation(
                action_type='Encode-Audio',
                filename=filename,
                output_filename=out_filename,
                payload_size=len(encrypted_payload),
                stego_score=0.0,
                status='Success'
            )
            flash("Audio steganography successful!", 'success')
            return render_template('audio_stego.html', output_file=out_filename, audio_info=cap)
        except Exception as e:
            flash(f"Audio Encoding Error: {str(e)}", 'error')
            return redirect(request.url)

    return render_template('audio_stego.html')

@app.route('/steganography/video', methods=['GET', 'POST'])
def video_stego():
    if request.method == 'POST':
        file = request.files.get('video')
        secret_message = request.form.get('secret_message', '').strip()
        passphrase = request.form.get('passphrase', '').strip()

        if not file or not secret_message or not passphrase:
            flash("MP4 video file, secret message, and key are required.", 'error')
            return redirect(request.url)

        try:
            filename = secure_filename(file.filename)
            unique_id = uuid.uuid4().hex[:8]
            input_path = os.path.join(app.config['UPLOAD_FOLDER'], f"vid_cov_{unique_id}_{filename}")
            file.save(input_path)

            encrypted_payload = EncryptionEngine.encrypt_payload(secret_message, passphrase)
            out_filename = f"stego_video_{unique_id}.mp4"
            output_path = os.path.join(app.config['OUTPUT_FOLDER'], out_filename)
            VideoSteganographyEngine.embed_data(input_path, encrypted_payload, output_path)

            remember_output(out_filename)
            log_user_operation(
                action_type='Encode-Video',
                filename=filename,
                output_filename=out_filename,
                payload_size=len(encrypted_payload),
                stego_score=0.0,
                status='Success'
            )
            flash("Video steganography frame embedding completed!", 'success')
            return render_template('video_stego.html', output_file=out_filename)
        except Exception as e:
            flash(f"Video Encoding Error: {str(e)}", 'error')
            return redirect(request.url)

    return render_template('video_stego.html')

@app.route('/steganography/text', methods=['GET', 'POST'])
def text_stego():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'encode':
            cover_text = request.form.get('cover_text', '').strip()
            secret_message = request.form.get('secret_message', '').strip()
            passphrase = request.form.get('passphrase', '').strip()

            if not secret_message or not passphrase:
                flash("Secret message and encryption passphrase are required.", 'error')
                return redirect(request.url)

            try:
                encrypted_payload = EncryptionEngine.encrypt_payload(secret_message, passphrase)
                stego_text = TextSteganographyEngine.embed_data(cover_text, encrypted_payload)
                log_user_operation(
                    action_type='Encode-Text',
                    filename='cover_text',
                    output_filename=None,
                    payload_size=len(encrypted_payload),
                    stego_score=0.0,
                    status='Success'
                )
                return render_template('text_stego.html', generated_stego_text=stego_text)
            except Exception as e:
                flash(f"Text Steganography Error: {str(e)}", 'error')
                return redirect(request.url)

        elif action == 'decode':
            stego_text = request.form.get('stego_text', '')
            passphrase = request.form.get('passphrase', '').strip()

            if not stego_text or not passphrase:
                flash("Stego text and passphrase are required.", 'error')
                return redirect(request.url)

            try:
                extracted_bytes = TextSteganographyEngine.extract_data(stego_text)
                decrypted_message = EncryptionEngine.decrypt_payload(extracted_bytes, passphrase)
                log_user_operation(
                    action_type='Decode-Text',
                    filename='stego_text',
                    output_filename=None,
                    payload_size=len(extracted_bytes),
                    stego_score=0.0,
                    status='Success'
                )
                return render_template('text_stego.html', extracted_message=decrypted_message)
            except Exception as e:
                flash(f"Extraction Error: {str(e)}", 'error')
                return redirect(request.url)

    return render_template('text_stego.html')

@app.route('/tools/capacity-checker', methods=['GET', 'POST'])
def capacity_checker():
    result = None
    if request.method == 'POST':
        file = request.files.get('cover_file')
        secret_size = request.form.get('secret_size', 0)
        try:
            secret_size = int(secret_size)
        except ValueError:
            secret_size = 0

        if file and file.filename != '':
            filename = secure_filename(file.filename)
            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"cap_{uuid.uuid4().hex[:6]}_{filename}")
            file.save(temp_path)
            try:
                result = CapacityCalculator.analyze_file_capacity(temp_path, secret_size)
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
    return render_template('capacity_checker.html', result=result)

@app.route('/tools/quality-analysis', methods=['GET', 'POST'])
def quality_analysis():
    report = None
    is_authenticated = bool(session.get('user_id'))
    if request.method == 'POST':
        cover_file = request.files.get('cover_image')
        stego_file = request.files.get('stego_image')

        if cover_file and stego_file:
            unique_id = uuid.uuid4().hex[:6]
            c_path = os.path.join(app.config['UPLOAD_FOLDER'], f"qa_c_{unique_id}_{secure_filename(cover_file.filename)}")
            s_path = os.path.join(app.config['UPLOAD_FOLDER'], f"qa_s_{unique_id}_{secure_filename(stego_file.filename)}")
            diff_out = os.path.join(app.config['OUTPUT_FOLDER'], f"qa_diff_{unique_id}.png")

            cover_file.save(c_path)
            stego_file.save(s_path)

            try:
                report = QualityAnalyzer.full_analysis(c_path, s_path, diff_out)
                if report and report.get("diff_heatmap_file"):
                    remember_output(report["diff_heatmap_file"])
            except Exception as e:
                flash(f"Quality Analysis Error: {str(e)}", 'error')
            finally:
                for p in [c_path, s_path]:
                    if os.path.exists(p): os.remove(p)

    return render_template('quality_analysis.html', report=report, is_authenticated=is_authenticated)

@app.route('/learn/how-it-works')
def how_it_works():
    return render_template('how_it_works.html')

@app.route('/learn/steganography')
def learn():
    return render_template('learn.html')

@app.route('/about')
def about():
    return render_template('about.html')


# ----------------- AUTHENTICATED MEMBER FEATURES -----------------

@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        flash("Please sign in or register an account to access My Files workspace.", 'error')
        return redirect(url_for('login'))

    user = database.get_user_by_id(user_id)
    search_query = request.args.get('q', '').strip()
    action_filter = request.args.get('action', '').strip()
    if action_filter not in ('Encode', 'Decode'):
        action_filter = ''

    history = database.get_user_history(user_id, query=search_query or None, action_filter=action_filter or None)
    for item in history:
        out_name = item.get('output_filename')
        item['file_available'] = bool(
            out_name and os.path.exists(os.path.join(app.config['OUTPUT_FOLDER'], out_name))
        )
    vault = database.get_user_vault(user_id)
    stats = database.get_user_stats(user_id)

    return render_template(
        'dashboard.html',
        user=user,
        history=history,
        vault=vault,
        stats=stats,
        search_query=search_query,
        action_filter=action_filter,
    )

@app.route('/history/delete/<int:history_id>', methods=['POST'])
def delete_history(history_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to manage history.", 'error')
        return redirect(url_for('login'))

    database.delete_history_item(user_id, history_id)
    flash("History log entry deleted successfully.", 'success')
    return redirect(url_for('dashboard'))

@app.route('/vault/add', methods=['POST'])
def add_vault():
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to save secret key vault items.", 'error')
        return redirect(url_for('login'))

    title = request.form.get('title', '').strip()
    note = request.form.get('note', '').strip()
    secret_key = request.form.get('secret_key', '').strip()

    if not title or not secret_key:
        flash("Title and Secret Key are required.", 'error')
        return redirect(url_for('dashboard'))

    database.add_vault_item(user_id, title, note, secret_key)
    flash("Secret key item saved to your personal encrypted vault!", 'success')
    return redirect(url_for('dashboard'))

@app.route('/vault/delete/<int:vault_id>', methods=['POST'])
def delete_vault(vault_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to manage vault.", 'error')
        return redirect(url_for('login'))

    database.delete_vault_item(user_id, vault_id)
    flash("Vault item deleted.", 'success')
    return redirect(url_for('dashboard'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        success, msg = database.register_user(username, email, password)
        if success:
            flash(msg, 'success')
            return redirect(url_for('login'))
        else:
            flash(msg, 'error')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email', '').strip()
        password = request.form.get('password', '').strip()

        user, msg = database.authenticate_user(username_or_email, password)
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['email'] = user['email']
            flash(f"Welcome back, {user['username']}! Member features unlocked.", 'success')
            return redirect(url_for('dashboard'))
        else:
            flash(msg, 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out safely.", 'success')
    return redirect(url_for('home'))

@app.route('/output/<filename>')
def get_output_file(filename):
    safe_name = secure_filename(filename)
    if not safe_name:
        abort(404)

    allowed = session.get('allowed_outputs') or []
    user_id = session.get('user_id')
    permitted = safe_name in allowed
    if not permitted and user_id:
        permitted = database.user_owns_output(user_id, safe_name)
    if not permitted:
        abort(403)

    return send_from_directory(app.config['OUTPUT_FOLDER'], safe_name)

if __name__ == '__main__':
    print("Starting StegoShield AI Cybersecurity Platform Server...")
    app.run(host='127.0.0.1', port=5000, debug=True)
