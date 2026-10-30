import os
import sys
import wave
import numpy as np
from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from encryption import EncryptionEngine, VaultCipher
from steganography import SteganographyEngine
from audio_stego import AudioSteganographyEngine
from video_stego import VideoSteganographyEngine
from text_stego import TextSteganographyEngine
from quality_analysis import QualityAnalyzer
from capacity import CapacityCalculator
import database

def run_tests():
    print("==========================================")
    print("  STEGOSHIELD AI CYBERSECURITY TEST SUITE ")
    print("==========================================")

    # 1. Test Encryption Engine
    print("\n[1/6] Testing AES-256 Encryption & Decryption...")
    secret_text = "CLASSIFIED PAYLOAD @ 2026"
    passphrase = "CyberShieldKey99#"
    encrypted_bytes = EncryptionEngine.encrypt_payload(secret_text, passphrase)
    decrypted_text = EncryptionEngine.decrypt_payload(encrypted_bytes, passphrase)
    assert decrypted_text == secret_text, "AES Encryption test failed!"
    print("  ✓ AES-256 GCM encryption & decryption verified PASSED!")

    # 2. Test Image Steganography Engine
    print("\n[2/6] Testing LSB Image Steganography Engine...")
    test_cover_img = os.path.join(os.path.dirname(__file__), "test_cover.png")
    test_stego_img = os.path.join(os.path.dirname(__file__), "test_stego.png")
    img = Image.new("RGB", (250, 250), color=(15, 23, 42))
    img.save(test_cover_img)

    SteganographyEngine.embed_data(test_cover_img, encrypted_bytes, test_stego_img)
    extracted_img_bytes = SteganographyEngine.extract_data(test_stego_img)
    assert decrypted_text == EncryptionEngine.decrypt_payload(extracted_img_bytes, passphrase)
    print("  ✓ Image LSB embedding & extraction verified PASSED!")

    # 3. Test Audio Steganography Engine
    print("\n[3/6] Testing WAV Audio LSB Steganography Engine...")
    test_cover_wav = os.path.join(os.path.dirname(__file__), "test_cover.wav")
    test_stego_wav = os.path.join(os.path.dirname(__file__), "test_stego.wav")

    with wave.open(test_cover_wav, 'wb') as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(44100)
        pcm_samples = np.zeros(44100, dtype=np.int16)
        wav.writeframes(pcm_samples.tobytes())

    AudioSteganographyEngine.embed_data(test_cover_wav, encrypted_bytes, test_stego_wav)
    extracted_wav_bytes = AudioSteganographyEngine.extract_data(test_stego_wav)
    assert decrypted_text == EncryptionEngine.decrypt_payload(extracted_wav_bytes, passphrase)
    print("  ✓ Audio LSB embedding & extraction verified PASSED!")

    # 4. Test Text Zero-Width Steganography Engine
    print("\n[4/6] Testing Zero-Width Text Steganography Engine...")
    cover_doc = "Official Government Cyber Notice."
    stego_text = TextSteganographyEngine.embed_data(cover_doc, encrypted_bytes)
    extracted_text_bytes = TextSteganographyEngine.extract_data(stego_text)
    assert decrypted_text == EncryptionEngine.decrypt_payload(extracted_text_bytes, passphrase)
    print("  ✓ Zero-width unicode text steganography verified PASSED!")

    # 5. Test Quality Analysis (PSNR, MSE, SSIM)
    print("\n[5/6] Testing Signal Quality Analysis Engine (PSNR/MSE/SSIM)...")
    diff_map_path = os.path.join(os.path.dirname(__file__), "test_diff.png")
    quality_report = QualityAnalyzer.full_analysis(test_cover_img, test_stego_img, diff_map_path)
    print(f"  ✓ PSNR: {quality_report['psnr']} dB | MSE: {quality_report['mse']} | SSIM: {quality_report['ssim']}")
    assert quality_report['psnr'] >= 40.0, "PSNR should be high for LSB steganography!"
    print("  ✓ Signal quality metrics test PASSED!")

    # 6. Test Encrypted Vault & Database Operations
    print("\n[6/6] Testing Encrypted Vault & Database Features...")
    cap_res = CapacityCalculator.analyze_file_capacity(test_cover_img, len(encrypted_bytes))
    assert cap_res['is_supported'] == True

    VaultCipher.init("test_suite_vault_key_12345")
    database.init_db()
    database.register_user("vault_operator", "operator@shield.ai", "VaultSecurePass123!")
    user, _ = database.authenticate_user("vault_operator", "VaultSecurePass123!")
    assert user is not None

    # Test adding vault item
    database.add_vault_item(user['id'], "Test Secret Key", "Image stego key", passphrase)
    vault_items = database.get_user_vault(user['id'])
    assert len(vault_items) > 0
    print(f"  ✓ Saved vault items count: {len(vault_items)}")

    # Cleanup vault item
    database.delete_vault_item(user['id'], vault_items[0]['id'])
    print("  ✓ Encrypted Vault & Database operations PASSED!")

    # Cleanup temp test files
    for p in [test_cover_img, test_stego_img, test_cover_wav, test_stego_wav, diff_map_path]:
        if os.path.exists(p): os.remove(p)

    print("\n==========================================")
    print("  ALL 6 DEFENSE SYSTEM TESTS PASSED 100%! ")
    print("==========================================")

if __name__ == "__main__":
    run_tests()
