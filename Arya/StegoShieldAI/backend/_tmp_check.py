from io import BytesIO
from PIL import Image
from app import app

client = app.test_client()
client.post(
    "/login",
    data={"username_or_email": "qa_user", "password": "secret1"},
    follow_redirects=True,
)

buf = BytesIO()
Image.new("RGB", (64, 64), color=(12, 80, 160)).save(buf, format="PNG")
buf.seek(0)

r = client.post(
    "/encode",
    data={
        "secret_message": "hidden-payload",
        "passphrase": "key-123",
        "cover_file": (buf, "cover.png"),
    },
    content_type="multipart/form-data",
    follow_redirects=True,
)
print("encode status", r.status_code)
assert r.status_code == 200
assert b"Download Stego File" in r.data

r = client.get("/dashboard")
assert b"Encode-Image" in r.data
assert b"cover.png" in r.data
print("history logged")
