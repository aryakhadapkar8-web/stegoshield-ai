import os
from PIL import Image
from steganography import SteganographyEngine
from audio_stego import AudioSteganographyEngine
from video_stego import VideoSteganographyEngine
from text_stego import TextSteganographyEngine

class CapacityCalculator:
    """
    Unified Steganography Capacity Calculation Engine.
    Supports Image (PNG, BMP, JPG), Audio (WAV), Video (MP4, AVI), and Text files.
    """

    @staticmethod
    def analyze_file_capacity(file_path: str, secret_size_bytes: int = 0) -> dict:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found at {file_path}")

        filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

        media_type = "Unknown"
        max_payload_bytes = 0
        details = {}

        if ext in ['png', 'bmp', 'jpg', 'jpeg', 'webp']:
            media_type = "Image"
            try:
                info = SteganographyEngine.get_image_capacity(file_path)
                max_payload_bytes = info["max_payload_bytes"]
                details = {
                    "dimensions": f"{info['width']}x{info['height']}",
                    "total_pixels": info['total_pixels'],
                    "channels": 3
                }
            except Exception:
                max_payload_bytes = (file_size // 8)

        elif ext in ['wav']:
            media_type = "Audio"
            try:
                info = AudioSteganographyEngine.get_audio_capacity(file_path)
                max_payload_bytes = info["max_payload_bytes"]
                details = {
                    "channels": info["channels"],
                    "duration_sec": info["duration_seconds"],
                    "sample_rate": f"{info['frame_rate']} Hz"
                }
            except Exception:
                max_payload_bytes = (file_size // 8)

        elif ext in ['mp4', 'avi', 'mkv', 'mov']:
            media_type = "Video"
            try:
                info = VideoSteganographyEngine.get_video_capacity(file_path)
                max_payload_bytes = info["max_payload_bytes"]
                details = {
                    "file_size": f"{round(file_size / (1024*1024), 2)} MB"
                }
            except Exception:
                max_payload_bytes = (file_size // 8)

        elif ext in ['txt', 'doc', 'md']:
            media_type = "Text"
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                info = TextSteganographyEngine.get_text_capacity(content)
                max_payload_bytes = info["max_payload_bytes"]
                details = {
                    "character_count": info["char_count"],
                    "word_count": info["word_count"]
                }
            except Exception:
                max_payload_bytes = 10000
        else:
            media_type = "Generic File"
            max_payload_bytes = max(0, (file_size // 8) - 8)

        # Formatting
        def format_size(size_bytes: int) -> str:
            if size_bytes >= 1024 * 1024:
                return f"{round(size_bytes / (1024 * 1024), 2)} MB"
            elif size_bytes >= 1024:
                return f"{round(size_bytes / 1024, 2)} KB"
            else:
                return f"{size_bytes} Bytes"

        is_supported = (secret_size_bytes <= max_payload_bytes) if secret_size_bytes > 0 else True
        usage_pct = round((secret_size_bytes / max_payload_bytes) * 100, 1) if max_payload_bytes > 0 and secret_size_bytes > 0 else 0.0

        return {
            "filename": filename,
            "media_type": media_type,
            "file_size_formatted": format_size(file_size),
            "file_size_bytes": file_size,
            "max_payload_formatted": format_size(max_payload_bytes),
            "max_payload_bytes": max_payload_bytes,
            "secret_size_formatted": format_size(secret_size_bytes),
            "secret_size_bytes": secret_size_bytes,
            "usage_percent": min(100.0, usage_pct),
            "status": "✓ Supported" if is_supported else "❌ Payload Exceeds Capacity",
            "is_supported": is_supported,
            "details": details
        }
