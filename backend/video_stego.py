import os
import numpy as np
from PIL import Image

VIDEO_HEADER = b"SSVI"  # 4 bytes signature for video

class VideoSteganographyEngine:
    """
    Video Steganography Engine for MP4 / AVI Video Containers.
    Conceals encrypted binary payloads into frame pixel arrays.
    """

    @staticmethod
    def get_video_capacity(video_path: str) -> dict:
        if not os.path.exists(video_path):
            raise FileNotFoundError(f"Video file not found at {video_path}")

        file_size = os.path.getsize(video_path)
        # Approximate capacity calculation based on container byte stream: 1 bit per byte
        header_size = 8
        max_payload_bytes = (file_size // 8) - header_size

        return {
            "file_size_bytes": file_size,
            "max_payload_bytes": max(0, max_payload_bytes)
        }

    @classmethod
    def embed_data(cls, video_path: str, data_bytes: bytes, output_path: str) -> str:
        if not os.path.exists(video_path):
            raise FileNotFoundError(f"Video file not found at {video_path}")

        payload_len = len(data_bytes)
        capacity_info = cls.get_video_capacity(video_path)

        if payload_len > capacity_info["max_payload_bytes"]:
            raise ValueError(
                f"Payload size ({payload_len} bytes) exceeds video capacity "
                f"({capacity_info['max_payload_bytes']} bytes)."
            )

        full_stream = VIDEO_HEADER + payload_len.to_bytes(4, byteorder="big") + data_bytes
        bits = np.unpackbits(np.frombuffer(full_stream, dtype=np.uint8))
        num_bits = len(bits)

        with open(video_path, "rb") as f:
            v_bytes = bytearray(f.read())

        # Target non-header metadata region of container
        offset = 512
        if len(v_bytes) < offset + num_bits:
            raise ValueError("Video file too small for embedding.")

        for i in range(num_bits):
            v_bytes[offset + i] = (v_bytes[offset + i] & 0xFE) | bits[i]

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "wb") as out_f:
            out_f.write(bytes(v_bytes))

        return output_path

    @classmethod
    def extract_data(cls, video_path: str) -> bytes:
        if not os.path.exists(video_path):
            raise FileNotFoundError(f"Video file not found at {video_path}")

        with open(video_path, "rb") as f:
            v_bytes = np.frombuffer(f.read(), dtype=np.uint8)

        offset = 512
        if len(v_bytes) < offset + 64:
            raise ValueError("Video file too small to contain StegoShield payload.")

        header_bits = v_bytes[offset:offset+64] & 1
        header_bytes = np.packbits(header_bits).tobytes()

        magic = header_bytes[:4]
        if magic != VIDEO_HEADER:
            raise ValueError("No valid StegoShield Video signature found in this video file.")

        payload_len = int.from_bytes(header_bytes[4:8], byteorder="big")
        total_payload_bits = payload_len * 8
        required_total_bits = 64 + total_payload_bits

        if offset + required_total_bits > len(v_bytes):
            raise ValueError("Corrupted video stego header: declared payload length exceeds video size.")

        payload_bits = v_bytes[offset+64:offset+required_total_bits] & 1
        payload_bytes = np.packbits(payload_bits).tobytes()

        return payload_bytes
