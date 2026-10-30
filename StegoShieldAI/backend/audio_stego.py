import os
import wave
import numpy as np

AUDIO_HEADER = b"SSAU"  # 4 bytes signature for audio

class AudioSteganographyEngine:
    """
    Audio LSB Steganography Engine for Uncompressed WAV PCM Audio Files.
    Conceals encrypted binary payloads into the least significant bit of audio sample bytes.
    """

    @staticmethod
    def get_audio_capacity(audio_path: str) -> dict:
        if not os.path.exists(audio_path):
            raise FileNotFoundError(f"Audio file not found at {audio_path}")

        with wave.open(audio_path, 'rb') as wav:
            n_channels = wav.getnchannels()
            sampwidth = wav.getsampwidth()
            framerate = wav.getframerate()
            n_frames = wav.getnframes()

            total_samples = n_frames * n_channels
            # Each sample byte can store 1 bit
            total_bytes_avail = total_samples * sampwidth
            header_size = 8  # 4 bytes signature + 4 bytes payload len
            max_payload_bytes = (total_bytes_avail // 8) - header_size

            duration_sec = round(n_frames / float(framerate), 2) if framerate > 0 else 0.0

            return {
                "channels": n_channels,
                "sample_width_bytes": sampwidth,
                "frame_rate": framerate,
                "total_frames": n_frames,
                "duration_seconds": duration_sec,
                "max_payload_bytes": max(0, max_payload_bytes)
            }

    @classmethod
    def embed_data(cls, audio_path: str, data_bytes: bytes, output_path: str) -> str:
        capacity_info = cls.get_audio_capacity(audio_path)
        payload_len = len(data_bytes)

        if payload_len > capacity_info["max_payload_bytes"]:
            raise ValueError(
                f"Payload size ({payload_len} bytes) exceeds WAV audio capacity "
                f"({capacity_info['max_payload_bytes']} bytes)."
            )

        full_stream = AUDIO_HEADER + payload_len.to_bytes(4, byteorder="big") + data_bytes
        bits = np.unpackbits(np.frombuffer(full_stream, dtype=np.uint8))
        num_bits = len(bits)

        with wave.open(audio_path, 'rb') as wav:
            params = wav.getparams()
            raw_frames = wav.readframes(params.nframes)

        frame_bytes = bytearray(raw_frames)
        if len(frame_bytes) < num_bits:
            raise ValueError("Audio file does not have enough sample bytes.")

        # Embed bit into LSB of each sample byte
        for i in range(num_bits):
            frame_bytes[i] = (frame_bytes[i] & 0xFE) | bits[i]

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with wave.open(output_path, 'wb') as out_wav:
            out_wav.setparams(params)
            out_wav.writeframes(bytes(frame_bytes))

        return output_path

    @classmethod
    def extract_data(cls, audio_path: str) -> bytes:
        if not os.path.exists(audio_path):
            raise FileNotFoundError(f"Audio file not found at {audio_path}")

        with wave.open(audio_path, 'rb') as wav:
            params = wav.getparams()
            raw_frames = wav.readframes(params.nframes)

        frame_bytes = np.frombuffer(raw_frames, dtype=np.uint8)
        if len(frame_bytes) < 64:
            raise ValueError("Audio file too short to contain StegoShield payload.")

        # Extract first 64 bits for header validation
        header_bits = frame_bytes[:64] & 1
        header_bytes = np.packbits(header_bits).tobytes()

        magic = header_bytes[:4]
        if magic != AUDIO_HEADER:
            raise ValueError("No valid StegoShield Audio signature found in this WAV file.")

        payload_len = int.from_bytes(header_bytes[4:8], byteorder="big")
        total_payload_bits = payload_len * 8
        required_total_bits = 64 + total_payload_bits

        if required_total_bits > len(frame_bytes):
            raise ValueError("Corrupted audio stego header: declared payload length exceeds audio size.")

        payload_bits = frame_bytes[64:required_total_bits] & 1
        payload_bytes = np.packbits(payload_bits).tobytes()

        return payload_bytes
