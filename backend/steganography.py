import os
from PIL import Image
import numpy as np

STEGO_HEADER = b"SSAI"  # 4 bytes signature

class SteganographyEngine:
    """
    LSB (Least Significant Bit) Steganography Engine for Lossless Image Formats (PNG, BMP, TIFF).
    Conceals encrypted binary payloads into the least significant bit of RGB pixel color channels.
    """

    @staticmethod
    def get_image_capacity(image_path: str) -> dict:
        """
        Calculate embedding capacity of an image in bytes.
        """
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image not found at {image_path}")

        with Image.open(image_path) as img:
            img_rgb = img.convert("RGB")
            width, height = img_rgb.size
            total_pixels = width * height
            total_channels = total_pixels * 3  # R, G, B channels
            # Total bits available = total_channels
            # Header size = 4 bytes (signature) + 4 bytes (length int) = 8 bytes = 64 bits
            header_size = 8
            max_payload_bytes = (total_channels // 8) - header_size
            
            return {
                "width": width,
                "height": height,
                "total_pixels": total_pixels,
                "total_channels": total_channels,
                "max_payload_bytes": max(0, max_payload_bytes)
            }

    @classmethod
    def embed_data(cls, image_path: str, data_bytes: bytes, output_path: str) -> str:
        """
        Embed binary payload into the LSBs of image_path and save result to output_path.
        """
        capacity_info = cls.get_image_capacity(image_path)
        payload_len = len(data_bytes)

        if payload_len > capacity_info["max_payload_bytes"]:
            raise ValueError(
                f"Payload size ({payload_len} bytes) exceeds image maximum capacity "
                f"({capacity_info['max_payload_bytes']} bytes)."
            )

        # Construct full stego byte stream: HEADER (4b) + PAYLOAD_LEN (4b) + PAYLOAD
        full_stream = STEGO_HEADER + payload_len.to_bytes(4, byteorder="big") + data_bytes

        # Convert byte stream into flat numpy array of bits (0 or 1)
        bits = np.unpackbits(np.frombuffer(full_stream, dtype=np.uint8))
        num_bits = len(bits)

        # Load image as numpy array of uint8 (RGB)
        with Image.open(image_path) as img:
            img_rgb = img.convert("RGB")
            img_np = np.array(img_rgb, dtype=np.uint8)

        # Flatten pixel array
        flat_pixels = img_np.flatten()

        # Overwrite LSB of pixel channels with payload bits
        # Clear LSB (flat_pixels & 0xFE) and OR with bit
        flat_pixels[:num_bits] = (flat_pixels[:num_bits] & np.uint8(0xFE)) | bits

        # Reshape back to original image dimensions
        stego_np = flat_pixels.reshape(img_np.shape)
        stego_img = Image.fromarray(stego_np, mode="RGB")

        # Ensure output folder exists
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        # Save output image strictly in PNG format to preserve LSB data
        stego_img.save(output_path, format="PNG")
        return output_path

    @classmethod
    def extract_data(cls, image_path: str) -> bytes:
        """
        Extract hidden binary payload from the LSBs of image_path.
        """
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image not found at {image_path}")

        with Image.open(image_path) as img:
            img_rgb = img.convert("RGB")
            img_np = np.array(img_rgb, dtype=np.uint8)

        flat_pixels = img_np.flatten()
        total_bits = len(flat_pixels)

        # Header requires 8 bytes = 64 bits
        if total_bits < 64:
            raise ValueError("Image too small to contain a StegoShield payload.")

        # Extract first 64 LSBs for header validation
        header_bits = flat_pixels[:64] & 1
        header_bytes = np.packbits(header_bits).tobytes()

        magic = header_bytes[:4]
        if magic != STEGO_HEADER:
            raise ValueError("No valid StegoShield AI payload signature found in this image.")

        payload_len = int.from_bytes(header_bytes[4:8], byteorder="big")
        total_payload_bits = payload_len * 8
        required_total_bits = 64 + total_payload_bits

        if required_total_bits > total_bits:
            raise ValueError("Corrupted stego header: declared payload length exceeds image size.")

        # Extract payload LSB bits
        payload_bits = flat_pixels[64:required_total_bits] & 1
        payload_bytes = np.packbits(payload_bits).tobytes()

        return payload_bytes

if __name__ == "__main__":
    # Test script
    from PIL import ImageDraw

    # Create dummy PNG image for testing
    test_img_path = "test_input.png"
    test_out_path = "test_stego.png"

    img = Image.new("RGB", (200, 200), color="deepskyblue")
    draw = ImageDraw.Draw(img)
    draw.rectangle([20, 20, 180, 180], fill="midnightblue")
    img.save(test_img_path)

    test_payload = b"TEST_ENCRYPTED_PAYLOAD_BYTES_XYZ"
    SteganographyEngine.embed_data(test_img_path, test_payload, test_out_path)
    extracted = SteganographyEngine.extract_data(test_out_path)

    print("Original payload:", test_payload)
    print("Extracted payload:", extracted)
    assert test_payload == extracted, "Steganography test failed!"
    print("Steganography engine test passed successfully!")

    # Cleanup temp test files
    if os.path.exists(test_img_path): os.remove(test_img_path)
    if os.path.exists(test_out_path): os.remove(test_out_path)
