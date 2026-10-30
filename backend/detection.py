import os
import math
from PIL import Image
import numpy as np
from steganography import STEGO_HEADER

class SteganalysisDetector:
    """
    AI & Statistical Steganalysis Engine.
    Detects LSB steganographic modifications using Bitplane Shannon Entropy,
    Chi-Square Pair-of-Values (PoV) histogram analysis, and Header Signature Scanning.
    """

    @staticmethod
    def calculate_shannon_entropy(bit_array: np.ndarray) -> float:
        """
        Calculates Shannon Entropy of a binary bit array (0 and 1).
        Max entropy for uniform random bits = 1.0 bit/symbol.
        """
        if len(bit_array) == 0:
            return 0.0
        p1 = np.mean(bit_array)
        p0 = 1.0 - p1
        if p0 <= 0 or p1 <= 0:
            return 0.0
        return float(- (p0 * math.log2(p0) + p1 * math.log2(p1)))

    @classmethod
    def analyze_image(cls, image_path: str) -> dict:
        """
        Analyzes image file for steganographic payloads and anomalies.
        Returns detailed statistical metrics and threat assessment.
        """
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image not found at {image_path}")

        with Image.open(image_path) as img:
            img_rgb = img.convert("RGB")
            img_np = np.array(img_rgb, dtype=np.uint8)

        width, height = img_rgb.size
        flat_pixels = img_np.flatten()
        total_channels = len(flat_pixels)

        # 1. Signature Check (StegoShield AI header detection)
        signature_found = False
        declared_payload_size = 0
        if total_channels >= 64:
            header_bits = flat_pixels[:64] & 1
            header_bytes = np.packbits(header_bits).tobytes()
            if header_bytes[:4] == STEGO_HEADER:
                signature_found = True
                declared_payload_size = int.from_bytes(header_bytes[4:8], byteorder="big")

        # 2. Extract LSB Bitplane
        lsb_plane = flat_pixels & 1

        # Calculate overall LSB entropy
        lsb_entropy = cls.calculate_shannon_entropy(lsb_plane)

        # 3. Chi-Square (PoV) Randomness Test on Channel Histograms
        # Count frequency of even/odd pairs (2k, 2k+1)
        pairs_chi_stat = 0.0
        pairs_count = 0

        # Sample up to 100,000 pixels for fast analysis
        sample_pixels = flat_pixels[:min(100_000, total_channels)]
        hist, _ = np.histogram(sample_pixels, bins=256, range=(0, 256))

        for k in range(0, 256, 2):
            y_2k = hist[k]
            y_2k1 = hist[k + 1]
            y_avg = (y_2k + y_2k1) / 2.0
            if y_avg > 0:
                pairs_chi_stat += ((y_2k - y_avg) ** 2 + (y_2k1 - y_avg) ** 2) / y_avg
                pairs_count += 1

        # Normalized Chi-Square anomaly score (higher means natural image, lower means equalized LSBs)
        # In natural images, pairs differ significantly -> chi_stat is higher
        # In stego images, pairs are equalized -> chi_stat approaches 0
        chi_anomaly_score = max(0.0, min(100.0, (1.0 - (pairs_chi_stat / max(1, pairs_count * 10))) * 100.0))

        # 4. Compute Final Stego Confidence Score (0% to 100%)
        if signature_found:
            stego_score = 99.8
            verdict = "CONFIRMED STEGO PAYLOAD"
            details = f"StegoShield AI header detected with {declared_payload_size} bytes encrypted payload."
        else:
            # Score based on entropy and chi anomaly
            # High LSB entropy (> 0.985) combined with low Chi-Square variance indicates artificial randomness
            entropy_factor = max(0.0, (lsb_entropy - 0.90) / 0.10) * 50.0
            chi_factor = chi_anomaly_score * 0.5
            stego_score = round(min(95.0, max(2.5, entropy_factor + chi_factor)), 1)

            if stego_score > 75.0:
                verdict = "SUSPICIOUS (High LSB Entropy)"
                details = "High LSB bitplane randomness detected. Possible hidden payload or noise artifact."
            elif stego_score > 40.0:
                verdict = "MODERATE ANOMALY"
                details = "Elevated LSB noise levels. Image contains complex textures or slight modifications."
            else:
                verdict = "CLEAN IMAGE"
                details = "No significant LSB anomalies or steganographic signatures detected."

        max_capacity_bytes = max(0, (total_channels // 8) - 8)
        capacity_used_pct = round((declared_payload_size / max_capacity_bytes * 100.0), 1) if signature_found and max_capacity_bytes > 0 else 0.0

        return {
            "verdict": verdict,
            "stego_score": stego_score,
            "signature_found": signature_found,
            "declared_payload_size": declared_payload_size,
            "lsb_entropy": round(lsb_entropy, 4),
            "chi_anomaly_score": round(chi_anomaly_score, 2),
            "capacity_used_pct": capacity_used_pct,
            "max_capacity_bytes": max_capacity_bytes,
            "details": details,
            "image_dimensions": f"{width}x{height}",
            "total_pixels": width * height
        }

if __name__ == "__main__":
    import sys
    print("Testing Steganysis Detector...")
    # Test on dummy image if available
