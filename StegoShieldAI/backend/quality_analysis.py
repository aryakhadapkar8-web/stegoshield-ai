import os
import math
import numpy as np
from PIL import Image, ImageChops, ImageEnhance

class QualityAnalyzer:
    """
    Quality Analysis Engine for Image Steganography Signal Fidelity Measurement.
    Computes PSNR (Peak Signal-to-Noise Ratio), MSE (Mean Squared Error),
    and SSIM (Structural Similarity Index), along with pixel delta heatmaps.
    """

    @staticmethod
    def calculate_mse(cover_img_path: str, stego_img_path: str) -> float:
        """
        Calculate Mean Squared Error (MSE) between original cover image and stego image.
        MSE = (1 / (M * N * C)) * sum((Cover - Stego)^2)
        """
        with Image.open(cover_img_path) as c_img, Image.open(stego_img_path) as s_img:
            c_rgb = c_img.convert("RGB")
            s_rgb = s_img.convert("RGB")

            # Ensure same dimensions
            if c_rgb.size != s_rgb.size:
                s_rgb = s_rgb.resize(c_rgb.size)

            c_np = np.array(c_rgb, dtype=np.float64)
            s_np = np.array(s_rgb, dtype=np.float64)

            err = np.sum((c_np - s_np) ** 2)
            mse = err / float(c_np.shape[0] * c_np.shape[1] * c_np.shape[2])
            return round(float(mse), 6)

    @staticmethod
    def calculate_psnr(cover_img_path: str, stego_img_path: str) -> float:
        """
        Calculate Peak Signal-to-Noise Ratio (PSNR) in dB.
        PSNR = 10 * log10(MAX^2 / MSE)
        """
        mse = QualityAnalyzer.calculate_mse(cover_img_path, stego_img_path)
        if mse == 0:
            return 99.99  # Infinite PSNR (identical images)

        max_pixel = 255.0
        psnr = 10.0 * math.log10((max_pixel ** 2) / mse)
        return round(float(psnr), 2)

    @staticmethod
    def calculate_ssim(cover_img_path: str, stego_img_path: str) -> float:
        """
        Calculate Structural Similarity Index (SSIM) between cover and stego image.
        Simplified SSIM over global luminance, contrast, and structure components.
        """
        with Image.open(cover_img_path) as c_img, Image.open(stego_img_path) as s_img:
            c_rgb = c_img.convert("RGB")
            s_rgb = s_img.convert("RGB")

            if c_rgb.size != s_rgb.size:
                s_rgb = s_rgb.resize(c_rgb.size)

            x = np.array(c_rgb, dtype=np.float64)
            y = np.array(s_rgb, dtype=np.float64)

            K1 = 0.01
            K2 = 0.03
            L = 255.0

            C1 = (K1 * L) ** 2
            C2 = (K2 * L) ** 2

            mu_x = np.mean(x)
            mu_y = np.mean(y)

            sigma_x_sq = np.var(x)
            sigma_y_sq = np.var(y)
            sigma_xy = np.mean((x - mu_x) * (y - mu_y))

            num = (2 * mu_x * mu_y + C1) * (2 * sigma_xy + C2)
            den = (mu_x**2 + mu_y**2 + C1) * (sigma_x_sq + sigma_y_sq + C2)

            ssim = num / den
            # Clip result to [0, 1]
            ssim_val = max(0.0, min(1.0, float(ssim)))
            return round(ssim_val, 4)

    @staticmethod
    def generate_diff_heatmap(cover_img_path: str, stego_img_path: str, output_diff_path: str) -> str:
        """
        Generates a pixel difference heatmap image highlighting LSB modifications.
        Amplifies modifications 20x for visual anomaly inspection.
        """
        with Image.open(cover_img_path) as c_img, Image.open(stego_img_path) as s_img:
            c_rgb = c_img.convert("RGB")
            s_rgb = s_img.convert("RGB")

            if c_rgb.size != s_rgb.size:
                s_rgb = s_rgb.resize(c_rgb.size)

            diff = ImageChops.difference(c_rgb, s_rgb)
            enhancer = ImageEnhance.Brightness(diff)
            diff_bright = enhancer.enhance(20.0)

            os.makedirs(os.path.dirname(os.path.abspath(output_diff_path)), exist_ok=True)
            diff_bright.save(output_diff_path, format="PNG")
            return output_diff_path

    @classmethod
    def full_analysis(cls, cover_img_path: str, stego_img_path: str, output_diff_path: str = None) -> dict:
        """
        Returns full quality report with PSNR, MSE, SSIM, file sizes, and fidelity rating.
        """
        mse = cls.calculate_mse(cover_img_path, stego_img_path)
        psnr = cls.calculate_psnr(cover_img_path, stego_img_path)
        ssim = cls.calculate_ssim(cover_img_path, stego_img_path)

        cover_size = os.path.getsize(cover_img_path) if os.path.exists(cover_img_path) else 0
        stego_size = os.path.getsize(stego_img_path) if os.path.exists(stego_img_path) else 0
        size_diff = stego_size - cover_size

        if psnr >= 50:
            rating = "EXCELLENT (Visually Imperceptible)"
            color = "#10b981"
        elif psnr >= 40:
            rating = "VERY GOOD (Minimal Noise)"
            color = "#3b82f6"
        elif psnr >= 30:
            rating = "MODERATE (Slight Noise)"
            color = "#f59e0b"
        else:
            rating = "POOR (High Degradation)"
            color = "#ef4444"

        diff_relative_path = None
        if output_diff_path:
            cls.generate_diff_heatmap(cover_img_path, stego_img_path, output_diff_path)
            diff_relative_path = os.path.basename(output_diff_path)

        return {
            "mse": mse,
            "psnr": psnr,
            "ssim": ssim,
            "cover_size_bytes": cover_size,
            "stego_size_bytes": stego_size,
            "size_diff_bytes": size_diff,
            "rating": rating,
            "rating_color": color,
            "diff_heatmap_file": diff_relative_path
        }
