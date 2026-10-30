import os

TEXT_HEADER_CHAR = "\uFEFF"  # Zero-width no-break space signature
BIT_0_CHAR = "\u200B"       # Zero-width space
BIT_1_CHAR = "\u200C"       # Zero-width non-joiner
DELIM_CHAR = "\u200D"       # Zero-width joiner

class TextSteganographyEngine:
    """
    Text Steganography Engine utilizing Zero-Width Unicode Characters (\u200B, \u200C, \u200D, \uFEFF).
    Embeds binary payload invisibly between words or at the end of cover text.
    """

    @staticmethod
    def get_text_capacity(cover_text: str) -> dict:
        words = cover_text.split()
        num_words = len(words)
        char_len = len(cover_text)

        # In zero-width steganography, text size is virtually unlimited, but for ideal density:
        # 8 zero-width characters per byte.
        max_bytes = max(1000, char_len * 10)

        return {
            "char_count": char_len,
            "word_count": num_words,
            "max_payload_bytes": max_bytes
        }

    @classmethod
    def embed_data(cls, cover_text: str, data_bytes: bytes) -> str:
        """
        Embed data_bytes into cover_text using zero-width characters.
        """
        if not cover_text:
            cover_text = "Official Security Document Notice. StegoShield Cyber Defense Division."

        # Convert data_bytes into binary string of '0' and '1's
        bits = ''.join(format(b, '08b') for b in data_bytes)

        # Map binary string to zero-width characters
        zw_encoded = TEXT_HEADER_CHAR
        for bit in bits:
            if bit == '0':
                zw_encoded += BIT_0_CHAR
            else:
                zw_encoded += BIT_1_CHAR
        zw_encoded += DELIM_CHAR

        # Insert after the first word or at the end of the cover text
        words = cover_text.split(' ', 1)
        if len(words) > 1:
            stego_text = words[0] + zw_encoded + ' ' + words[1]
        else:
            stego_text = cover_text + zw_encoded

        return stego_text

    @classmethod
    def extract_data(cls, stego_text: str) -> bytes:
        """
        Extract hidden zero-width payload from stego_text.
        """
        if TEXT_HEADER_CHAR not in stego_text:
            raise ValueError("No valid StegoShield zero-width signature found in this text.")

        start_idx = stego_text.find(TEXT_HEADER_CHAR) + len(TEXT_HEADER_CHAR)
        end_idx = stego_text.find(DELIM_CHAR, start_idx)

        if end_idx == -1:
            raise ValueError("Corrupted zero-width text payload structure.")

        zw_stream = stego_text[start_idx:end_idx]
        bits = []
        for char in zw_stream:
            if char == BIT_0_CHAR:
                bits.append('0')
            elif char == BIT_1_CHAR:
                bits.append('1')

        bit_string = ''.join(bits)
        if len(bit_string) % 8 != 0:
            # Trim incomplete byte
            bit_string = bit_string[:(len(bit_string) // 8) * 8]

        if not bit_string:
            raise ValueError("Extracted zero-width string is empty.")

        extracted_bytes = bytes(int(bit_string[i:i+8], 2) for i in range(0, len(bit_string), 8))
        return extracted_bytes
