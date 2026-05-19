from PIL import Image, ImageDraw, ImageFont
import numpy as np
import io
import os

def apply_visible_watermark(image_bytes: bytes, text: str = "OMNI VEIL") -> bytes:
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGBA")
        w, h = img.size
        badge_w, badge_h = 180, 36
        badge = Image.new("RGBA", (badge_w, badge_h), (0, 0, 0, 180))
        draw = ImageDraw.Draw(badge)
        try:
            font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 14)
        except Exception:
            font = ImageFont.load_default()
        draw.text((10, 10), f"✦ {text}", fill=(212, 175, 55, 255), font=font)
        pos = (w - badge_w - 16, h - badge_h - 16)
        img.paste(badge, pos, badge)
        out = io.BytesIO()
        img.convert("RGB").save(out, format="JPEG", quality=92)
        return out.getvalue()
    except Exception:
        return image_bytes

def apply_invisible_watermark(image_bytes: bytes, payload: str) -> bytes:
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        arr = np.array(img, dtype=np.float32)
        payload_bits = ''.join(format(ord(c), '08b') for c in payload[:32])
        channel = arr[:, :, 0]
        from scipy.fft import dct, idct
        dct_channel = dct(dct(channel, axis=0), axis=1)
        rows, cols = dct_channel.shape
        strength = 8.0
        for i, bit in enumerate(payload_bits):
            r = 10 + (i * 7) % (rows - 10)
            c = 10 + (i * 11) % (cols - 10)
            if bit == '1':
                dct_channel[r, c] += strength
            else:
                dct_channel[r, c] -= strength
        from scipy.fft import idct
        restored = idct(idct(dct_channel, axis=1), axis=0)
        arr[:, :, 0] = np.clip(restored, 0, 255)
        result = Image.fromarray(arr.astype(np.uint8))
        out = io.BytesIO()
        result.save(out, format="JPEG", quality=92)
        return out.getvalue()
    except Exception:
        return image_bytes

def extract_invisible_watermark(image_bytes: bytes, payload_len: int = 32) -> str | None:
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        arr = np.array(img, dtype=np.float32)
        channel = arr[:, :, 0]
        from scipy.fft import dct
        dct_channel = dct(dct(channel, axis=0), axis=1)
        rows, cols = dct_channel.shape
        bits = []
        for i in range(payload_len * 8):
            r = 10 + (i * 7) % (rows - 10)
            c = 10 + (i * 11) % (cols - 10)
            bits.append('1' if dct_channel[r, c] > 0 else '0')
        chars = []
        for i in range(0, len(bits), 8):
            byte = ''.join(bits[i:i+8])
            chars.append(chr(int(byte, 2)))
        return ''.join(chars)
    except Exception:
        return None
