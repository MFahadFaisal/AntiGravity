import io
import math
import requests
from PIL import Image

# LRU Cache for visual hashes
VISUAL_CACHE = {}

# Authorized domains for major brands
AUTHORIZED_BRAND_DOMAINS = {
    "paypal": ["paypal.com", "paypal-communication.com"],
    "google": ["google.com", "gstatic.com", "googleapis.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
    "binance": ["binance.com"],
    "meta": ["meta.com", "facebook.com", "instagram.com", "whatsapp.com"],
    "steam": ["steampowered.com", "steamcommunity.com"]
}

# Known perceptual dHash signatures for target brand favicons
BRAND_SIGNATURES = {
    "paypal": ["0038787878383800", "003c7e7e7e3c3c00", "0018387878381800"],
    "google": ["3c7e66667e7e603c", "3c7e66607e7e663c", "3c7e42407c427e3c"],
    "microsoft": ["f0f0f0f00f0f0f0f", "ff00ff0000ff00ff", "f0f000000f0f0000"],
    "apple": ["00183c7e7e3c1800", "003c7e7e7e7e3c00", "00183c7e3c180000"],
    "netflix": ["e7c3c3c3c3c3c3e7", "e7818181818181e7", "ff818181818181ff"],
    "binance": ["183c7ebdff7e3c18", "00183c7ebd7e3c18", "183c7ebd7e3c1800"],
    "meta": ["3c7e666666667e3c", "7e7e666666667e7e", "3c6666666666663c"],
    "steam": ["3c7effffffffff3c", "3c7ee7c3c3e77e3c", "003c7effff7e3c00"]
}

def compute_dhash(image: Image.Image, hash_size: int = 8) -> str:
    """Computes difference hash (dHash) from PIL image."""
    try:
        # Resize to (hash_size + 1, hash_size) and convert to grayscale
        resized = image.convert("L").resize((hash_size + 1, hash_size), Image.Resampling.LANCZOS)
        raw_bytes = list(resized.tobytes())
        diff = []
        for row in range(hash_size):
            for col in range(hash_size):
                p_left = raw_bytes[row * (hash_size + 1) + col]
                p_right = raw_bytes[row * (hash_size + 1) + col + 1]
                diff.append(p_left > p_right)

        val = 0
        for bit in diff:
            val = (val << 1) | int(bit)
        return f"{val:016x}"
    except Exception:
        return ""

def hamming_distance(hex1: str, hex2: str) -> int:
    """Calculates the number of differing bits between two 64-bit hex hashes."""
    try:
        val1 = int(hex1, 16)
        val2 = int(hex2, 16)
        return bin(val1 ^ val2).count("1")
    except Exception:
        return 64

def check_visual_spoofing(favicon_url: str, current_domain: str, timeout: float = 1.5) -> dict:
    """
    Downloads the page favicon/logo, computes perceptual hash, and checks
    if it matches a protected brand while hosted on an unauthorized domain.
    """
    clean_domain = (current_domain or "").replace("www.", "").lower()
    if not favicon_url or not clean_domain:
        return {"is_visual_spoof": False}

    cache_key = f"{clean_domain}:{favicon_url}"
    if cache_key in VISUAL_CACHE:
        return VISUAL_CACHE[cache_key]

    # Don't inspect if current domain is already legitimate
    for brand, auth_domains in AUTHORIZED_BRAND_DOMAINS.items():
        if any(clean_domain == auth or clean_domain.endswith("." + auth) for auth in auth_domains):
            res = {"is_visual_spoof": False, "is_authorized": True, "brand": brand}
            VISUAL_CACHE[cache_key] = res
            return res

    try:
        headers = {"User-Agent": "AntiGravity-Vision-Agent/2.0"}
        resp = requests.get(favicon_url, headers=headers, timeout=timeout)
        if resp.status_code == 200 and len(resp.content) > 32:
            img = Image.open(io.BytesIO(resp.content))
            f_hash = compute_dhash(img)

            if f_hash:
                for brand, known_hashes in BRAND_SIGNATURES.items():
                    for ref_hash in known_hashes:
                        dist = hamming_distance(f_hash, ref_hash)
                        # Threshold 10 out of 64 bits matches visually similar images
                        if dist <= 10:
                            result = {
                                "is_visual_spoof": True,
                                "brand": brand.capitalize(),
                                "hamming_dist": dist,
                                "hash": f_hash,
                                "details": f"Görsel Klon Tespiti: '{brand.capitalize()}' resmi logosu yetkisiz alanda taklit ediliyor (Hamming: {dist}/64)!"
                            }
                            VISUAL_CACHE[cache_key] = result
                            return result
    except Exception:
        pass

    res = {"is_visual_spoof": False}
    VISUAL_CACHE[cache_key] = res
    return res
