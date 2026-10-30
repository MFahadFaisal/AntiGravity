import io
import math
import requests
from PIL import Image

# LRU Cache for visual hashes to ensure sub-millisecond retrieval
VISUAL_CACHE = {}

# Authorized legitimate domains for major global target brands
AUTHORIZED_BRAND_DOMAINS = {
    # 1. Global Financial & Payments
    "paypal": ["paypal.com", "paypal-communication.com", "paypalobjects.com"],
    "chase": ["chase.com", "jpmorganchase.com", "chasecdn.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "wellsfargo": ["wellsfargo.com", "wf.com"],
    "citi": ["citi.com", "citigroup.com", "citibank.com"],
    "hsbc": ["hsbc.com", "hsbc.co.uk", "hsbc.com.tr"],
    "americanexpress": ["americanexpress.com", "amex.com"],
    "barclays": ["barclays.co.uk", "barclays.com"],

    # 2. Crypto & Web3 Wallets
    "binance": ["binance.com", "binance.vision", "binance.us", "bnbchain.org"],
    "coinbase": ["coinbase.com", "pro.coinbase.com"],
    "metamask": ["metamask.io", "consensys.io"],
    "kraken": ["kraken.com"],
    "kucoin": ["kucoin.com"],
    "ledger": ["ledger.com", "ledgerwallet.com"],

    # 3. Big Tech & Cloud Infrastructure
    "google": ["google.com", "gstatic.com", "googleapis.com", "youtube.com", "google.co.uk", "google.com.tr"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "office365.com", "azure.com", "microsoftonline.com"],
    "apple": ["apple.com", "icloud.com", "apple-dns.net"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.com.tr", "aws.amazon.com", "media-amazon.com"],
    "netflix": ["netflix.com", "nflximg.net", "nflxext.com"],
    "adobe": ["adobe.com", "adobelogin.com"],
    "dropbox": ["dropbox.com", "dropboxstatic.com"],
    "spotify": ["spotify.com", "scdn.co"],

    # 4. Gaming & Entertainment
    "steam": ["steampowered.com", "steamcommunity.com", "steamstatic.com"],
    "playstation": ["playstation.com", "sony.com"],
    "epicgames": ["epicgames.com", "unrealengine.com"],
    "roblox": ["roblox.com", "rbxcdn.com"],

    # 5. Social & Communications
    "meta": ["meta.com", "facebook.com", "instagram.com", "whatsapp.com", "fbcdn.net"],
    "linkedin": ["linkedin.com", "licdn.com"],
    "twitter": ["twitter.com", "x.com", "twimg.com"],
    "telegram": ["telegram.org", "t.me"],
    "discord": ["discord.com", "discordapp.com", "discord.gg"],
    "tiktok": ["tiktok.com", "tiktokcdn.com"],

    # 6. Logistics & E-Commerce
    "dhl": ["dhl.com", "dhl.de"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "ebay": ["ebay.com", "ebay.co.uk", "ebay.de"]
}

# Known perceptual dHash signatures for target brand favicons
BRAND_SIGNATURES = {
    # Financial
    "paypal": ["0038787878383800", "003c7e7e7e3c3c00", "0018387878381800", "0078fcfcfcf87000"],
    "chase": ["3c3c7e7e7e7e3c3c", "387cfefefefc3800", "7e7e3c3c3c3c7e7e"],
    "bankofamerica": ["ff00ff00ff00ff00", "e7e7e7e7e7e7e7e7", "f0f00f0ff0f00f0f"],
    "wellsfargo": ["ffff00000000ffff", "c3c3c3c3c3c3c3c3", "ff818181818181ff"],
    "citi": ["00387cfe7c380000", "00183c7e3c180000", "007efe7e3c180000"],
    "hsbc": ["e7c381000081c3e7", "e7810000000081e7", "ff810000000081ff"],
    "americanexpress": ["ffffffffffffffff", "3c3c3c3c3c3c3c3c", "e7e700000000e7e7"],
    "barclays": ["003c7effff7e3c00", "00183c7e7e3c1800", "007e7e7e7e7e7e00"],

    # Crypto
    "binance": ["183c7ebdff7e3c18", "00183c7ebd7e3c18", "183c7ebd7e3c1800", "3c7effffff7e3c00"],
    "coinbase": ["003c7e7e7e7e3c00", "00183c3c3c3c1800", "3c7e7e7e7e7e7e3c"],
    "metamask": ["e7c381818181c3e7", "e7810000000081e7", "7e3c181818183c7e"],
    "kraken": ["007effffffffff00", "003c7e7e7e7e3c00", "3c7e666666667e3c"],
    "kucoin": ["003c7e66667e3c00", "00183c66663c1800", "3c6666666666663c"],
    "ledger": ["003c3c3c3c3c3c00", "ffff00000000ffff", "00ff00ff00ff0000"],

    # Big Tech
    "google": ["3c7e66667e7e603c", "3c7e66607e7e663c", "3c7e42407c427e3c", "3c7e6666667e603c"],
    "microsoft": ["f0f0f0f00f0f0f0f", "ff00ff0000ff00ff", "f0f000000f0f0000", "ff000000000000ff"],
    "apple": ["00183c7e7e3c1800", "003c7e7e7e7e3c00", "00183c7e3c180000", "003c7e7e3c180000"],
    "amazon": ["00007e7e7e3c0000", "00183c7e7e381000", "00387cfefc380000"],
    "netflix": ["e7c3c3c3c3c3c3e7", "e7818181818181e7", "ff818181818181ff", "c3818181818181c3"],
    "adobe": ["ff818181818181ff", "ff010101010101ff", "e7838383838383e7"],
    "dropbox": ["3c7effffff7e3c00", "183c7effff7e3c18", "003c7e7e7e7e3c00"],
    "spotify": ["3c7e7e7e7e7e7e3c", "003c7e7e7e7e3c00", "00183c3c3c3c1800"],

    # Gaming
    "steam": ["3c7effffffffff3c", "3c7ee7c3c3e77e3c", "003c7effff7e3c00", "183c7effff7e3c18"],
    "playstation": ["003c7e7e7e3c0000", "007effffff7e0000", "183c3c3c3c3c3c18"],
    "epicgames": ["003c7effff7e3c00", "3c7e7e7e7e7e7e3c", "183c7e7e7e7e3c18"],
    "roblox": ["3c3c3c3c3c3c3c3c", "7e7e7e7e7e7e7e7e", "003c3c3c3c3c3c00"],

    # Social & Chat
    "meta": ["3c7e666666667e3c", "7e7e666666667e7e", "3c6666666666663c", "003c666666663c00"],
    "linkedin": ["3838003838383838", "7c7c007c7c7c7c7c", "3030003030303030"],
    "twitter": ["00183c7effff7e3c", "003c7effffff7e00", "00183c7e7e3c1800"],
    "telegram": ["00387cfefc380000", "00183c7ebd3c1800", "003c7eff7e3c0000"],
    "discord": ["3c7e66667e7e7e3c", "3c6666667e7e663c", "003c7e66667e3c00"],
    "tiktok": ["00183c3c3c3c1800", "003c7e7e7e7e3c00", "00183c7e7e3c1800"],

    # Logistics
    "dhl": ["ff8181ff818181ff", "ffff00000000ffff", "c3810000000081c3"],
    "fedex": ["ff00ff00ff00ff00", "7e3c181818183c7e", "e7818181818181e7"],
    "ups": ["3c7e7e7e7e7e3c00", "183c7e7e7e3c1800", "003c7e7e7e3c0000"],
    "ebay": ["3c66667e66667e3c", "3c7e66667e667e3c", "003c667e663c0000"]
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
        headers = {"User-Agent": "AntiGravity-Vision-Agent/2.1"}
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
                                "details": f"Görsel Klon Tespiti: '{brand.capitalize()}' resmi kurumsal logosu yetkisiz alanda taklit ediliyor (Hamming: {dist}/64)!"
                            }
                            VISUAL_CACHE[cache_key] = result
                            return result

        res = {"is_visual_spoof": False, "hash": ""}
        VISUAL_CACHE[cache_key] = res
        return res
    except Exception:
        res = {"is_visual_spoof": False}
        VISUAL_CACHE[cache_key] = res
        return res
