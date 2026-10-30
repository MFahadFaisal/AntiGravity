import random
from urllib.parse import quote

# Confusable lookalike unicode characters (Cyrillic / Greek)
CONFUSABLES = {
    'a': ['а', 'α'],
    'c': ['с'],
    'e': ['е', 'ε'],
    'i': ['і', 'ı'],
    'j': ['ј'],
    'o': ['о', 'ο'],
    'p': ['р'],
    's': ['ѕ'],
    'x': ['х'],
    'y': ['у']
}

CLOUD_PROVIDERS = [
    "pages.dev", "firebaseapp.com", "vercel.app", "netlify.app",
    "ngrok.io", "github.io", "glitch.me", "workers.dev", "render.com"
]

BRANDS = [
    "paypal", "chase", "apple", "microsoft", "google", "binance",
    "coinbase", "metamask", "wellsfargo", "bankofamerica", "netflix"
]

RISK_TLDS = [
    ".xyz", ".top", ".buzz", ".icu", ".cam", ".vip", ".work",
    ".cfd", ".sbs", ".monster", ".fit", ".kim", ".fun", ".live"
]

ACTION_KEYWORDS = [
    "login", "verify", "secure", "auth", "signin", "portal", "update",
    "billing", "kyc-validation", "confirm-identity", "unlock-account"
]

def mutate_homoglyph(text: str) -> str:
    """Substitutes 1-2 Latin letters with visual lookalike Cyrillic characters."""
    chars = list(text)
    mutated = False
    for i, c in enumerate(chars):
        if c.lower() in CONFUSABLES and random.random() < 0.4:
            chars[i] = random.choice(CONFUSABLES[c.lower()])
            mutated = True
            break
    if not mutated:
        # Force mutate first matchable character
        for i, c in enumerate(chars):
            if c.lower() in CONFUSABLES:
                chars[i] = random.choice(CONFUSABLES[c.lower()])
                break
    return "".join(chars)

def generate_adversarial_phishing_urls(count: int = 5000) -> list[str]:
    """Generates synthetic adversarial phishing URLs designed to stress test ML evasion."""
    adversarial_urls = []

    for _ in range(count):
        strategy = random.choice(["homoglyph", "cloud_nesting", "parameter_cloaking", "dga", "double_ext"])
        brand = random.choice(BRANDS)
        action = random.choice(ACTION_KEYWORDS)
        tld = random.choice(RISK_TLDS)

        if strategy == "homoglyph":
            spoofed_brand = mutate_homoglyph(brand)
            url = f"https://{spoofed_brand}-{action}{tld}/auth/index.php?token={random.randint(100000, 999999)}"

        elif strategy == "cloud_nesting":
            cloud = random.choice(CLOUD_PROVIDERS)
            sub = f"{action}-{brand}" if random.random() < 0.5 else f"{brand}-{action}-portal"
            url = f"https://{sub}.{cloud}/signin.html"

        elif strategy == "parameter_cloaking":
            legit_brand = f"https://www.{brand}.com/signin"
            url = f"http://secure-redirect-service{tld}/jump?return_to={quote(legit_brand)}&auth_seed={random.randint(1000, 9999)}"

        elif strategy == "dga":
            # Pseudo-random consonant-heavy domain
            consonants = "bcdfghjklmnpqrstvwxyz"
            dga_label = "".join(random.choices(consonants, k=random.randint(8, 14)))
            url = f"http://{dga_label}{tld}/{action}/{brand}"

        elif strategy == "double_ext":
            exts = [".pdf.exe", ".html.php", ".doc.vbs", ".zip.bat"]
            target_ext = random.choice(exts)
            url = f"http://invoice-{brand}-alert{tld}/download/statement_2026{target_ext}"

        adversarial_urls.append(url)

    return adversarial_urls
