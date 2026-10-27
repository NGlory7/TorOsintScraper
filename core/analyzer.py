import re
from bs4 import BeautifulSoup

PATTERNS = {
    "btc_wallets": re.compile(
        r'\b(bc1[ac-hj-np-z02-9]{39,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b'
    ),
    "eth_wallets": re.compile(
        r'\b0x[a-fA-F0-9]{40}\b'
    ),
    "xmr_wallets": re.compile(
        r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'
    ),
    "emails": re.compile(
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    ),
    "onion_links": re.compile(
        r'[a-z2-7]{16,56}\.onion'
    ),
    "telegram": re.compile(
        r'(?:https?://)?(?:t\.me|telegram\.me)/([a-zA-Z0-9_]{5,32})\b'
    ),
    "xmpp_jabber": re.compile(
        r'\b[a-zA-Z0-9._%+-]+@(?:jabber\.[a-z]+|xmpp\.[a-z]+|exploit\.im|calyx\.net|thesecure\.biz)\b',
        re.IGNORECASE
    )
}

def analyze_content(html: str) -> dict:
    """
    HTML içeriğinden OSINT verilerini (e-postalar, onion linkleri, kripto cüzdanlar, PGP) çıkarır.
    Orijinal kodla %100 uyumlu olarak hem kök dizinde hem 'osint' anahtarı altında döndürür.
    """
    soup = BeautifulSoup(html, "html.parser")
    page_title = soup.title.string.strip() if soup.title and soup.title.string else ""
    text = soup.get_text()

    raw_emails = set(PATTERNS["emails"].findall(text))
    cleaned_emails = sorted([
        e for e in raw_emails
        if not e.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.css', '.js'))
    ])

    btc_wallets = sorted(list(set(PATTERNS["btc_wallets"].findall(text))))
    eth_wallets = sorted(list(set(PATTERNS["eth_wallets"].findall(text))))
    xmr_wallets = sorted(list(set(PATTERNS["xmr_wallets"].findall(text))))
    onion_links = sorted(list(set(PATTERNS["onion_links"].findall(html))))
    telegram_handles = sorted(list(set(PATTERNS["telegram"].findall(text))))
    xmpp_contacts = sorted(list(set(PATTERNS["xmpp_jabber"].findall(text))))

    has_pgp = "-----BEGIN PGP PUBLIC KEY BLOCK-----" in text or "-----BEGIN PGP SIGNED MESSAGE-----" in text

    osint_data = {
        "emails": cleaned_emails,
        "onion_links": onion_links,
        "crypto_wallets": {
            "btc": btc_wallets,
            "eth": eth_wallets,
            "xmr": xmr_wallets
        },
        "telegram": telegram_handles,
        "xmpp": xmpp_contacts,
        "has_pgp": has_pgp
    }

    return {
        "title": page_title,
        "osint": osint_data,
        "emails": cleaned_emails,
        "onion_links": onion_links,
        "crypto_wallets": osint_data["crypto_wallets"],
        "telegram": telegram_handles,
        "xmpp": xmpp_contacts,
        "has_pgp": has_pgp
    }
