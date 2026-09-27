import unicodedata

ZW = set("\u200b\u200c\u200d\u200e\u200f\u2060\u2066\u2067\u2068\u2069")
BIDI = set("\u202a\u202b\u202c\u202d\u202e")

def has_smuggling(text: str) -> bool:
    """Detects zero-width characters, Bidi overrides, and tag chars."""
    for ch in text:
        if ch in ZW or ch in BIDI:
            return True
        if 0xE0000 <= ord(ch) <= 0xE007F:
            return True
    return False

def normalize(text: str) -> str:
    """Normalizes unicode to collapse homoglyphs and strips zero-widths."""
    cleaned = "".join(ch for ch in text if ch not in ZW and ch not in BIDI)
    return unicodedata.normalize("NFKC", cleaned)