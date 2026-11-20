#!/usr/bin/env python3
"""secret_guard.py — محافظ اسرار برای ریپوهای GitHub.

دو کار اصلی میکند:

  scan                      اسکن تمام فایلها و پیدا کردن پسوورد/توکن/کلید
  encrypt / decrypt         رمزگذاری فایلی که حاوی پسوورد است (با پسوورد کاربر)
  install-hook              نصب pre-commit hook جلوگیری از کامیت اسرار

استفاده:
    python3 secret_guard.py scan
    python3 secret_guard.py install-hook
    python3 secret_guard.py encrypt config.py          # پسوورد را میپرسد
    python3 secret_guard.py decrypt config.py.enc      # پسوورد را میپرسد

نیاز به cryptography فقط برای encrypt/decrypt است (برای scan و hook نیازی نیست).
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import os
import re
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MAGIC = b"SECGUARD1\x00"

# الگوهای اسرار
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("پسوورد هاردکد شده", re.compile(r"""(?i)\b(?:pass(?:word|wd)?|pwd)\s*[:=]\s*["'][^"'\n]{4,}["']""")),
    ("کلید/توکن API", re.compile(r"""(?i)\b(?:api[_-]?key|access[_-]?token|secret[_-]?key|auth[_-]?token|client[_-]?secret)\s*[:=]\s*["'][A-Za-z0-9_\-]{12,}["']""")),
    ("توکن گیت هاب", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("توکن گیت هاب (fine-grained)", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("کلید OpenAI", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("کلید Google API", re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b")),
    ("کلید خصوصی SSH/RSA", re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----")),
    ("آدرس دیتابیس همراه پسوورد", re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:/@]+:[^\s@/]+@")),
    ("کلید AWS", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
]

# چیزهایی که شبیه اسرارند ولی نیستند (کد خود برنامه)
ALLOWLIST = (
    "csrf_token", "password_hash", "generate_password_hash", "check_password_hash",
    "secrets.", "os.environ", "token_hex", "token_urlsafe", "getpass",
    "placeholder", 'type="password"', "name=\"password\"", "Flask-SocketIO",
    "SECRET_KEY = os.environ", "SECRET_KEY=\"", "SECRET_KEY='",
    "GH_TOKEN", "GITHUB_TOKEN", "MCP_", "input(", "promptString",
)

SKIP_DIRS = {".git", ".venv", "__pycache__", "node_modules", "instance", "dist", "build"}
SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf",
    ".zip", ".db", ".sqlite", ".sqlite3", ".pyc", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mp3", ".enc",
}
MAX_BYTES = 2_000_000


def scan() -> int:
    findings: list[tuple[str, int, str, str]] = []

    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        # .env files are secrets by design and must stay gitignored —
        # they are never committed, so skip them in the pre-commit scan.
        if path.name == ".env" or path.name.startswith(".env."):
            continue
        if path.suffix.lower() in SKIP_EXT:
            continue
        try:
            if path.stat().st_size > MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue

        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//", "/*", "*")):
                continue
            if any(item in line for item in ALLOWLIST):
                continue
            for name, rx in PATTERNS:
                if rx.search(line):
                    findings.append(
                        (str(path.relative_to(ROOT)), lineno, name, stripped[:160])
                    )
                    break

    if not findings:
        print("✅ اسکن تمیز است — هیچ پسوورد/توکنی پیدا نشد.")
        return 0

    print(f"🚨 {len(findings)} مورد مشکوک پیدا شد:\n")
    for file, lineno, name, line in findings:
        print(f"  • {file}:{lineno}  [{name}]")
        print(f"      {line}\n")
    return 1


def _derive(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 480_000, dklen=32)


def encrypt_file(src: Path, password: str | None) -> int:
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        print("❌ برای رمزگذاری باید cryptography نصب باشد: pip install cryptography", file=sys.stderr)
        return 2

    if not src.is_file():
        print(f"❌ فایل پیدا نشد: {src}", file=sys.stderr)
        return 2

    if password is None:
        password = getpass.getpass("پسوورد رمزگذاری: ")
        confirm = getpass.getpass("تکرار پسوورد: ")
        if password != confirm:
            print("❌ پسووردها یکسان نیستند.", file=sys.stderr)
            return 2

    salt = secrets.token_bytes(16)
    key = base64.urlsafe_b64encode(_derive(password, salt))
    token = Fernet(key).encrypt(src.read_bytes())

    out = src.with_suffix(src.suffix + ".enc")
    out.write_bytes(MAGIC + salt + token)
    os.chmod(out, 0o600)
    print(f"✅ رمزگذاری شد: {out.name}  (مجوز 600 — فقط خودت میخوانی)")
    print("   فایل اصلی را از ریپو حذف کن و .enc کامیت نکن.")
    return 0


def decrypt_file(src: Path, password: str | None) -> int:
    try:
        from cryptography.fernet import Fernet, InvalidToken
    except ImportError:
        print("❌ برای رمزگشایی cryptography لازم است: pip install cryptography", file=sys.stderr)
        return 2

    raw = src.read_bytes()
    if not raw.startswith(MAGIC):
        print("❌ فرمت فایل معتبر نیست.", file=sys.stderr)
        return 2

    if password is None:
        password = getpass.getpass("پسوورد رمزگشایی: ")

    salt = raw[len(MAGIC):len(MAGIC) + 16]
    token = raw[len(MAGIC) + 16:]
    key = base64.urlsafe_b64encode(_derive(password, salt))

    try:
        data = Fernet(key).decrypt(token)
    except InvalidToken:
        print("❌ پسوورد اشتباه است یا فایل تغییر کرده.", file=sys.stderr)
        return 2

    out = src.with_suffix("")
    if src.name.endswith(".enc") and out == src:
        out = src.with_name(src.stem)
    out.write_bytes(data)
    os.chmod(out, 0o600)
    print(f"✅ رمزگشایی شد: {out.name}")
    return 0


HOOK = """#!/bin/sh
# توسط secret_guard.py نصب شد — از کامیت شدن اسرار جلوگیری میکند
exec python3 "$(git rev-parse --show-toplevel)/secret_guard.py" scan
"""


def install_hook() -> int:
    git_dir = ROOT / ".git"
    if not git_dir.exists():
        print("❌ این پوشه یک ریپو git نیست.", file=sys.stderr)
        return 2
    hook = git_dir / "hooks" / "pre-commit"
    hook.parent.mkdir(parents=True, exist_ok=True)
    # hook قبلی را overwrite نکنیم
    if hook.exists() and "secret_guard" not in hook.read_text(errors="ignore"):
        backup = hook.with_suffix(".backup")
        hook.rename(backup)
        print(f"ℹ️  hook قبلی به {backup.name} منتقل شد.")
    hook.write_text(HOOK)
    os.chmod(hook, 0o755)
    print("✅ pre-commit hook نصب شد. هر کامیت قبل از ثبت، اسکن میشود.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="محافظ اسرار ریپو")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("scan", help="اسکن پسوورد و توکن")
    sub.add_parser("install-hook", help="نصب pre-commit hook")

    p_enc = sub.add_parser("encrypt", help="رمزگذاری فایل با پسوورد")
    p_enc.add_argument("file", type=Path)
    p_enc.add_argument("--password", help="پسوورد (در non-interactive؛ بهتر است ندهی تا پرسیده شود)")

    p_dec = sub.add_parser("decrypt", help="رمزگشایی فایل")
    p_dec.add_argument("file", type=Path)
    p_dec.add_argument("--password")

    args = ap.parse_args()

    if args.cmd == "scan":
        return scan()
    if args.cmd == "install-hook":
        return install_hook()
    if args.cmd == "encrypt":
        return encrypt_file(args.file, args.password)
    if args.cmd == "decrypt":
        return decrypt_file(args.file, args.password)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
