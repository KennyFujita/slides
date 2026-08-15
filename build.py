#!/usr/bin/env python3
"""平文のスライドを AES-256-CBC + HMAC-SHA256 で暗号化し、公開用の HTML を書き出す。

平文はこのリポジトリに入れない。SOURCES のパスはリポジトリ外を指している。
パスワードは環境変数 SLIDES_PASSWORD、無ければ対話入力で受け取る。

    python3 build.py

鍵導出は PBKDF2-HMAC-SHA256 (200,000 回) で 64 バイト。
前半 32 バイトを AES 鍵、後半 32 バイトを HMAC 鍵に使う（encrypt-then-MAC）。
本文は gzip してから暗号化する（588KB の HTML が base64 で 800KB になるのを避けるため）。
AES は openssl コマンドに任せている。この Mac には pycryptodome も
cryptography も入っておらず、LibreSSL の enc は GCM を持たないため CBC + HMAC にした。
"""

import base64
import getpass
import gzip
import hashlib
import hmac
import html
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent
RESEARCH = Path("/Users/fujita/workspace/research/robot")

ITERATIONS = 200_000

# 出力名: (平文の場所, <title>, 表紙に出す見出し, 補足)
SOURCES = [
    {
        "out": "tac2pose.html",
        "src": RESEARCH / "paper survey/tac2pose/slides.html",
        "title": "Tac2Pose — Tactile Object Pose Estimation from the First Touch",
        "heading": "Tac2Pose",
        "subtitle": "論文紹介 · Tactile Object Pose Estimation from the First Touch",
        "lang": "ja",
    },
    {
        "out": "sparse-ft-pose.html",
        "src": RESEARCH / "proposal/sparse-ft-pose/slides.html",
        "title": "疎な指先力覚からの物体姿勢推定 — 提案構想",
        "heading": "疎な指先力覚からの物体姿勢推定",
        "subtitle": "提案構想",
        "lang": "ja",
    },
]


def wrap_document(fragment: str, title: str, lang: str) -> str:
    """スライドの断片（<style> から始まる）を単体で開ける HTML にする。"""
    if fragment.lstrip().lower().startswith("<!doctype"):
        return fragment
    return (
        "<!doctype html>\n"
        f'<html lang="{lang}">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{html.escape(title)}</title>\n</head>\n<body>\n"
        f"{fragment}\n</body>\n</html>\n"
    )


def encrypt(plaintext: bytes, password: str) -> dict:
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    keys = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS, dklen=64)
    aes_key, mac_key = keys[:32], keys[32:]

    packed = gzip.compress(plaintext, 9)
    # 数百 KB を openssl の stdin/stdout に流すとパイプで詰まるので一時ファイルを使う。
    with tempfile.TemporaryDirectory() as tmp:
        raw, enc = Path(tmp) / "in", Path(tmp) / "out"
        raw.write_bytes(packed)
        subprocess.run(
            ["openssl", "enc", "-aes-256-cbc",
             "-K", aes_key.hex(), "-iv", iv.hex(),
             "-in", str(raw), "-out", str(enc)],
            check=True,
        )
        ciphertext = enc.read_bytes()

    mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    b64 = lambda b: base64.b64encode(b).decode()
    return {
        "v": 1,
        "iterations": ITERATIONS,
        "salt": b64(salt),
        "iv": b64(iv),
        "ct": b64(ciphertext),
        "mac": b64(mac),
    }


GATE = """<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{title}</title>
<link rel="stylesheet" href="./assets/gate.css">
</head>
<body>

<main class="gate">
  <p class="lock" aria-hidden="true">&#128274;</p>
  <h1>{heading}</h1>
  <p class="subtitle">{subtitle}</p>

  <form id="unlock-form" autocomplete="off">
    <label for="password">パスワード</label>
    <input type="password" id="password" name="password" autocomplete="current-password" autofocus>
    <button type="submit" id="submit">開く</button>
  </form>

  <p class="status" id="status" role="status" aria-live="polite"></p>
  <p class="back"><a href="https://kennyfujita.github.io/notes/">&#8592; Notes</a></p>
</main>

<script type="application/json" id="payload">{payload}</script>
<script src="./assets/gate.js"></script>

</body>
</html>
"""


def main() -> int:
    password = os.environ.get("SLIDES_PASSWORD") or getpass.getpass("パスワード: ")
    if not password:
        print("パスワードが空です。", file=sys.stderr)
        return 1

    for item in SOURCES:
        src = item["src"]
        if not src.exists():
            print(f"見つかりません: {src}", file=sys.stderr)
            return 1

        document = wrap_document(src.read_text(encoding="utf-8"), item["title"], item["lang"])
        payload = encrypt(document.encode("utf-8"), password)

        page = GATE.format(
            title=html.escape(item["title"]),
            heading=html.escape(item["heading"]),
            subtitle=html.escape(item["subtitle"]),
            payload=json.dumps(payload, separators=(",", ":")),
        )
        out = REPO / item["out"]
        out.write_text(page, encoding="utf-8")
        print(f"{item['out']}: 平文 {len(document):,} B → ページ {len(page):,} B")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
