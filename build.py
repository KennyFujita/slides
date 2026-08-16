#!/usr/bin/env python3
"""スライドを公開用の HTML に書き出す。

    python3 build.py

すべて AES-256-CBC + HMAC-SHA256 で暗号化する。**タイトルは公開される HTML の
どこにも出さない。** 入口 `private/index.html` も中身が暗号文で、解錠したときに
初めてタイトルの一覧が現れる。読む人は入口だけ覚えておけばよく、個々のスライドの
ファイル名は無意味な文字列でかまわない。

タイトルと平文の場所は decks.json にだけ書く。このファイルは .gitignore 済み。
**リポジトリは公開なので、ここに戻して書かないこと**（履歴に永久に残る）。
コミットメッセージにタイトルを書くのも同じ理由で不可（GitHub の公開イベント
アーカイブに残る）。

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
import re
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent
DECKS = REPO / "decks.json"
NOTES_URL = "https://kennyfujita.github.io/notes/"

ITERATIONS = 200_000


def download_name(title: str) -> str:
    """保存したときのファイル名。暗号文の中にしか出ないので題名のままでよい。"""
    name = re.sub(r'[\\/:*?"<>|]', "", title)
    name = re.sub(r"\s+", " ", name).strip()
    return (name or "slides") + ".html"


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


# スライドに差し込む保存ボタン。復号できた人の手元にしか現れない。
# 保存するときはボタン自身とこのスクリプトを取り除いてから直列化するので、
# 落ちてくるファイルは元のスライドそのものになる（開き直しても何も出ない）。
SAVE_BUTTON = """
<div id="deck-save"><button type="button">&#11015; 保存</button></div>
<style id="deck-save-css">
  #deck-save {{
    position: fixed;
    right: 1rem;
    bottom: 1rem;
    z-index: 9999;
  }}
  #deck-save button {{
    font: inherit;
    font-size: 0.8rem;
    padding: 0.4em 0.9em;
    color: var(--muted, #5B6270);
    background: var(--paper-raised, #E7EAEA);
    border: 1px solid var(--line, #D8DCDC);
    border-radius: 999px;
    cursor: pointer;
    opacity: 0.55;
    transition: opacity 0.15s;
  }}
  #deck-save button:hover {{ opacity: 1; }}
  @media print {{ #deck-save {{ display: none; }} }}
</style>
<script id="deck-save-js">
(function () {{
  document.querySelector('#deck-save button').addEventListener('click', function () {{
    var root = document.documentElement.cloneNode(true);
    ['#deck-save', '#deck-save-css', '#deck-save-js'].forEach(function (sel) {{
      var el = root.querySelector(sel);
      if (el) el.parentNode.removeChild(el);
    }});
    var url = URL.createObjectURL(new Blob(
      ['<!doctype html>\\n' + root.outerHTML], {{ type: 'text/html' }}));
    var a = document.createElement('a');
    a.href = url;
    a.download = {filename};
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () {{ URL.revokeObjectURL(url); }}, 1000);
  }});
}})();
</script>
</body>"""


# 入口を解錠すると現れる一覧。ここにだけタイトルが載る（暗号文の中なので公開されない）。
# 保存ボタンは listing.js が受け持ち、押されたら暗号文を取ってきてその場で復号する。
LISTING = """<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
<title>限定公開のノート</title>
<link rel="stylesheet" href="../assets/gate.css">
</head>
<body>

<main class="listing">
  <h1>限定公開のノート</h1>
  <p class="subtitle">
    タイトルをクリックすると、パスワードを入れ直さずに開きます。
    「保存」で落としたファイルもパスワードなしで開きます。
  </p>

  <ul class="deck-list">
{rows}
  </ul>

  <p class="dl-status" id="dl-status" role="status" aria-live="polite"></p>
  <p class="back"><a href="{notes}">&#8592; Notes</a></p>
</main>

<script src="../assets/crypto.js"></script>
<script src="../assets/listing.js"></script>

</body>
</html>
"""

LISTING_ROW = """    <li>
      <span class="date">{date}</span>
      <a href="../{out}">{title}</a>
      <button type="button" class="dl" data-src="../{out}" data-name="{filename}">&#11015; 保存</button>
    </li>"""


# 暗号文を置く入口ページ。タイトルは持たせない。個々のスライドにも入口自身にも使う。
GATE = """<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
<title>限定公開</title>
<link rel="stylesheet" href="{prefix}assets/gate.css">
</head>
<body>

<main class="gate">
  <p class="lock" aria-hidden="true">&#128274;</p>
  <h1>限定公開</h1>
  <p class="subtitle">パスワードを知っている人だけが読めます。</p>

  <form id="unlock-form" autocomplete="off">
    <label for="password">パスワード</label>
    <input type="password" id="password" name="password" autocomplete="current-password" autofocus>
    <button type="submit" id="submit">開く</button>
  </form>

  <p class="status" id="status" role="status" aria-live="polite"></p>
  <p class="back"><a href="{back}">&#8592; {back_label}</a></p>
</main>

<script type="application/json" id="payload">{payload}</script>
<script src="{prefix}assets/crypto.js"></script>
<script src="{prefix}assets/gate.js"></script>

</body>
</html>
"""


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


def gate_page(plaintext: str, password: str, prefix: str, back: str, back_label: str) -> str:
    return GATE.format(
        prefix=prefix,
        back=back,
        back_label=back_label,
        payload=json.dumps(encrypt(plaintext.encode("utf-8"), password),
                           separators=(",", ":")),
    )


def main() -> int:
    if not DECKS.exists():
        print(f"{DECKS.name} がありません。CLAUDE.md を見てください。", file=sys.stderr)
        return 1
    decks = json.loads(DECKS.read_text(encoding="utf-8"))["decks"]

    password = os.environ.get("SLIDES_PASSWORD") or getpass.getpass("パスワード: ")
    if not password:
        print("パスワードが空です。", file=sys.stderr)
        return 1

    for deck in decks:
        src = Path(deck["src"])
        if not src.exists():
            print(f"見つかりません: {src}", file=sys.stderr)
            return 1

        document = wrap_document(src.read_text(encoding="utf-8"), deck["title"], deck["lang"])
        document = document.replace(
            "</body>",
            SAVE_BUTTON.format(filename=json.dumps(download_name(deck["title"]))),
            1)
        page = gate_page(document, password,
                         prefix="./", back="./private/", back_label="限定公開のノート")
        (REPO / deck["out"]).write_text(page, encoding="utf-8")
        print(f"{deck['out']}: 本文 {len(document):,} B → ページ {len(page):,} B")

    # 入口。タイトルの一覧そのものを暗号化する。
    rows = "\n".join(
        LISTING_ROW.format(date=html.escape(d["date"]),
                           out=html.escape(d["out"]),
                           title=html.escape(d["title"]),
                           filename=html.escape(download_name(d["title"]), quote=True))
        for d in decks)
    listing = LISTING.format(rows=rows, notes=NOTES_URL)
    page = gate_page(listing, password, prefix="../", back=NOTES_URL, back_label="Notes")
    out = REPO / "private/index.html"
    out.parent.mkdir(exist_ok=True)
    out.write_text(page, encoding="utf-8")
    print(f"private/index.html: 入口 / {len(decks)} 件 → ページ {len(page):,} B")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
