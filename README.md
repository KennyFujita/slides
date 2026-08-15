# slides

発表スライドの公開場所。<https://kennyfujita.github.io/slides/>

各スライドはパスワードを知っている人だけが読める。ページに埋め込まれているのは
暗号文だけで、平文はこのリポジトリにも配信物にも含まれていない。

## 仕組み

| 段階 | 使うもの |
|---|---|
| 鍵導出 | PBKDF2-HMAC-SHA256、200,000 回、salt 16 バイト、512 bit |
| 暗号化 | AES-256-CBC（前半 256 bit を鍵に使う） |
| 改ざん・パスワード判定 | HMAC-SHA256（後半 256 bit）で encrypt-then-MAC |
| 本文 | 暗号化の前に gzip する |

ブラウザ側は [`assets/gate.js`](assets/gate.js) が Web Crypto API で同じ手順を逆に辿る。
`crypto.subtle` は https と localhost でしか使えないので、`file://` で直接開いても動かない。

## 承知しておくこと

**これは「公開してよいが検索には出したくない」ものを置く場所であって、
秘密を守る仕組みではない。** 暗号文は誰でもダウンロードでき、手元で好きなだけ
パスワードを試せる（オフライン総当たり）。PBKDF2 20 万回はその速度を落とすだけで、
短いパスワードや推測しやすいパスワードは時間の問題で破られる。

- 他のサービスと同じパスワードを使わない
- 本当に外に出せないものはここに置かない

## 更新のしかた

平文はこのリポジトリの外（`~/workspace/research/...`）にある。
場所は [`build.py`](build.py) の `SOURCES` に書いてある。

```sh
SLIDES_PASSWORD='...' python3 build.py   # 暗号化して *.html を書き出す
git add -A && git commit -m "..." && git push
```

パスワードを変えるときは全ページを作り直すことになる（`build.py` を流し直すだけ）。

### 動作確認

```sh
python3 -m http.server 8799     # http://localhost:8799/
```

`file://` では動かないので必ずサーバー経由で開く。
