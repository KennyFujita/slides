/* パスワードでページ本体を復号して表示する。入口 (private/) と各スライドで共用。
 *
 * ページに埋まっているのは暗号文だけで、平文はどこにも置かれていない。
 * タイトルも暗号文の中にしかないので、解錠するまで何のページかは分からない。
 *
 * 鍵は PBKDF2-HMAC-SHA256 (build.py と同じ回数) で 512 bit 導出し、
 * 前半を AES-CBC、後半を HMAC に使う。HMAC を先に検証してから復号する
 * （検証に通らない = パスワードが違う、と判定できる）。
 *
 * 一度解錠したら sessionStorage に控えて、入口 → スライドと辿るときに
 * 訊き直さない。タブを閉じれば消える。
 */
(function () {
  'use strict';

  var SESSION_KEY = 'slides-pass';

  var form = document.getElementById('unlock-form');
  var input = document.getElementById('password');
  var button = document.getElementById('submit');
  var status = document.getElementById('status');
  var data = JSON.parse(document.getElementById('payload').textContent);

  function say(message, isError) {
    status.textContent = message;
    status.className = isError ? 'status error' : 'status';
  }

  function bytes(b64) {
    var raw = atob(b64);
    var out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }

  // プライベートブラウジングでは sessionStorage が触れないことがある。
  function remember(value) {
    try { window.sessionStorage.setItem(SESSION_KEY, value); } catch (e) {}
  }
  function recall() {
    try { return window.sessionStorage.getItem(SESSION_KEY); } catch (e) { return null; }
  }
  function forget() {
    try { window.sessionStorage.removeItem(SESSION_KEY); } catch (e) {}
  }

  // crypto.subtle は安全なコンテキストでしか生えない（https / localhost / file:）。
  // 平文の http:// で置いた場合だけここに落ちる。
  if (!window.crypto || !window.crypto.subtle) {
    say('このページは https でのみ動きます。', true);
    button.disabled = true;
    return;
  }
  if (typeof DecompressionStream === 'undefined') {
    say('お使いのブラウザでは表示できません（Safari 16.4 / Chrome 80 / Firefox 113 以降が必要です）。', true);
    button.disabled = true;
    return;
  }

  function unlock(password) {
    var subtle = window.crypto.subtle;
    var iv = bytes(data.iv);
    var ct = bytes(data.ct);
    var signed = new Uint8Array(iv.length + ct.length);
    signed.set(iv, 0);
    signed.set(ct, iv.length);

    return subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits'])
      .then(function (base) {
        return subtle.deriveBits({
          name: 'PBKDF2',
          salt: bytes(data.salt),
          iterations: data.iterations,
          hash: 'SHA-256'
        }, base, 512);
      })
      .then(function (raw) {
        var derived = new Uint8Array(raw);
        return Promise.all([
          subtle.importKey('raw', derived.slice(0, 32), { name: 'AES-CBC' }, false, ['decrypt']),
          subtle.importKey('raw', derived.slice(32), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'])
        ]);
      })
      .then(function (keys) {
        return subtle.verify('HMAC', keys[1], bytes(data.mac), signed).then(function (ok) {
          if (!ok) return null;
          return subtle.decrypt({ name: 'AES-CBC', iv: iv }, keys[0], ct);
        });
      })
      .then(function (packed) {
        if (packed === null) return null;
        var stream = new Blob([packed]).stream().pipeThrough(new DecompressionStream('gzip'));
        return new Response(stream).text();
      });
  }

  function show(page) {
    document.open();
    document.write(page);
    document.close();
  }

  function attempt(password, silent) {
    button.disabled = true;
    say('開いています…');

    return unlock(password).then(function (page) {
      if (page === null) {
        button.disabled = false;
        if (silent) {
          forget();
          say('');
        } else {
          input.select();
          say('パスワードが違います。', true);
        }
        return;
      }
      remember(password);
      show(page);
    }).catch(function () {
      button.disabled = false;
      forget();
      say(silent ? '' : 'パスワードが違います。', !silent);
    });
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    if (input.value) attempt(input.value, false);
  });

  // 入口で入れたパスワードがあれば、そのまま開く。
  var saved = recall();
  if (saved) attempt(saved, true);
})();
