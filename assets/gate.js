/* パスワードでスライド本体を復号して表示する。
 *
 * ページに埋まっているのは暗号文だけで、平文はどこにも置かれていない。
 * 鍵は PBKDF2-HMAC-SHA256 (build.py と同じ回数) で 512 bit 導出し、
 * 前半を AES-CBC、後半を HMAC に使う。HMAC を先に検証してから復号する
 * （検証に通らない = パスワードが違う、と判定できる）。
 */
(function () {
  'use strict';

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

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    var password = input.value;
    if (!password) return;

    button.disabled = true;
    say('開いています…');

    unlock(password).then(function (page) {
      if (page === null) {
        button.disabled = false;
        input.select();
        say('パスワードが違います。', true);
        return;
      }
      document.open();
      document.write(page);
      document.close();
    }).catch(function () {
      button.disabled = false;
      say('パスワードが違います。', true);
    });
  });
})();
