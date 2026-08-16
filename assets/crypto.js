/* 復号処理。入口ページ (gate.js) と、解錠後の一覧 (listing.js) の両方から使う。
 *
 * 鍵は PBKDF2-HMAC-SHA256 (build.py と同じ回数) で 512 bit 導出し、
 * 前半を AES-CBC、後半を HMAC に使う。HMAC を先に検証してから復号する
 * （検証に通らない = パスワードが違う、と判定できる）。
 */
(function () {
  'use strict';

  var SESSION_KEY = 'slides-pass';

  function bytes(b64) {
    var raw = atob(b64);
    var out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }

  // 使えない環境（安全でないコンテキスト、古いブラウザ）を先に弾く。
  window.slidesUnsupported = function () {
    if (!window.crypto || !window.crypto.subtle) {
      return 'このページは https でのみ動きます。';
    }
    if (typeof DecompressionStream === 'undefined') {
      return 'お使いのブラウザでは表示できません（Safari 16.4 / Chrome 80 / Firefox 113 以降が必要です）。';
    }
    return null;
  };

  // パスワードが違えば null を返す。合っていれば平文の HTML を返す。
  window.slidesDecrypt = function (data, password) {
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
  };

  // 一度入れたパスワードはタブの中だけで持ち回る。閉じれば消える。
  // プライベートブラウジングでは sessionStorage が触れないことがある。
  window.slidesPass = {
    get: function () {
      try { return window.sessionStorage.getItem(SESSION_KEY); } catch (e) { return null; }
    },
    set: function (v) {
      try { window.sessionStorage.setItem(SESSION_KEY, v); } catch (e) {}
    },
    clear: function () {
      try { window.sessionStorage.removeItem(SESSION_KEY); } catch (e) {}
    }
  };

  // 保存用に、スライドから保存ボタン自身を取り除く。
  window.slidesStripSaveButton = function (html) {
    var doc = new DOMParser().parseFromString(html, 'text/html');
    ['#deck-save', '#deck-save-css', '#deck-save-js'].forEach(function (sel) {
      var el = doc.querySelector(sel);
      if (el) el.parentNode.removeChild(el);
    });
    return '<!doctype html>\n' + doc.documentElement.outerHTML;
  };

  window.slidesDownload = function (html, filename) {
    var url = URL.createObjectURL(new Blob([html], { type: 'text/html' }));
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  };
})();
