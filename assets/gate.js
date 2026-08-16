/* 入口ページ。パスワードでページ本体を復号して表示する。各スライドでも同じものを使う。
 *
 * ページに埋まっているのは暗号文だけで、平文はどこにも置かれていない。
 * タイトルも暗号文の中にしかないので、解錠するまで何のページかは分からない。
 *
 * 一度解錠したら sessionStorage に控えて、入口 → スライドと辿るときに訊き直さない。
 * 復号そのものは crypto.js にある。
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

  var unsupported = window.slidesUnsupported();
  if (unsupported) {
    say(unsupported, true);
    button.disabled = true;
    return;
  }

  function attempt(password, silent) {
    button.disabled = true;
    say('開いています…');

    return window.slidesDecrypt(data, password).then(function (page) {
      if (page === null) {
        button.disabled = false;
        window.slidesPass.clear();
        if (silent) {
          say('');
        } else {
          input.select();
          say('パスワードが違います。', true);
        }
        return;
      }
      window.slidesPass.set(password);
      document.open();
      document.write(page);
      document.close();
    }).catch(function () {
      button.disabled = false;
      window.slidesPass.clear();
      say(silent ? '' : 'パスワードが違います。', !silent);
    });
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    if (input.value) attempt(input.value, false);
  });

  // 入口で入れたパスワードがあれば、そのまま開く。
  var saved = window.slidesPass.get();
  if (saved) attempt(saved, true);
})();
