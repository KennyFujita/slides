/* 解錠したあとに現れる一覧で動く。各行の「保存」ボタンを受け持つ。
 *
 * 押されたらそのスライドの暗号文を取ってきて、その場で復号してから
 * ダウンロードさせる。落ちるのは平文のスライドで、開くのにパスワードは要らない
 * （暗号化したまま渡しても、開くときに訊かれるだけで意味がないため）。
 *
 * パスワードは入口で入れたものを sessionStorage から取る。
 */
(function () {
  'use strict';

  var status = document.getElementById('dl-status');
  var buttons = document.querySelectorAll('.deck-list .dl');

  function say(message, isError) {
    if (!status) return;
    status.textContent = message;
    status.className = isError ? 'dl-status error' : 'dl-status';
  }

  function fetchPayload(src) {
    return fetch(src, { cache: 'no-store' }).then(function (res) {
      if (!res.ok) throw new Error(res.status);
      return res.text();
    }).then(function (html) {
      var doc = new DOMParser().parseFromString(html, 'text/html');
      var el = doc.getElementById('payload');
      if (!el) throw new Error('payload なし');
      return JSON.parse(el.textContent);
    });
  }

  Array.prototype.forEach.call(buttons, function (button) {
    button.addEventListener('click', function () {
      var password = window.slidesPass.get();
      if (!password) {
        say('パスワードが分かりません。入口から開き直してください。', true);
        return;
      }

      button.disabled = true;
      say('用意しています…');

      fetchPayload(button.dataset.src)
        .then(function (payload) { return window.slidesDecrypt(payload, password); })
        .then(function (page) {
          if (page === null) throw new Error('復号できません');
          window.slidesDownload(window.slidesStripSaveButton(page), button.dataset.name);
          button.disabled = false;
          say('');
        })
        .catch(function () {
          button.disabled = false;
          say('保存できませんでした。', true);
        });
    });
  });
})();
