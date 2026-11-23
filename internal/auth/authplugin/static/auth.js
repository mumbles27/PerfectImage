// Auth module helpers (CSP: no inline script).
(function () {
  "use strict";
  // <form data-confirm="Really?"> asks before submitting.
  document.addEventListener("submit", function (evt) {
    var form = evt.target;
    var msg = form && form.getAttribute && form.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) evt.preventDefault();
  }, true);
})();
