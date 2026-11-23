// Ask for confirmation before submitting forms marked data-confirm="message".
// Loaded from 'self' (the CSP forbids inline script).
(function () {
  "use strict";
  document.addEventListener("submit", function (e) {
    var msg = e.target && e.target.getAttribute && e.target.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) {
      e.preventDefault();
    }
  }, true);
})();
