// PerfectImage UI helpers. Loaded from 'self' only (CSP forbids inline script).
(function () {
  "use strict";

  // Send the CSRF token (if the active CSRF protector uses tokens) with htmx requests.
  document.addEventListener("htmx:configRequest", function (evt) {
    var meta = document.querySelector('meta[name="csrf-token"]');
    if (meta && meta.content) {
      evt.detail.headers["X-CSRF-Token"] = meta.content;
    }
  });

  // Live job log streaming via Server-Sent Events.
  function streamJobLog(pre) {
    var url = pre.getAttribute("data-stream");
    if (!url || !window.EventSource) return;
    var statusEl = document.getElementById("job-status");
    var es = new EventSource(url);
    es.addEventListener("log", function (e) {
      var msg;
      try { msg = JSON.parse(e.data); } catch (_) { return; }
      var atBottom = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 8;
      pre.appendChild(document.createTextNode(msg.line + "\n"));
      if (atBottom) pre.scrollTop = pre.scrollHeight;
    });
    es.addEventListener("status", function (e) {
      if (!statusEl) return;
      statusEl.textContent = e.data;
      statusEl.className = "status status-" + e.data;
    });
    es.addEventListener("done", function () {
      es.close();
      // Reload once so finish time, result and cancel button are current.
      var initial = statusEl ? statusEl.getAttribute("data-initial") : "";
      if (initial === "queued" || initial === "running") {
        setTimeout(function () { window.location.reload(); }, 500);
      }
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var pre = document.getElementById("job-log");
    if (pre) streamJobLog(pre);
  });
})();
