/** Admin users form — auth_type radio toggles local-only fields.
 *
 * Extracted from an inline <script> so the page-wide CSP can stay strict
 * (`script-src 'self'`, no `'unsafe-inline'`). Only runs on the create
 * form; on edit the radios do not exist so the DOMContentLoaded lookup
 * is a no-op.
 */
(function () {
  "use strict";

  var radios = document.querySelectorAll('input[name="auth_type"]');
  if (!radios.length) return;
  var localFields = document.querySelectorAll(".js-local-only");

  function sync() {
    var selected = document.querySelector('input[name="auth_type"]:checked');
    var isLocal = !selected || selected.value === "local";
    localFields.forEach(function (el) {
      el.style.display = isLocal ? "" : "none";
      var input = el.querySelector("input");
      if (input) {
        input.required = isLocal;
        if (!isLocal) {
          input.value = "";
        }
      }
    });
  }

  radios.forEach(function (r) {
    r.addEventListener("change", sync);
  });
  sync();
})();
