/** Admin base — Save-button loading state.
 *
 * Disable + swap text on form submit so the operator sees immediate feedback
 * and can't accidentally double-submit while the redirect is in flight.
 * Opt-in via `data-loading-text` so inline delete buttons (which gate on a
 * confirm dialog and a shared submit-event handler elsewhere) are not
 * affected — swapping "Delete" → "Saving…" would shift layout and look wrong.
 *
 * Extracted from an inline <script> so the page-wide CSP can stay strict
 * (`script-src 'self'`, no `'unsafe-inline'`).
 */
(function () {
  "use strict";
  document.querySelectorAll('form[method="post"]').forEach(function (form) {
    form.addEventListener("submit", function () {
      var btn = form.querySelector('button[type="submit"][data-loading-text]');
      if (!btn || btn.disabled) return;
      btn.disabled = true;
      btn.innerText = btn.dataset.loadingText;
      btn.classList.add("opacity-60", "cursor-not-allowed");
    });
  });
})();
