/** Multi-device result view switcher (stacked / side-by-side / diff).
 *
 * Delegated click listener on the document dispatches on `data-view` so htmx
 * re-swaps of `#results` automatically pick up new buttons — no per-render
 * re-wire needed. Extracted from an inline <script> so the page-wide CSP can
 * stay strict (`script-src 'self'`, no `'unsafe-inline'`).
 */
(function () {
  "use strict";

  function setView(btn, mode) {
    var wrapper = btn.closest("[id^='multi-result-']");
    if (!wrapper) return;
    var container = wrapper.querySelector(".multi-results-container");
    var buttons = wrapper.querySelectorAll(".multi-view-btn");

    buttons.forEach(function (b) {
      b.classList.remove("multi-view-active");
      b.classList.add("text-slate-500", "dark:text-slate-400");
    });
    btn.classList.add("multi-view-active");
    btn.classList.remove("text-slate-500", "dark:text-slate-400");

    container.setAttribute("data-layout", mode);

    var pres = container.querySelectorAll("pre");
    if (mode === "diff" && pres.length >= 2 && window.bgpeekDiff) {
      window.bgpeekDiff.compute(pres[0], pres[1]);
    } else if (window.bgpeekDiff && pres.length > 0) {
      pres.forEach(function (pre) {
        window.bgpeekDiff.clear(pre);
      });
    }
  }

  document.addEventListener("click", function (evt) {
    var btn = evt.target.closest(".multi-view-btn[data-view]");
    if (!btn) return;
    setView(btn, btn.dataset.view);
  });

  // Compatibility shim — older call sites / extensions may still reach for the global.
  window.bgpeekMultiView = setView;
})();
