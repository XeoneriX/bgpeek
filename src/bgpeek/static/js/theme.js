/** Dark/light theme toggle for bgpeek. */
(function () {
  "use strict";

  var STORAGE_KEY = "bgpeek-theme";

  function applyTheme(dark) {
    document.documentElement.classList.toggle("dark", dark);
    localStorage.setItem(STORAGE_KEY, dark ? "dark" : "light");
  }

  function toggle() {
    applyTheme(!document.documentElement.classList.contains("dark"));
  }

  // Expose for the toggle button.
  window.bgpeekToggleTheme = toggle;

  // Apply stored preference (also called inline in <head> to avoid flash).
  var stored = localStorage.getItem(STORAGE_KEY);
  if (stored === "dark") {
    applyTheme(true);
  } else if (stored === "light") {
    applyTheme(false);
  }
})();
