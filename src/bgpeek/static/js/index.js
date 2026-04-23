/** Main-page interactivity — query form, device multi-select, target validation,
 * HTMX lifecycle state for Run/Abort buttons, dynamic placeholder, empty-state
 * observer.
 *
 * Extracted from an inline `<script>` block so the page-wide CSP can enforce
 * `script-src 'self'` without an `'unsafe-inline'` carve-out. Jinja strings that
 * used to be interpolated inline are now read from `data-*` attributes on
 * `#query-config`.
 */
(function () {
  "use strict";

  var form = document.getElementById("query-form");
  var btnRun = document.getElementById("btn-run");
  var btnAbort = document.getElementById("btn-abort");
  var empty = document.getElementById("empty-state");
  var results = document.getElementById("results");
  var deviceSel = document.getElementById("device-select");
  var deviceCount = document.getElementById("device-count");
  var cfg = document.getElementById("query-config");
  if (!form || !cfg) return;

  var labelSelected = cfg.dataset.labelNSelected || "";
  var msgInvalid = cfg.dataset.errorTargetFormat || "Invalid target";
  var placeholders = {
    bgp_route: cfg.dataset.placeholderBgp || "",
    ping: cfg.dataset.placeholderPing || "",
    traceroute: cfg.dataset.placeholderTrace || "",
  };

  function updateFormAction() {
    var selected = deviceSel.selectedOptions.length;
    if (selected > 1) {
      form.setAttribute("hx-post", "/query/multi");
    } else {
      form.setAttribute("hx-post", "/query");
    }
    if (window.htmx) {
      window.htmx.process(form);
    }
    if (selected > 0) {
      deviceCount.textContent = selected + " " + labelSelected;
    } else {
      deviceCount.textContent = "";
    }
  }

  deviceSel.addEventListener("change", updateFormAction);
  updateFormAction();

  var regionFilter = document.getElementById("region-filter");
  if (regionFilter) {
    regionFilter.addEventListener("change", function () {
      var selected = regionFilter.value;
      var optgroups = deviceSel.querySelectorAll("optgroup");
      var topOptions = deviceSel.querySelectorAll(":scope > option");

      optgroups.forEach(function (og) {
        og.style.display = !selected || og.label === selected ? "" : "none";
        if (og.style.display === "none") {
          Array.from(og.options).forEach(function (o) {
            o.selected = false;
          });
        }
      });

      topOptions.forEach(function (o) {
        o.style.display = selected ? "none" : "";
        if (o.style.display === "none") {
          o.selected = false;
        }
      });

      updateFormAction();
    });
  }

  var targetEl = document.getElementById("target-input");
  var targetErr = document.getElementById("target-error");

  var RE_IPV4 =
    /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?:\/(?:3[0-2]|[12]?\d))?$/;
  var RE_IPV6 = /^(?:[0-9a-fA-F:]+)(?:\/(?:12[0-8]|1[01]\d|[1-9]?\d))?$/;
  var RE_HOST =
    /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;

  function isValidTarget(value) {
    if (RE_IPV4.test(value)) return true;
    if (RE_IPV6.test(value) && value.indexOf(":") !== -1) return true;
    if (RE_HOST.test(value)) return true;
    return false;
  }

  function clearTargetError() {
    targetEl.classList.remove(
      "border-rose-500",
      "dark:border-rose-500",
      "focus:border-rose-500",
      "focus:ring-rose-500",
    );
    targetErr.classList.add("hidden");
    targetErr.textContent = "";
  }

  function showTargetError(msg) {
    targetEl.classList.add(
      "border-rose-500",
      "dark:border-rose-500",
      "focus:border-rose-500",
      "focus:ring-rose-500",
    );
    targetErr.classList.remove("hidden");
    targetErr.textContent = msg;
  }

  targetEl.addEventListener("input", clearTargetError);
  targetEl.addEventListener("blur", function () {
    targetEl.value = targetEl.value.trim();
  });

  form.addEventListener("htmx:beforeRequest", function (evt) {
    var v = (targetEl.value || "").trim();
    targetEl.value = v;
    if (!isValidTarget(v)) {
      evt.preventDefault();
      evt.stopImmediatePropagation();
      showTargetError(msgInvalid);
      targetEl.focus();
    }
  });
  form.addEventListener("htmx:configRequest", function (evt) {
    if (typeof evt.detail.parameters.target === "string") {
      evt.detail.parameters.target = evt.detail.parameters.target.trim();
    }
  });

  form.addEventListener("htmx:beforeRequest", function () {
    btnRun.disabled = true;
    btnAbort.disabled = false;
  });
  form.addEventListener("htmx:afterRequest", function () {
    btnRun.disabled = false;
    btnAbort.disabled = true;
  });

  if (btnAbort) {
    btnAbort.addEventListener("click", function () {
      if (window.htmx) {
        window.htmx.trigger(form, "htmx:abort");
      }
    });
  }

  var observer = new MutationObserver(function () {
    empty.style.display = results.children.length ? "none" : "";
  });
  observer.observe(results, { childList: true });

  var targetInput = document.querySelector('input[name="target"]');
  var queryTypeSelect = document.querySelector('select[name="query_type"]');
  function updatePlaceholder() {
    var type = queryTypeSelect.value;
    targetInput.placeholder = placeholders[type] || "8.8.8.0/24";
  }
  queryTypeSelect.addEventListener("change", updatePlaceholder);
  updatePlaceholder();
})();
