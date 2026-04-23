/** Admin devices form — Test SSH button + Junos source-IP warning.
 *
 * Extracted from two inline <script> blocks so the page-wide CSP can stay
 * strict (`script-src 'self'`, no `'unsafe-inline'`). The Test SSH button
 * now carries `data-action="test-ssh"` + `data-cred-id` + `data-device-id`
 * instead of an inline `onclick=` handler.
 */
(function () {
  "use strict";

  async function testSsh(btn) {
    var credId = btn.dataset.credId;
    var deviceId = btn.dataset.deviceId;
    var runningLabel = btn.dataset.runningLabel || "Running…";
    var out = document.getElementById("test-ssh-result");
    if (!out) return;

    btn.disabled = true;
    out.textContent = runningLabel;
    out.className = "text-sm text-slate-500 dark:text-slate-400";
    try {
      var resp = await fetch(
        "/api/credentials/" + credId + "/test?device_id=" + deviceId,
        { method: "POST", headers: { Accept: "application/json" } },
      );
      if (!resp.ok) {
        out.textContent = "✗ HTTP " + resp.status;
        out.className = "text-sm text-rose-600 dark:text-rose-400";
        return;
      }
      var data = await resp.json();
      if (data.success) {
        out.textContent = "✓ " + data.message;
        out.className = "text-sm text-emerald-600 dark:text-emerald-400";
      } else {
        out.textContent = "✗ " + data.message;
        out.className = "text-sm text-rose-600 dark:text-rose-400";
      }
    } catch (err) {
      out.textContent = "✗ " + err;
      out.className = "text-sm text-rose-600 dark:text-rose-400";
    } finally {
      btn.disabled = false;
    }
  }

  var testBtn = document.getElementById("test-ssh-btn");
  if (testBtn) {
    testBtn.addEventListener("click", function () {
      testSsh(testBtn);
    });
  }

  // Junos source-IP soft warning
  var platform = document.querySelector('select[name="platform"]');
  var source4 = document.querySelector('input[name="source4"]');
  var source6 = document.querySelector('input[name="source6"]');
  var warning = document.getElementById("junos-source-warning");
  if (platform && source4 && source6 && warning) {
    function update() {
      var isJunos = platform.value === "juniper_junos";
      var hasSource = source4.value.trim() !== "" || source6.value.trim() !== "";
      warning.hidden = !(isJunos && !hasSource);
    }
    platform.addEventListener("change", update);
    source4.addEventListener("input", update);
    source6.addEventListener("input", update);
    update();
  }
})();
