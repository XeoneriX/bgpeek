/** Initialise the Swagger UI bundle on the branded /api/docs page.
 *
 * The openapi URL is read from a data-* attribute on the container so this
 * file can stay pure JS — Jinja interpolation stays in the template, not
 * inside string literals. `SwaggerUIBundle` itself is loaded from a CDN
 * script tag; the `/api/docs` path is exempted from the page-wide CSP
 * precisely so that CDN script can run.
 */
window.addEventListener("DOMContentLoaded", function () {
  var container = document.getElementById("swagger-ui");
  if (!container) return;
  var openapiUrl = container.dataset.openapiUrl;
  if (!openapiUrl || typeof SwaggerUIBundle !== "function") return;
  SwaggerUIBundle({
    url: openapiUrl,
    dom_id: "#swagger-ui",
    deepLinking: true,
    displayRequestDuration: true,
    tryItOutEnabled: true,
    defaultModelsExpandDepth: 1,
    docExpansion: "list",
    syntaxHighlight: { theme: "nord" },
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
  });
});
