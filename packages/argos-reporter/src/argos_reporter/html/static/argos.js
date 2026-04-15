/*
 * Minimal, dependency-free interactivity for ARGOS reports.
 *
 * The reporter deliberately ships a single file of vanilla JS. If an audit
 * recipient opens the HTML offline, everything they need must already be in
 * this document -- no bundling, no CDN.
 */
(function () {
  "use strict";

  function setupFilters(root) {
    var buttons = root.querySelectorAll("[data-argos-filter]");
    var rows = root.querySelectorAll("[data-argos-severity]");

    function apply(severity) {
      rows.forEach(function (row) {
        var match = severity === "all" || row.getAttribute("data-argos-severity") === severity;
        row.hidden = !match;
      });
      buttons.forEach(function (btn) {
        btn.setAttribute(
          "aria-pressed",
          btn.getAttribute("data-argos-filter") === severity ? "true" : "false"
        );
      });
    }

    buttons.forEach(function (btn) {
      btn.addEventListener("click", function () {
        apply(btn.getAttribute("data-argos-filter") || "all");
      });
    });

    apply("all");
  }

  document.addEventListener("DOMContentLoaded", function () {
    setupFilters(document);
  });
})();
