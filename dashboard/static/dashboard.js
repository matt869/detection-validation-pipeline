// Dashboard interactions. No dependencies, no build step - the CSP served with
// every page blocks external scripts anyway.

(function () {
  "use strict";

  // Click a case row to reveal the compiled queries and evidence that produced
  // its outcome. Explaining *why* a case is blind is the whole point of the
  // detail row, so it lives one click away rather than behind a separate page.
  document.querySelectorAll("tr.case-row").forEach(function (row) {
    row.addEventListener("click", function () {
      var detail = row.nextElementSibling;
      if (detail && detail.classList.contains("detail")) {
        detail.classList.toggle("open");
      }
    });
  });

  // Outcome filters. Hides rows rather than re-rendering, so an open detail row
  // stays open when the filter is cleared.
  var buttons = document.querySelectorAll(".filters button");
  buttons.forEach(function (button) {
    button.addEventListener("click", function () {
      var wanted = button.getAttribute("data-filter");

      buttons.forEach(function (other) { other.classList.remove("active"); });
      button.classList.add("active");

      document.querySelectorAll("tr.case-row").forEach(function (row) {
        var show = wanted === "all" || row.getAttribute("data-outcome") === wanted;
        row.style.display = show ? "" : "none";

        var detail = row.nextElementSibling;
        if (detail && detail.classList.contains("detail")) {
          detail.style.display = show ? "" : "none";
          if (!show) { detail.classList.remove("open"); }
        }
      });
    });
  });
})();
