/* Runs before first paint (loaded in <head>, not deferred) to avoid a light/dark flash. */
(function () {
  try {
    var q = /[?&]theme=(light|dark)/.exec(location.search);
    var t = q ? q[1] : localStorage.getItem("pn-theme");
    if (!t) t = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", t);
  } catch (e) {
    document.documentElement.setAttribute("data-theme", "light");
  }
})();
