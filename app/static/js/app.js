/* PhishNet AI front-end behaviour. No inline scripts or styles anywhere (strict CSP). */
(function () {
  "use strict";
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const EXAMPLES = {
    phish: "From: PayPal Security <service@paypa1-secure.com>\nSubject: URGENT: Your account has been suspended\n\nDear Customer,\n\nWe detected suspicious activity on your PayPal account. Verify your password and credit card number immediately at http://paypa1-secure.com/verify or your account will be permanently deleted within 24 hours.\n\nThank you,\nPayPal Security Team",
    link: "http://micros0ft-login.xyz/verify-account",
    safe: "Hi team,\n\nJust a reminder that our weekly sync is on Thursday at 3 PM in Conference Room B. Please bring your project updates. The agenda is attached.\n\nBest regards,\nSarah",
  };

  document.addEventListener("DOMContentLoaded", () => {
    /* ---------- theme toggle ---------- */
    $$("[data-theme-toggle]").forEach((b) =>
      b.addEventListener("click", () => {
        const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", next);
        try { localStorage.setItem("pn-theme", next); } catch (e) { /* storage may be blocked */ }
      }));

    /* ---------- nav drawers ---------- */
    $$("[data-nav-toggle]").forEach((t) =>
      t.addEventListener("click", () => {
        const target = $(t.dataset.navToggle || "#mainnav");
        if (target) target.classList.toggle("open");
        document.body.classList.toggle("nav-open");
      }));
    $$("[data-nav-close]").forEach((el) => el.addEventListener("click", () => {
      document.body.classList.remove("nav-open");
      $$(".open").forEach((n) => n.classList.remove("open"));
    }));

    /* ---------- sticky header shadow ---------- */
    const bar = $(".topbar");
    if (bar) {
      const f = () => bar.classList.toggle("scrolled", window.scrollY > 8);
      f(); window.addEventListener("scroll", f, { passive: true });
    }

    /* ---------- confirm + loading ---------- */
    $$("form[data-confirm]").forEach((f) =>
      f.addEventListener("submit", (e) => { if (!confirm(f.dataset.confirm)) e.preventDefault(); }));
    $$("form[data-loading]").forEach((f) =>
      f.addEventListener("submit", () => {
        const b = $("button[type=submit]", f);
        if (b) { b.classList.add("is-loading"); b.disabled = true; b.dataset.label = b.textContent; b.textContent = f.dataset.loading; }
        const ov = $("#scan-overlay");
        if (ov && f.hasAttribute("data-overlay")) { ov.classList.add("show"); animateSteps(ov); }
      }));
    window.addEventListener("pageshow", (e) => {           // restore after browser "back"
      if (e.persisted) {
        $$("button.is-loading").forEach((b) => { b.disabled = false; b.classList.remove("is-loading"); if (b.dataset.label) b.textContent = b.dataset.label; });
        const ov = $("#scan-overlay"); if (ov) ov.classList.remove("show");
      }
    });
    function animateSteps(ov) {
      const steps = $$("li", ov);
      steps.forEach((s, i) => setTimeout(() => s.classList.add("on"), reduce ? 0 : 350 * i));
    }

    /* ---------- toasts ---------- */
    $$(".toast").forEach((t, i) => {
      const close = () => { t.classList.add("out"); setTimeout(() => t.remove(), 300); };
      const x = $(".toast-x", t); if (x) x.addEventListener("click", close);
      if (!t.classList.contains("toast-danger")) setTimeout(close, 6500 + i * 600);
    });

    /* ---------- copy buttons ---------- */
    $$("[data-copy]").forEach((b) =>
      b.addEventListener("click", async () => {
        const el = $(b.dataset.copy);
        const label = b.innerHTML;
        try { await navigator.clipboard.writeText(el.innerText.trim()); b.textContent = "Copied ✓"; }
        catch (e) { b.textContent = "Press Ctrl+C"; }
        setTimeout(() => { b.innerHTML = label; }, 1800);
      }));

    /* ---------- counters + char counter ---------- */
    $$("textarea[data-counter]").forEach((ta) => {
      const out = $(ta.dataset.counter);
      const upd = () => { if (out) out.textContent = ta.value.length.toLocaleString(); };
      ta.addEventListener("input", upd); upd();
    });

    /* ---------- example chips + dropzone ---------- */
    $$("[data-example]").forEach((b) =>
      b.addEventListener("click", () => {
        const ta = $(b.dataset.target);
        if (!ta) return;
        ta.value = EXAMPLES[b.dataset.example] || "";
        ta.dispatchEvent(new Event("input"));
        ta.focus();
      }));
    $$("[data-dropzone]").forEach((zone) => {
      const ta = $("textarea", zone);
      const fileIn = $("input[type=file]", zone);
      const read = (file) => {
        if (!file) return;
        if (file.size > 300 * 1024) { alert("That file is too large (max 300 KB)."); return; }
        const r = new FileReader();
        r.onload = () => {
          ta.value = String(r.result).slice(0, parseInt(ta.getAttribute("maxlength") || "50000", 10));
          ta.dispatchEvent(new Event("input"));
        };
        r.readAsText(file);   // read locally in the browser; nothing is uploaded until you press the button
      };
      ["dragenter", "dragover"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add("drag"); }));
      ["dragleave", "drop"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.remove("drag"); }));
      zone.addEventListener("drop", (e) => read(e.dataTransfer.files[0]));
      if (fileIn) fileIn.addEventListener("change", () => read(fileIn.files[0]));
    });

    /* ---------- password: show/hide + strength ---------- */
    $$("[data-pw-toggle]").forEach((b) =>
      b.addEventListener("click", () => {
        const inp = $(b.dataset.pwToggle);
        const show = inp.type === "password";
        inp.type = show ? "text" : "password";
        b.setAttribute("aria-label", show ? "Hide password" : "Show password");
        b.innerHTML = '<svg class="ic"><use href="' + b.dataset.icons + (show ? "#i-eye-off" : "#i-eye") + '"/></svg>';
      }));
    $$("[data-strength]").forEach((inp) => {
      const meter = $(inp.dataset.strength);
      inp.addEventListener("input", () => {
        const v = inp.value;
        let s = 0;
        if (v.length >= 10) s++;
        if (v.length >= 14) s++;
        if (/[a-z]/.test(v) && /[A-Z]/.test(v)) s++;
        if (/\d/.test(v)) s++;
        if (/[^\w\s]/.test(v)) s++;
        const level = v ? Math.min(4, Math.max(1, s - 0)) : 0;
        meter.dataset.level = level;
        $(".strength-text", meter).textContent = ["", "Weak", "Fair", "Good", "Strong"][level];
      });
    });

    /* ---------- OTP: digits only, auto-submit at 6 ---------- */
    $$("input.otp-input").forEach((inp) =>
      inp.addEventListener("input", () => {
        inp.value = inp.value.replace(/\D/g, "").slice(0, 6);
        if (inp.value.length === 6 && inp.form) inp.form.requestSubmit();
      }));

    /* ---------- bars / sparkline / donut / gauge (CSP-safe CSSOM styling) ---------- */
    const css = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
    const animateIn = (fn) => { reduce ? fn(1) : requestAnimationFrame(() => setTimeout(() => fn(1), 60)); };
    $$("[data-w]").forEach((el) => { el.style.width = "0%"; animateIn(() => { el.style.width = el.dataset.w + "%"; }); });
    $$("[data-h]").forEach((el) => { el.style.height = "0%"; animateIn(() => { el.style.height = el.dataset.h + "%"; }); });
    $$("[data-donut]").forEach((el) => {
      const [a, b, c] = el.dataset.donut.split(",").map(Number);
      const total = a + b + c || 1;
      const p1 = (a / total) * 100, p2 = p1 + (b / total) * 100;
      el.style.background = "conic-gradient(" + css("--safe") + " 0 " + p1 + "%, " + css("--warn") + " " + p1 + "% " + p2 + "%, " + css("--bad") + " " + p2 + "% 100%)";
    });
    $$("[data-gauge]").forEach((g) => {
      const score = Math.max(0, Math.min(100, parseFloat(g.dataset.gauge) || 0));
      const arc = $(".gauge-fill", g), num = $(".gauge-num", g);
      const C = 2 * Math.PI * 54;
      arc.style.strokeDasharray = String(C);
      arc.style.strokeDashoffset = String(C);
      animateIn(() => { arc.style.strokeDashoffset = String(C * (1 - score / 100)); });
      countTo(num, score, 1, 900);
    });
    function countTo(el, target, decimals, ms) {
      if (!el) return;
      if (reduce) { el.textContent = target.toFixed(decimals); return; }
      setTimeout(() => { el.textContent = target.toFixed(decimals); }, ms + 250);  // guarantee the final value
      const t0 = performance.now();
      const step = (t) => {
        const p = Math.min(1, (t - t0) / ms), e = 1 - Math.pow(1 - p, 3);
        el.textContent = (target * e).toFixed(decimals);
        if (p < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    }

    /* ---------- scroll reveal + count-up on view ---------- */
    const io = "IntersectionObserver" in window ? new IntersectionObserver((entries) => {
      entries.forEach((en) => {
        if (!en.isIntersecting) return;
        en.target.classList.add("in");
        if (en.target.dataset.count) countTo(en.target, parseFloat(en.target.dataset.count), 0, 1100);
        io.unobserve(en.target);
      });
    }, { threshold: 0.15 }) : null;
    $$(".reveal, [data-count]").forEach((el) => {
      if (io && !reduce) io.observe(el);
      else { el.classList.add("in"); if (el.dataset.count) el.textContent = el.dataset.count; }
    });

    /* ---------- rotating placeholder on the hero input ---------- */
    const hero = $("#content");
    if (hero && !reduce) {
      const ph = ["https://secure-paypa1.com/login", "Paste the full text of a suspicious email…", "http://micros0ft-verify.xyz/account", "Your account will be suspended in 24 hours…"];
      let i = 0;
      setInterval(() => { if (document.activeElement !== hero && !hero.value) { i = (i + 1) % ph.length; hero.setAttribute("placeholder", ph[i]); } }, 3200);
    }

    /* ---------- filter chips auto-submit ---------- */
    $$("[data-autosubmit]").forEach((el) => el.addEventListener("change", () => el.form.requestSubmit()));
  });
})();
