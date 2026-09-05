(() => {
  const toggle = document.querySelector(".nav-toggle");
  const nav = document.querySelector(".site-nav");
  if (toggle && nav) {
    toggle.addEventListener("click", () => {
      const open = nav.classList.toggle("is-open");
      toggle.setAttribute("aria-expanded", open);
    });
  }
  const input = document.querySelector("#passwordInput");
  const bar = document.querySelector("#strengthBar");
  const label = document.querySelector("#strengthLabel");
  const meta = document.querySelector("#strengthMeta");
  const tips = document.querySelector("#passwordTips");
  if (input && bar && label && meta) {
    const update = () => {
      const value = input.value;
      let points = 0;
      if (value.length >= 8) points++;
      if (value.length >= 14) points++;
      if (/[a-z]/.test(value) && /[A-Z]/.test(value)) points++;
      if (/\d/.test(value)) points++;
      if (/[^a-zA-Z\d]/.test(value)) points++;
      const names = ["Waiting for input", "Very weak", "Weak", "Fair", "Strong", "Excellent"];
      const colors = ["", "weak", "weak", "fair", "strong", "excellent"];
      label.textContent = value ? names[points] : names[0];
      label.className = colors[points] ? colors[points] : "";
      bar.style.width = `${value ? Math.max(5, points * 20) : 0}%`;
      bar.className = colors[points] || "";
      meta.textContent = `${value ? Math.round((value.length * 3.5) + points * 8) : 0} bits estimated`;
      if (tips) tips.querySelectorAll("span").forEach((tip, index) => tip.classList.toggle("tip-done", [value.length >= 14, /[A-Z]/.test(value) && /\d/.test(value), value.length > 0][index]));
    };
    input.addEventListener("input", update);
    const show = document.querySelector("#togglePassword");
    if (show) show.addEventListener("click", () => { input.type = input.type === "password" ? "text" : "password"; show.textContent = input.type === "password" ? "Show" : "Hide"; });
  }
})();
