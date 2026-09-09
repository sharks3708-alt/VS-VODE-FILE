(() => {
  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = document.getElementById(button.dataset.copyTarget);
      if (!target) return;
      await navigator.clipboard.writeText(target.textContent);
      const original = button.textContent;
      button.textContent = "Copied";
      setTimeout(() => { button.textContent = original; }, 1400);
    });
  });

  const hashForm = document.querySelector("#hashForm");
  const hashLoading = document.querySelector("#hashLoading");
  if (hashForm && hashLoading) {
    hashForm.addEventListener("submit", () => {
      hashLoading.classList.add("is-visible");
      const submit = document.querySelector("#hashSubmit");
      if (submit) submit.disabled = true;
    });
  }

  const metrics = document.querySelectorAll("[data-metric]");
  const scoreOutput = document.querySelector("#cvssScore");
  if (!metrics.length || !scoreOutput) return;
  const values = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.62 },
    UI: { N: 0.85, R: 0.62 },
    C: { N: 0, L: 0.22, H: 0.56 },
    I: { N: 0, L: 0.22, H: 0.56 },
    A: { N: 0, L: 0.22, H: 0.56 },
  };
  const roundup = (value) => Math.ceil((value * 10) - 1e-9) / 10;
  const severityFor = (score) => score === 0 ? ["None", "none", "Informational"] : score < 4 ? ["Low", "low", "Limited"] : score < 7 ? ["Medium", "medium", "Material"] : score < 9 ? ["High", "high", "Serious"] : ["Critical", "critical", "Urgent"];
  const calculate = () => {
    const selected = {};
    metrics.forEach((input) => { selected[input.dataset.metric] = input.value; });
    const pr = selected.S === "U" ? { N: 0.85, L: 0.62, H: 0.27 } : { N: 0.85, L: 0.68, H: 0.5 };
    const exploitability = 8.22 * values.AV[selected.AV] * values.AC[selected.AC] * pr[selected.PR] * values.UI[selected.UI];
    const isc = 1 - ((1 - values.C[selected.C]) * (1 - values.I[selected.I]) * (1 - values.A[selected.A]));
    let score = 0;
    if (isc > 0) {
      const impact = selected.S === "U" ? 6.42 * isc : 7.52 * (isc - 0.029) - 3.25 * Math.pow(isc - 0.02, 15);
      score = roundup(Math.min(selected.S === "U" ? impact + exploitability : 1.08 * (impact + exploitability), 10));
    }
    const severity = severityFor(score);
    scoreOutput.textContent = score.toFixed(1);
    document.querySelector("#cvssSeverity").textContent = severity[0].toUpperCase();
    document.querySelector("#cvssSeverity").className = `risk-badge risk-${severity[1]}`;
    document.querySelector("#cvssRisk").textContent = severity[2];
    document.querySelector("#cvssMeter").style.width = `${score * 10}%`;
    document.querySelector("#cvssVector").textContent = `CVSS:3.1/AV:${selected.AV}/AC:${selected.AC}/PR:${selected.PR}/UI:${selected.UI}/S:${selected.S}/C:${selected.C}/I:${selected.I}/A:${selected.A}`;
    document.querySelector("#cvssExplanation").textContent = score ? `${severity[0]} severity: the selected metrics describe an estimated ${severity[2].toLowerCase()} vulnerability impact.` : "No direct impact is represented by the selected metrics.";
  };
  metrics.forEach((input) => input.addEventListener("change", calculate));
  const reset = document.querySelector("#resetCvss");
  if (reset) reset.addEventListener("click", () => { metrics.forEach((input) => { input.selectedIndex = 0; }); calculate(); });
  calculate();
})();
