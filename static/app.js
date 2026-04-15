const state = {
  result: null,
  animationFrame: null
};

const els = {
  input: document.querySelector("#identityInput"),
  scanButton: document.querySelector("#scanButton"),
  resetHardening: document.querySelector("#resetHardening"),
  targetName: document.querySelector("#targetName"),
  targetMeta: document.querySelector("#targetMeta"),
  scoreRing: document.querySelector("#scoreRing"),
  scoreValue: document.querySelector("#scoreValue"),
  scoreBand: document.querySelector("#scoreBand"),
  impactNumber: document.querySelector("#impactNumber"),
  impactRange: document.querySelector("#impactRange"),
  categoryBars: document.querySelector("#categoryBars"),
  scanMode: document.querySelector("#scanMode"),
  exposureList: document.querySelector("#exposureList"),
  attackPaths: document.querySelector("#attackPaths"),
  pathCount: document.querySelector("#pathCount"),
  recommendations: document.querySelector("#recommendations"),
  riskDrop: document.querySelector("#riskDrop"),
  executiveReport: document.querySelector("#executiveReport"),
  copyReport: document.querySelector("#copyReport"),
  exportJson: document.querySelector("#exportJson"),
  graph: document.querySelector("#attackGraph")
};

const hardeningInputs = [...document.querySelectorAll("[data-hardening]")];

function getHardening() {
  return hardeningInputs.reduce((payload, input) => {
    payload[input.dataset.hardening] = input.checked;
    return payload;
  }, {});
}

function money(value) {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0
  }).format(value);
}

function titleCase(value) {
  return String(value)
    .replace(/([A-Z])/g, " $1")
    .replace(/^./, (letter) => letter.toUpperCase())
    .trim();
}

function escapeHtml(value) {
  const entities = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;"
  };
  return String(value).replace(/[&<>"']/g, (character) => entities[character]);
}

function severityClass(value) {
  return String(value || "low").toLowerCase();
}

function setLoading(isLoading) {
  document.body.classList.toggle("loading", isLoading);
  els.scanButton.disabled = isLoading;
  els.scanButton.lastChild.textContent = isLoading ? "Scanning" : "Scan";
}

async function runScan() {
  setLoading(true);
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        query: els.input.value,
        hardening: getHardening()
      })
    });

    if (!response.ok) {
      throw new Error(`Scan failed with status ${response.status}`);
    }

    state.result = await response.json();
    render(state.result);
  } catch (error) {
    els.executiveReport.innerHTML = `
      <div class="exposure-item">
        <div>
          <p class="item-title">Scanner unavailable</p>
          <p class="item-copy">${escapeHtml(error.message)}. Start the Flask app with python3 app.py, then reload this dashboard.</p>
        </div>
        <span class="severity high">Error</span>
      </div>
    `;
  } finally {
    setLoading(false);
  }
}

function render(result) {
  renderScore(result);
  renderCategories(result.score.categoryScores);
  renderExposures(result.exposures);
  renderAttackPaths(result.attackPaths);
  renderRecommendations(result.recommendations, result.beforeAfter);
  renderReport(result.report);
  drawGraph(result.graph);
}

function renderScore(result) {
  const score = result.score.score;
  const degrees = Math.max(0, Math.min(360, score * 3.6));
  const color = score >= 78 ? "#d9544d" : score >= 58 ? "#c48919" : score >= 35 ? "#0e7c7b" : "#2e8b57";

  els.targetName.textContent = result.identity.name;
  els.targetMeta.textContent = `${result.identity.email} | ${result.identity.role} at ${result.identity.company}`;
  els.scoreValue.textContent = score;
  els.scoreBand.textContent = result.score.band;
  els.scoreRing.style.setProperty("--score", `${degrees}deg`);
  els.scoreRing.style.background = `conic-gradient(${color} ${degrees}deg, #e7ebe1 0deg)`;
  els.impactNumber.textContent = money(result.businessImpact.estimatedFinancialRisk);
  els.impactRange.textContent = `${money(result.businessImpact.rangeLow)}-${money(result.businessImpact.rangeHigh)} exposure range`;
  els.scanMode.textContent = result.scanMode;
}

function renderCategories(scores) {
  const labels = {
    breaches: "Breach",
    credentials: "Credential",
    socials: "Social",
    darkWeb: "Dark web",
    publicRecords: "Public"
  };

  els.categoryBars.innerHTML = Object.entries(scores)
    .map(([key, value]) => `
      <div class="mini-bar">
        <span>${escapeHtml(labels[key] || titleCase(key))}</span>
        <div class="track"><span style="width: ${Math.min(100, value)}%"></span></div>
        <strong>${Math.round(value)}</strong>
      </div>
    `)
    .join("");
}

function renderExposures(exposures) {
  const groups = [
    ["breaches", "Breach exposure", (item) => item.name, (item) => item.description],
    ["credentials", "Credential signal", (item) => `${item.label}: ${item.value}`, (item) => item.description],
    ["socials", "Linked social account", (item) => item.platform, (item) => item.description],
    ["darkWeb", "Mock dark-web signal", (item) => `${item.market} (${item.price})`, (item) => item.description],
    ["publicRecords", "Public data point", (item) => item.label, (item) => item.description]
  ];

  els.exposureList.innerHTML = groups
    .flatMap(([key, label, title, copy]) => exposures[key].map((item) => ({ key, label, title: title(item), copy: copy(item), severity: item.severity })))
    .slice(0, 12)
    .map((item) => `
      <div class="exposure-item">
        <div>
          <p class="section-kicker">${escapeHtml(item.label)}</p>
          <p class="item-title">${escapeHtml(item.title)}</p>
          <p class="item-copy">${escapeHtml(item.copy)}</p>
        </div>
        <span class="severity ${severityClass(item.severity)}">${escapeHtml(item.severity)}</span>
      </div>
    `)
    .join("");
}

function renderAttackPaths(paths) {
  els.pathCount.textContent = `${paths.length} paths`;
  els.attackPaths.innerHTML = paths
    .map((path) => `
      <article class="path-card">
        <header>
          <div>
            <p class="item-title">${escapeHtml(path.title)}</p>
            <p class="item-copy">${escapeHtml(path.impact)}</p>
          </div>
          <div class="likelihood">${Math.round(path.likelihood)}%</div>
        </header>
        <ol class="path-steps">
          ${path.steps.map((step) => `<li>${escapeHtml(step)}</li>`).join("")}
        </ol>
        <p class="fix-line">${escapeHtml(path.fix)}</p>
      </article>
    `)
    .join("");
}

function renderRecommendations(recommendations, beforeAfter) {
  els.riskDrop.textContent = `${beforeAfter.riskDrop} pt max drop`;
  els.recommendations.innerHTML = recommendations
    .map((rec) => `
      <div class="rec-item ${rec.status === "done" ? "done" : ""}">
        <div>
          <p class="item-title">${escapeHtml(rec.title)}</p>
          <p class="item-copy">${escapeHtml(rec.effort)} effort | ${rec.status === "done" ? "Already modeled" : "Recommended next"}</p>
        </div>
        <div class="rec-impact">-${rec.impact}</div>
      </div>
    `)
    .join("");
}

function renderReport(report) {
  els.executiveReport.innerHTML = `
    <section>
      <h3>${escapeHtml(report.title)}</h3>
      <p>${escapeHtml(report.summary)}</p>
    </section>
    <section>
      <h3>How this identity gets attacked</h3>
      <ul>${report.howYouGetHacked.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
    </section>
    <section>
      <h3>Business impact</h3>
      <p>${escapeHtml(report.businessImpact)}</p>
    </section>
    <section>
      <h3>Fix plan</h3>
      <ul>${report.fixPlan.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
    </section>
    <section>
      <p class="muted">${escapeHtml(report.disclaimer)}</p>
    </section>
  `;
}

function reportAsText(result) {
  const report = result.report;
  return [
    report.title,
    "",
    report.summary,
    "",
    "How this identity gets attacked:",
    ...report.howYouGetHacked.map((item, index) => `${index + 1}. ${item}`),
    "",
    "Business impact:",
    report.businessImpact,
    "",
    "Fix plan:",
    ...report.fixPlan.map((item) => `- ${item}`),
    "",
    report.disclaimer
  ].join("\n");
}

function drawGraph(graph) {
  cancelAnimationFrame(state.animationFrame);

  const canvas = els.graph;
  const ctx = canvas.getContext("2d");
  const rect = canvas.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.max(320, Math.floor(rect.width * dpr));
  canvas.height = Math.max(300, Math.floor(rect.height * dpr));
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  const width = rect.width;
  const height = rect.height;
  const center = { x: width / 2, y: height / 2 };
  const radius = Math.max(92, Math.min(width, height) * 0.34);
  const nodes = graph.nodes.map((node, index) => {
    if (node.id === "identity") {
      return { ...node, x: center.x - 70, y: center.y, size: 30 };
    }
    if (node.id === "email") {
      return { ...node, x: center.x + 76, y: center.y, size: 25 };
    }
    const angle = ((index - 2) / Math.max(1, graph.nodes.length - 2)) * Math.PI * 2 - Math.PI / 2;
    return {
      ...node,
      x: center.x + Math.cos(angle) * radius,
      y: center.y + Math.sin(angle) * radius,
      size: node.type === "path" ? 22 : 18
    };
  });
  const byId = new Map(nodes.map((node) => [node.id, node]));
  let tick = 0;

  function colorFor(type) {
    return {
      identity: "#17191f",
      asset: "#0e7c7b",
      breach: "#d9544d",
      social: "#0e7c7b",
      dark: "#c48919",
      path: "#6857a6"
    }[type] || "#667085";
  }

  function paint() {
    tick += 0.018;
    ctx.clearRect(0, 0, width, height);

    ctx.lineWidth = 1.4;
    ctx.font = "12px Inter, system-ui, sans-serif";
    graph.edges.forEach((edge) => {
      const source = byId.get(edge.source);
      const target = byId.get(edge.target);
      if (!source || !target) return;

      ctx.beginPath();
      ctx.moveTo(source.x, source.y);
      ctx.lineTo(target.x, target.y);
      ctx.strokeStyle = "rgba(23, 25, 31, 0.18)";
      ctx.stroke();
    });

    nodes.forEach((node) => {
      const pulse = node.type === "path" ? Math.sin(tick * 4 + node.risk) * 2 : 0;
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.size + pulse, 0, Math.PI * 2);
      ctx.fillStyle = colorFor(node.type);
      ctx.fill();
      ctx.lineWidth = 4;
      ctx.strokeStyle = "rgba(255, 255, 255, 0.92)";
      ctx.stroke();

      const label = node.label.length > 26 ? `${node.label.slice(0, 24)}...` : node.label;
      const metrics = ctx.measureText(label);
      const labelWidth = Math.min(metrics.width + 14, 210);
      const labelX = Math.max(8, Math.min(width - labelWidth - 8, node.x - labelWidth / 2));
      const labelY = node.y + node.size + 15;

      ctx.fillStyle = "rgba(255, 255, 255, 0.94)";
      ctx.strokeStyle = "rgba(217, 223, 211, 0.95)";
      roundRect(ctx, labelX, labelY, labelWidth, 24, 6);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = "#30362f";
      ctx.textAlign = "center";
      ctx.fillText(label, labelX + labelWidth / 2, labelY + 16, labelWidth - 10);
    });

    state.animationFrame = requestAnimationFrame(paint);
  }

  paint();
}

function roundRect(ctx, x, y, width, height, radius) {
  ctx.beginPath();
  ctx.moveTo(x + radius, y);
  ctx.arcTo(x + width, y, x + width, y + height, radius);
  ctx.arcTo(x + width, y + height, x, y + height, radius);
  ctx.arcTo(x, y + height, x, y, radius);
  ctx.arcTo(x, y, x + width, y, radius);
  ctx.closePath();
}

els.scanButton.addEventListener("click", runScan);
els.input.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    runScan();
  }
});

hardeningInputs.forEach((input) => input.addEventListener("change", runScan));

document.querySelectorAll("[data-sample]").forEach((button) => {
  button.addEventListener("click", () => {
    els.input.value = button.dataset.sample;
    runScan();
  });
});

els.resetHardening.addEventListener("click", () => {
  hardeningInputs.forEach((input) => {
    input.checked = false;
  });
  runScan();
});

els.copyReport.addEventListener("click", async () => {
  if (!state.result) return;
  await navigator.clipboard.writeText(reportAsText(state.result));
  els.copyReport.lastChild.textContent = "Copied";
  setTimeout(() => {
    els.copyReport.lastChild.textContent = "Copy";
  }, 1200);
});

els.exportJson.addEventListener("click", () => {
  if (!state.result) return;
  const blob = new Blob([JSON.stringify(state.result, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "ghosttrace-scan.json";
  anchor.click();
  URL.revokeObjectURL(url);
});

window.addEventListener("resize", () => {
  if (state.result) {
    drawGraph(state.result.graph);
  }
});

runScan();
