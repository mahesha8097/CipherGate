// public/js/report.js
// Renders the audit report page: score ring (Chart.js), stats, and
// grouped pass/fail findings with filtering by module.

let reportData = null;
let scoreChart = null;

document.addEventListener('DOMContentLoaded', async () => {
  const params = new URLSearchParams(window.location.search);
  const auditId = params.get('auditId');

  const cached = sessionStorage.getItem('latestAuditReport');
  if (cached) {
    const parsed = JSON.parse(cached);
    if (!auditId || parsed.auditId === auditId) {
      reportData = parsed;
    }
  }

  if (!reportData && auditId) {
    try {
      const res = await fetch(`/report/json/${encodeURIComponent(auditId)}`);
      if (res.ok) reportData = await res.json();
    } catch (err) {
      // fall through to empty state
    }
  }

  if (!reportData) {
    document.getElementById('report-empty').style.display = 'block';
    document.getElementById('report-content').style.display = 'none';
    return;
  }

  renderReport(reportData);
});

function renderReport(data) {
  document.getElementById('report-empty').style.display = 'none';
  document.getElementById('report-content').style.display = 'grid';

  document.getElementById('report-website').textContent = data.website;
  document.getElementById('report-date').textContent = data.auditDate;
  document.getElementById('report-summary').textContent = data.executiveSummary;

  document.getElementById('stat-total').textContent = data.stats.totalChecks;
  document.getElementById('stat-passed').textContent = data.stats.passed;
  document.getElementById('stat-failed').textContent = data.stats.failed;

  const scoreLabel = document.getElementById('score-label');
  scoreLabel.textContent = data.riskScore.rating;
  scoreLabel.style.color = data.riskScore.color;
  scoreLabel.style.borderColor = data.riskScore.color + '66';
  scoreLabel.style.background = data.riskScore.color + '14';
  document.getElementById('score-num').textContent = data.riskScore.value;
  document.getElementById('score-num').style.color = data.riskScore.color;

  renderScoreRing(data.riskScore.value, data.riskScore.color);
  renderModulePills(data);
  renderFindings(data, 'all');

  document.getElementById('download-pdf').href = `/report/pdf/${data.auditId}`;
  document.getElementById('download-json').href = `/report/json/${data.auditId}`;
}

function renderScoreRing(score, color) {
  const ctx = document.getElementById('score-ring').getContext('2d');
  if (scoreChart) scoreChart.destroy();
  scoreChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      datasets: [
        {
          data: [score, 100 - score],
          backgroundColor: [color, 'rgba(255,255,255,0.06)'],
          borderWidth: 0,
        },
      ],
    },
    options: {
      cutout: '78%',
      responsive: true,
      maintainAspectRatio: true,
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      animation: { animateRotate: true, duration: 900 },
    },
  });
}

function renderModulePills(data) {
  const modules = [...new Set(data.failedChecks.concat(data.passedChecks).map((c) => c.module))];
  const wrap = document.getElementById('module-pills');
  wrap.innerHTML =
    `<div class="module-pill active" data-module="all">All Modules</div>` +
    modules.map((m) => `<div class="module-pill" data-module="${escapeHtml(m)}">${escapeHtml(m)}</div>`).join('');

  wrap.querySelectorAll('.module-pill').forEach((pill) => {
    pill.addEventListener('click', () => {
      wrap.querySelectorAll('.module-pill').forEach((p) => p.classList.remove('active'));
      pill.classList.add('active');
      renderFindings(reportData, pill.dataset.module);
    });
  });
}

function renderFindings(data, moduleFilter) {
  const failedContainer = document.getElementById('failed-list');
  const passedContainer = document.getElementById('passed-list');

  const filterFn = (c) => moduleFilter === 'all' || c.module === moduleFilter;

  const failed = data.failedChecks.filter(filterFn);
  const passed = data.passedChecks.filter(filterFn);

  failedContainer.innerHTML =
    failed.length === 0
      ? '<div class="empty-state" style="padding:20px;">No failed checks in this module. ✅</div>'
      : failed.map(renderCheckItem).join('');

  passedContainer.innerHTML =
    passed.length === 0
      ? '<div class="empty-state" style="padding:20px;">No passed checks in this module.</div>'
      : passed.map(renderCheckItem).join('');
}

function renderCheckItem(check) {
  const passed = check.status === 'Pass';
  return `
    <div class="check-item">
      <div class="check-badge ${passed ? 'pass' : 'fail'}">${passed ? '✓' : '✕'}</div>
      <div class="check-body">
        <div class="check-title-row">
          <span class="check-title">${escapeHtml(check.name)}</span>
          <span class="severity-tag sev-${check.severity}">${escapeHtml(check.severity)}</span>
        </div>
        <div class="check-detail">${escapeHtml(check.detail)}</div>
        ${!passed ? `<div class="check-reco"><strong>Mitigation:</strong> ${escapeHtml(check.recommendation)}</div>` : ''}
      </div>
    </div>`;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str ?? '';
  return div.innerHTML;
}
