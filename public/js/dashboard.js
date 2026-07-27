// public/js/dashboard.js
// Loads recent audit history from GET /audit/history and renders it,
// plus a mini scan form so users can kick off a new audit from the dashboard.

document.addEventListener('DOMContentLoaded', () => {
  loadHistory();

  const form = document.getElementById('dash-scan-form');
  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const input = document.getElementById('dash-url-input');
      const btn = document.getElementById('dash-scan-btn');
      const url = input.value.trim();
      if (!url) return;

      btn.disabled = true;
      btn.textContent = 'Scanning...';

      try {
        const res = await fetch('/audit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url }),
        });
        const data = await res.json();
        if (!res.ok || !data.success) throw new Error(data.error?.message || 'Audit failed.');

        sessionStorage.setItem('latestAuditReport', JSON.stringify(data.data));
        window.location.href = `/report?auditId=${encodeURIComponent(data.data.auditId)}`;
      } catch (err) {
        alert(err.message);
        btn.disabled = false;
        btn.textContent = 'Run Audit';
      }
    });
  }
});

async function loadHistory() {
  const list = document.getElementById('history-list');
  const emptyState = document.getElementById('history-empty');
  if (!list) return;

  try {
    const res = await fetch('/audit/history');
    const data = await res.json();
    const history = (data && data.data) || [];

    if (history.length === 0) {
      emptyState.style.display = 'block';
      return;
    }
    emptyState.style.display = 'none';

    list.innerHTML = history
      .map(
        (item) => `
        <div class="history-item">
          <div>
            <div class="site">${escapeHtml(item.website)}</div>
            <div style="color:var(--slate); font-size:0.75rem;">${escapeHtml(item.date)}</div>
          </div>
          <div style="text-align:right;">
            <div class="history-score" style="color:${scoreColor(item.score)}">${item.score}/100</div>
            <div style="color:var(--slate); font-size:0.72rem;">${escapeHtml(item.rating)}</div>
          </div>
        </div>`
      )
      .join('');
  } catch (err) {
    emptyState.style.display = 'block';
    emptyState.textContent = 'Unable to load audit history.';
  }
}

function scoreColor(score) {
  if (score >= 90) return '#00ff9d';
  if (score >= 75) return '#7CFC00';
  if (score >= 55) return '#FFD166';
  if (score >= 35) return '#ff9e57';
  return '#ff4d5e';
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str ?? '';
  return div.innerHTML;
}
