/* GitSafty app UI. Talks only to window.gitsafty (desktop: Electron preload, Android: browser engine). */
(function () {
  'use strict';

  const api = window.gitsafty;
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  if (!api) {
    document.body.innerHTML = '<p style="padding:24px">GitSafty engine not loaded.</p>';
    return;
  }

  // ---------------------------------------------------------------- navigation
  function show(page) {
    $$('.page').forEach(p => p.classList.toggle('active', p.id === `page-${page}`));
    $$('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.page === page));
    if (page === 'protection') loadProtection();
  }
  $$('.nav-item').forEach(b => b.addEventListener('click', () => show(b.dataset.page)));

  // ---------------------------------------------------------------- progress
  function progress(el) {
    const bar = $('.bar', el);
    const text = $('span', el);
    return {
      start(label) { el.hidden = false; el.classList.add('indeterminate'); text.textContent = label || 'Working…'; },
      update(done, total, label) {
        if (total) { el.classList.remove('indeterminate'); bar.style.setProperty('--p', `${Math.round((done / total) * 100)}%`); }
        text.textContent = label || (total ? `${done} of ${total}` : `${done}`);
      },
      stop() { el.hidden = true; }
    };
  }

  // ---------------------------------------------------------------- results
  function tagOf(f) {
    if (f.verdict === 'CONFIRMED') return '<span class="tag malware">MALWARE</span>';
    if (f.severity === 'CRITICAL' && f.category !== 'secret') return '<span class="tag danger">DANGER</span>';
    if (f.category === 'secret') return '<span class="tag review">SECRET</span>';
    return '<span class="tag review">REVIEW</span>';
  }

  function renderResult(container, result, { onRemove } = {}) {
    const confirmed = result.findings.filter(f => f.verdict === 'CONFIRMED' && !(f.action && f.action.removed));
    const removed = result.findings.filter(f => f.action && f.action.removed);
    const open = result.findings.filter(f => !(f.action && f.action.removed));
    const cls = confirmed.length ? 'bad' : open.length ? 'warn' : 'ok';
    const headline = confirmed.length
      ? `Malware found: ${confirmed.length}`
      : removed.length && !open.length ? `Cleaned: ${removed.length} removed`
        : open.length ? `No malware. ${open.length} thing(s) to review` : 'Clean. Nothing found.';

    const groups = new Map();
    for (const f of result.findings) {
      const key = f.group || f.archive || (f.filePath || '').split('/')[0] || result.title;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(f);
    }

    const canRemove = onRemove && confirmed.length && result.canRemove;
    container.innerHTML = `
      <div class="summary ${cls}">
        <div class="headline">${esc(headline)}</div>
        <div class="stats">${(result.stats || []).map(s => `<span>${esc(s.label)}: <b>${esc(s.value)}</b></span>`).join('')}</div>
      </div>
      ${canRemove ? `<div class="result-actions"><button class="primary" id="remove-btn">Remove ${confirmed.length} confirmed malware</button>
        <span class="muted small">A backup of every removed file is kept. Only confirmed malware is touched.</span></div>` : ''}
      ${confirmed.length && !result.canRemove ? `<p class="muted small">${esc(result.removeNote || 'Delete these files yourself.')}</p>` : ''}
      ${result.notes && result.notes.length ? `<p class="muted small">${result.notes.map(esc).join('<br>')}</p>` : ''}
      ${[...groups].map(([title, list]) => `
        <div class="group">
          <div class="group-title">${esc(title)}</div>
          ${list.slice(0, 60).map(f => `
            <div class="finding">
              <div class="name">${tagOf(f)}${esc(f.name)}</div>
              <div class="path">${esc(f.filePath || '')}${f.lineNumber ? ':' + f.lineNumber : ''}</div>
              ${f.description && f.verdict !== 'CONFIRMED' ? `<div class="muted small">${esc(f.description)}</div>` : ''}
              ${f.action ? `<div class="action ${f.action.removed ? 'removed' : 'muted'}">${esc(f.action.text)}</div>` : ''}
            </div>`).join('')}
          ${list.length > 60 ? `<div class="finding muted small">… ${list.length - 60} more</div>` : ''}
        </div>`).join('')}
    `;
    const btn = $('#remove-btn', container);
    if (btn) {
      btn.addEventListener('click', async () => {
        btn.disabled = true;
        btn.textContent = 'Removing…';
        try {
          const updated = await onRemove(result);
          renderResult(container, updated, { onRemove });
        } catch (err) {
          btn.disabled = false;
          btn.textContent = 'Try again';
          container.insertAdjacentHTML('afterbegin', `<p class="error">${esc(err.message || err)}</p>`);
        }
      });
    }
  }

  function renderError(container, err) {
    container.innerHTML = `<p class="error">${esc((err && err.message) || err)}</p>`;
  }

  // ---------------------------------------------------------------- protection (desktop)
  async function loadProtection() {
    const box = $('#protection-status');
    box.innerHTML = '<p class="muted">Checking…</p>';
    let st;
    try { st = await api.status(); } catch (err) { renderError(box, err); return; }

    const card = (id, title, desc, on, labelOn, labelOff, button) => `
      <div class="card">
        <div><div class="title">${esc(title)}</div><div class="desc">${esc(desc)}</div></div>
        <div class="row"><span class="state ${on ? 'on' : 'off'}">${esc(on ? labelOn : labelOff)}</span>${button ? `<button data-act="${id}">${esc(button)}</button>` : ''}</div>
      </div>`;

    box.innerHTML = [
      card('protect', 'Protect all projects on this computer', 'Checks every git push, clone and pull.', st.globalHooks, 'On', 'Off', st.globalHooks ? 'Turn off' : 'Turn on'),
      card('pull', 'Scan every git pull', 'Also pulls that say "Already up to date".', st.pullScan === 'on', 'On', st.pullScan === 'off-by-user' ? 'Off (by you)' : 'Off', st.pullScan === 'on' ? 'Turn off' : 'Turn on'),
      card('vault', 'Safe GitHub login', 'Stay logged out of GitHub; confirm each push.', st.vault === 'on', 'On', 'Off', null)
    ].join('');

    $('#protection-note').textContent = st.cli.installed
      ? `GitSafty command ${st.cli.version ? 'v' + st.cli.version + ' ' : ''}is installed.`
      : st.node ? 'Turning protection on installs the gitsafty command with npm.' : 'Protection needs Node.js. Install it from nodejs.org, then reopen this app.';

    $$('[data-act]', box).forEach(b => b.addEventListener('click', async () => {
      const out = $('#protection-output');
      $$('[data-act]', box).forEach(x => { x.disabled = true; });
      b.textContent = 'Working…';
      try {
        const r = b.dataset.act === 'protect' ? await api.setProtection(!st.globalHooks) : await api.setPullScan(st.pullScan !== 'on');
        out.hidden = !r.output;
        out.textContent = r.output || '';
      } catch (err) {
        out.hidden = false;
        out.textContent = String((err && err.message) || err);
      }
      loadProtection();
    }));
  }

  // ---------------------------------------------------------------- scan
  const scanProgress = progress($('#scan-progress'));
  async function removeAndRefresh(result) {
    return api.removeMalware(result.id);
  }

  $$('.choice').forEach(btn => btn.addEventListener('click', async () => {
    const mode = btn.dataset.mode;
    const out = $('#scan-result');
    let target;
    try {
      target = mode === 'files' ? await api.pickFiles() : await api.pickFolder();
    } catch (err) { renderError(out, err); return; }
    if (!target || (Array.isArray(target) && !target.length)) return;

    $$('.choice').forEach(c => { c.disabled = true; });
    out.innerHTML = '';
    scanProgress.start('Scanning…');
    try {
      const result = await api.scan(mode, target, (done, total, label) => scanProgress.update(done, total, label));
      renderResult(out, result, { onRemove: removeAndRefresh });
    } catch (err) {
      renderError(out, err);
    } finally {
      scanProgress.stop();
      $$('.choice').forEach(c => { c.disabled = false; });
    }
  }));

  // ---------------------------------------------------------------- github
  const ghProgress = progress($('#github-progress'));
  $('#github-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const out = $('#github-result');
    const submit = $('#github-form button[type=submit]');
    submit.disabled = true;
    out.innerHTML = '';
    ghProgress.start('Reading the file list from GitHub…');
    try {
      const result = await api.scanGitHub($('#github-url').value, $('#github-token').value.trim(),
        (done, total) => ghProgress.update(done, total, `Checked ${done} of ${total} files`));
      renderResult(out, result);
    } catch (err) {
      renderError(out, err);
    } finally {
      ghProgress.stop();
      submit.disabled = false;
    }
  });

  // ---------------------------------------------------------------- doctor (desktop)
  async function runDoctor(fix) {
    const out = $('#doctor-output');
    out.hidden = false;
    out.textContent = 'Checking…';
    try {
      const r = await api.doctor(fix);
      out.textContent = r.output;
    } catch (err) {
      out.textContent = String((err && err.message) || err);
    }
  }
  $('#doctor-run').addEventListener('click', () => runDoctor(false));
  $('#doctor-fix').addEventListener('click', () => runDoctor(true));

  // ---------------------------------------------------------------- start
  api.info().then((info) => {
    $('#version').textContent = info.version ? `v${info.version}` : '';
    $('#version').title = info.signatures ? `Learned signatures from ${String(info.signatures).slice(0, 10)}` : 'Learned signatures not downloaded yet';
    if (info.platform !== 'desktop') {
      document.body.classList.add('mobile');
      $('#scan-lead').textContent = 'Check files on this phone, for example a zip or apk you downloaded.';
      show('scan');
    } else {
      show('protection');
    }
  });
})();
