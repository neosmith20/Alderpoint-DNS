(function () {
  const appShell = document.querySelector('.app-shell');
  const appNav = document.getElementById('appNav');
  const navToggle = document.querySelector('[data-nav-toggle]');
  const navDismiss = document.querySelector('[data-nav-dismiss]');
  const setNavOpen = (open) => {
    if (!appShell || !navToggle) return;
    appShell.classList.toggle('nav-open', open);
    navToggle.setAttribute('aria-expanded', String(open));
    if (navDismiss) navDismiss.hidden = !open;
  };
  if (appShell && navToggle) {
    navToggle.addEventListener('click', () => {
      setNavOpen(!appShell.classList.contains('nav-open'));
    });
    if (navDismiss) navDismiss.addEventListener('click', () => setNavOpen(false));
    if (appNav) {
      appNav.addEventListener('click', (event) => {
        if (event.target.closest('a') && window.matchMedia('(max-width: 840px)').matches) setNavOpen(false);
      });
    }
    document.addEventListener('click', (event) => {
      if (!appShell.classList.contains('nav-open')) return;
      if (!event.target.closest('#appNav') && !event.target.closest('[data-nav-toggle]')) setNavOpen(false);
    });
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') setNavOpen(false);
    });
  }

  const sidebarCollapseToggle = document.querySelector('[data-sidebar-collapse]');
  if (sidebarCollapseToggle) {
    const SIDEBAR_COLLAPSE_KEY = 'alderpointdnsSidebarCollapsed';
    const setSidebarCollapsed = (collapsed) => {
      document.documentElement.classList.toggle('sidebar-collapsed', collapsed);
      sidebarCollapseToggle.setAttribute('aria-pressed', String(collapsed));
      const label = collapsed ? 'Expand sidebar' : 'Collapse sidebar';
      sidebarCollapseToggle.setAttribute('aria-label', label);
      sidebarCollapseToggle.title = label;
      try {
        window.localStorage.setItem(SIDEBAR_COLLAPSE_KEY, collapsed ? '1' : '0');
      } catch (e) {}
    };
    setSidebarCollapsed(document.documentElement.classList.contains('sidebar-collapsed'));
    sidebarCollapseToggle.addEventListener('click', () => {
      setSidebarCollapsed(!document.documentElement.classList.contains('sidebar-collapsed'));
    });
  }

  // Nav sections (DNS/Security/Operations/System) toggle open/closed on
  // click, independently of one another, and remember their state across
  // ordinary navigation (a full page load, not an SPA) via localStorage --
  // otherwise every click would reset back to whatever the server
  // rendered from the current path alone. A section containing the
  // active page can be collapsed too; it stays visually identifiable via
  // the .is-active styling on the section itself (set from the server
  // regardless of open/closed state), so collapsing it doesn't lose that.
  const NAV_SECTION_KEY_PREFIX = 'alderpointdnsNavSectionOpen:';
  document.querySelectorAll('[data-nav-section-toggle]').forEach((button) => {
    const panel = document.getElementById(button.getAttribute('aria-controls') || '');
    if (!panel) return;
    const section = button.closest('[data-nav-section]');
    const sectionId = section ? section.getAttribute('data-nav-section') : null;
    const storageKey = sectionId ? NAV_SECTION_KEY_PREFIX + sectionId : null;
    const setSectionOpen = (open, persist) => {
      button.setAttribute('aria-expanded', String(open));
      panel.hidden = !open;
      if (section) section.classList.toggle('is-expanded', open);
      if (persist && storageKey) {
        try { window.localStorage.setItem(storageKey, open ? '1' : '0'); } catch (e) {}
      }
    };
    let initialOpen = button.getAttribute('aria-expanded') === 'true';
    if (storageKey) {
      try {
        const stored = window.localStorage.getItem(storageKey);
        if (stored !== null) initialOpen = stored === '1';
      } catch (e) {}
    }
    setSectionOpen(initialOpen, false);
    button.addEventListener('click', () => {
      setSectionOpen(!(button.getAttribute('aria-expanded') === 'true'), true);
    });
  });

  // In the collapsed desktop rail, an opened section renders as a flyout
  // over the page content instead of pushing the nav down; close it when
  // the user clicks elsewhere so it doesn't linger on top of the page.
  document.addEventListener('click', (event) => {
    if (!document.documentElement.classList.contains('sidebar-collapsed')) return;
    document.querySelectorAll('[data-nav-section].is-expanded').forEach((section) => {
      if (section.contains(event.target)) return;
      const toggle = section.querySelector('[data-nav-section-toggle]');
      const panel = toggle && document.getElementById(toggle.getAttribute('aria-controls') || '');
      if (!toggle || !panel || toggle.getAttribute('aria-current') === 'true') return;
      toggle.setAttribute('aria-expanded', 'false');
      panel.hidden = true;
      section.classList.remove('is-expanded');
    });
  });

  const globalStatuses = document.querySelectorAll('.js-global-service-status[data-status-url]');
  if (globalStatuses.length) {
    const refreshStatus = async () => {
      try {
        const response = await fetch(globalStatuses[0].dataset.statusUrl, { headers: { 'X-Requested-With': 'AlderpointDNSStatus' } });
        if (!response.ok) return;
        const data = await response.json();
        const tone = data.tone || 'unavailable';
        globalStatuses.forEach((globalStatus) => {
          const label = globalStatus.querySelector('[data-status-label]');
          const extraClasses = Array.from(globalStatus.classList).filter((name) => !name.startsWith('status-badge--') && name !== 'status-badge');
          globalStatus.className = ['status-badge', `status-badge--${tone}`, ...extraClasses].join(' ');
          globalStatus.title = data.detail || data.label || 'service status';
          if (label) label.textContent = data.label || 'Unknown';
        });
      } catch (_) {
        globalStatuses.forEach((globalStatus) => {
          const label = globalStatus.querySelector('[data-status-label]');
          const extraClasses = Array.from(globalStatus.classList).filter((name) => !name.startsWith('status-badge--') && name !== 'status-badge');
          globalStatus.className = ['status-badge', 'status-badge--unavailable', ...extraClasses].join(' ');
          globalStatus.title = 'service status unavailable';
          if (label) label.textContent = 'Unknown';
        });
      }
    };
    window.setInterval(refreshStatus, 15000);
  }

  const rangeLinks = document.querySelectorAll('[data-range-link]');
  if (rangeLinks.length) {
    const params = new URLSearchParams(window.location.search);
    if (!params.has('range')) {
      const stored = sessionStorage.getItem('alderpointdnsRange');
      const current = document.querySelector('[data-current-range]');
      if (stored && current && current.dataset.currentRange !== stored) {
        params.set('range', stored);
        window.location.search = params.toString();
      }
    }
    rangeLinks.forEach((link) => {
      link.addEventListener('click', () => sessionStorage.setItem('alderpointdnsRange', link.dataset.rangeLink));
    });
  }

  function showToast(message, tone) {
    let toast = document.getElementById('appToast');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'appToast';
      toast.className = 'toast';
      toast.setAttribute('role', 'status');
      document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.dataset.tone = tone || 'success';
    toast.classList.add('toast--visible');
    window.clearTimeout(showToast.timer);
    showToast.timer = window.setTimeout(() => toast.classList.remove('toast--visible'), 3600);
  }

  // Reusable pending-action button state, applied to every form submit
  // across the app (Apply/Add/Delete/Import/Save/Deploy/Restore/Flush/
  // Update/...): disables the submitted button immediately (so rapid
  // double-clicks can't fire a second submission), swaps its label for an
  // in-progress gerund with a spinner, and sets aria-busy -- without
  // requiring every page to wire up its own one-off handler.
  function pendingGerund(label) {
    const trimmed = (label || '').trim();
    if (!trimmed) return 'Working…';
    const words = trimmed.replace(/[.…]+$/, '').split(' ');
    let stem = words[0];
    if (/e$/i.test(stem) && !/[eoy]e$/i.test(stem)) {
      stem = stem.slice(0, -1);
    }
    words[0] = stem + 'ing';
    return words.join(' ') + '…';
  }

  function startPending(button) {
    if (!button || button.dataset.pendingActive === '1') return;
    button.dataset.pendingActive = '1';
    button.dataset.pendingOriginalHtml = button.innerHTML;
    const label = button.dataset.pendingLabel || pendingGerund(button.textContent);
    button.innerHTML = '';
    const spinner = document.createElement('span');
    spinner.className = 'btn-spinner';
    spinner.setAttribute('aria-hidden', 'true');
    const text = document.createElement('span');
    text.textContent = label;
    button.appendChild(spinner);
    button.appendChild(text);
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
  }

  function stopPending(button) {
    if (!button || button.dataset.pendingActive !== '1') return;
    button.innerHTML = button.dataset.pendingOriginalHtml || button.innerHTML;
    delete button.dataset.pendingActive;
    delete button.dataset.pendingOriginalHtml;
    button.disabled = false;
    button.removeAttribute('aria-busy');
  }

  function submitterFor(form, event) {
    return (event && event.submitter) || form.querySelector('button[type="submit"], button:not([type])');
  }

  document.addEventListener('submit', async (event) => {
    const form = event.target.closest('form');
    if (!form) return;
    if (form.dataset.confirm && !window.confirm(form.dataset.confirm)) {
      event.preventDefault();
      return;
    }
    const button = submitterFor(form, event);
    if (!form.matches('[data-async-form]')) {
      // Regular form: let the browser navigate normally (no
      // preventDefault), but still show the pending state immediately so
      // there's visible feedback during the round-trip and the button
      // can't be double-clicked while the new page loads.
      if (button) startPending(button);
      return;
    }
    event.preventDefault();
    if (button) startPending(button);
    try {
      const response = await fetch(form.action, {
        method: form.method || 'POST',
        body: new FormData(form),
        headers: { 'X-Requested-With': 'AlderpointDNSAsyncForm' },
      });
      const text = await response.text();
      const doc = new DOMParser().parseFromString(text, 'text/html');
      const nextMain = doc.querySelector('main');
      const main = document.querySelector('main');
      if (nextMain && main) {
        main.innerHTML = nextMain.innerHTML;
        if (response.url) {
          const url = new URL(response.url);
          if (url.origin === window.location.origin) window.history.replaceState({}, '', url.pathname + url.search);
        }
      }
      const error = doc.querySelector('.alert.error');
      if (error) showToast(error.textContent.trim() || 'Local DNS change failed.', 'error');
      else if (response.ok) showToast(form.dataset.successMessage || 'Saved.', 'success');
      else showToast('Local DNS change failed.', 'error');
    } catch (error) {
      showToast('Local DNS change failed.', 'error');
    } finally {
      // On success/inline-error responses, main.innerHTML was already
      // replaced above with a fresh (non-pending) render, so this is a
      // harmless no-op on the now-detached old button. On a genuine
      // network failure (caught above), the old button is still live in
      // the DOM, so this is what actually restores it.
      if (button) stopPending(button);
    }
  });

  // A page restored from the back/forward cache can still have a button
  // frozen mid-"pending" from just before the user navigated away; reset
  // any such buttons so the page isn't stuck looking like a submission is
  // still in flight.
  window.addEventListener('pageshow', (event) => {
    if (!event.persisted) return;
    document.querySelectorAll('[data-pending-active="1"]').forEach(stopPending);
  });

  // Row-level expandable editors (Local DNS, etc): collapsed by default so
  // records don't render a full edit form for every row; toggled via a
  // delegated listener so it keeps working after data-async-form swaps in
  // new markup.
  document.addEventListener('click', (event) => {
    const toggle = event.target.closest('[data-row-edit-toggle]');
    if (!toggle) return;
    const panel = document.getElementById(toggle.getAttribute('aria-controls') || '');
    if (!panel) return;
    const open = panel.hidden;
    panel.hidden = !open;
    toggle.setAttribute('aria-expanded', String(open));
    toggle.textContent = open ? 'Close' : 'Edit';
  });

  // Button-level confirmation for forms with several submit actions where
  // only one is destructive (Filters bulk actions, etc).
  document.addEventListener('click', (event) => {
    const button = event.target.closest('button[data-confirm]');
    if (!button) return;
    if (!window.confirm(button.dataset.confirm)) event.preventDefault();
  });

  // Header select-all checkbox for bulk-selection tables (Filters, etc).
  document.addEventListener('change', (event) => {
    const master = event.target.closest('input[type="checkbox"][data-check-all]');
    if (!master) return;
    document
      .querySelectorAll(`input[type="checkbox"][data-check-group="${master.dataset.checkAll}"]`)
      .forEach((box) => { box.checked = master.checked; });
  });

  // Compact overflow action menus (DNS Settings, Blocklists, etc).
  function closeOverflowMenus(except) {
    document.querySelectorAll('[data-overflow-menu]').forEach((menu) => {
      if (menu === except) return;
      const trigger = menu.querySelector('[data-overflow-trigger]');
      const panel = menu.querySelector('.overflow-menu__panel');
      if (!trigger || !panel || panel.hidden) return;
      panel.hidden = true;
      trigger.setAttribute('aria-expanded', 'false');
    });
  }
  document.addEventListener('click', (event) => {
    const trigger = event.target.closest('[data-overflow-trigger]');
    if (trigger) {
      const menu = trigger.closest('[data-overflow-menu]');
      const panel = menu && menu.querySelector('.overflow-menu__panel');
      if (!panel) return;
      const open = panel.hidden;
      closeOverflowMenus(open ? menu : null);
      panel.hidden = !open;
      trigger.setAttribute('aria-expanded', String(open));
      return;
    }
    if (!event.target.closest('.overflow-menu__panel')) closeOverflowMenus();
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeOverflowMenus();
  });

  const refreshToggle = document.getElementById('autoRefresh');
  let refreshTimer = null;
  if (refreshToggle) {
    const key = `alderpointdnsAutoRefresh:${window.location.pathname}`;
    const target = document.getElementById(refreshToggle.dataset.refreshTarget || '');
    const refresh = async () => {
      if (!target || !target.dataset.refreshUrl) {
        window.location.reload();
        return;
      }
      const url = new URL(target.dataset.refreshUrl, window.location.origin);
      url.search = window.location.search;
      const response = await fetch(url, { headers: { 'X-Requested-With': 'AlderpointDNSAutoRefresh' } });
      if (response.ok) target.innerHTML = await response.text();
    };
    const schedule = () => {
      if (refreshTimer) clearInterval(refreshTimer);
      refreshTimer = refreshToggle.checked ? setInterval(refresh, 10000) : null;
    };
    refreshToggle.checked = sessionStorage.getItem(key) === '1';
    refreshToggle.addEventListener('change', () => {
      sessionStorage.setItem(key, refreshToggle.checked ? '1' : '0');
      schedule();
      if (refreshToggle.checked) refresh();
    });
    schedule();
  }

  function parseSeries(canvas) {
    try {
      return JSON.parse(canvas.dataset.series || '[]');
    } catch (_) {
      return [];
    }
  }

  function resizeCanvas(canvas) {
    const ratio = window.devicePixelRatio || 1;
    const width = Math.max(280, canvas.clientWidth || 600);
    const height = Math.max(180, canvas.clientHeight || 300);
    canvas.width = Math.floor(width * ratio);
    canvas.height = Math.floor(height * ratio);
    const ctx = canvas.getContext('2d');
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    return { ctx, width, height };
  }

  function niceTime(epoch) {
    const d = new Date(epoch * 1000);
    return d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  }

  function drawSparkline(canvas) {
    const data = parseSeries(canvas);
    const { ctx, width, height } = resizeCanvas(canvas);
    ctx.clearRect(0, 0, width, height);
    if (!data.length) return;
    const max = Math.max(1, ...data);
    ctx.strokeStyle = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() || '#20d6b5';
    ctx.lineWidth = 2;
    ctx.beginPath();
    data.forEach((value, index) => {
      const x = data.length === 1 ? width : index * (width / (data.length - 1));
      const y = height - 3 - ((height - 6) * value / max);
      if (index === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();
  }

  function drawChart(canvas, hoverIndex) {
    const data = parseSeries(canvas);
    const { ctx, width, height } = resizeCanvas(canvas);
    const styles = getComputedStyle(document.documentElement);
    const colors = {
      total: styles.getPropertyValue('--accent-strong').trim() || '#67e8f9',
      blocked: styles.getPropertyValue('--blocked').trim() || '#fb7185',
      allowed: styles.getPropertyValue('--success').trim() || '#36d399',
      grid: styles.getPropertyValue('--border').trim() || '#26384e',
      text: styles.getPropertyValue('--muted').trim() || '#9cafc1',
      panel: styles.getPropertyValue('--panel-elevated').trim() || '#15283e',
    };
    ctx.clearRect(0, 0, width, height);
    const padding = { top: 20, right: 18, bottom: 38, left: 52 };
    const plotW = Math.max(20, width - padding.left - padding.right);
    const plotH = Math.max(20, height - padding.top - padding.bottom);
    ctx.font = '12px system-ui, sans-serif';
    ctx.textBaseline = 'middle';

    if (!data.length) {
      ctx.fillStyle = colors.text;
      ctx.fillText('No analytics data collected yet', padding.left, height / 2);
      return;
    }

    const enabled = (canvas.dataset.enabledSeries || 'total,blocked').split(',');
    const max = Math.max(1, ...data.map((d) => Math.max(...enabled.map((key) => Number(d[key] || 0)))));
    for (let i = 0; i <= 4; i += 1) {
      const y = padding.top + (plotH * i / 4);
      const value = Math.round(max - (max * i / 4));
      ctx.strokeStyle = colors.grid;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(padding.left, y);
      ctx.lineTo(width - padding.right, y);
      ctx.stroke();
      ctx.fillStyle = colors.text;
      ctx.textAlign = 'right';
      ctx.fillText(String(value), padding.left - 9, y);
    }

    function point(index, key) {
      const x = padding.left + (data.length === 1 ? plotW : plotW * index / (data.length - 1));
      const y = padding.top + plotH - (plotH * Number(data[index][key] || 0) / max);
      return { x, y };
    }

    enabled.forEach((key) => {
      ctx.strokeStyle = colors[key] || colors.total;
      ctx.lineWidth = key === 'blocked' ? 2.4 : 2;
      ctx.beginPath();
      data.forEach((_, index) => {
        const p = point(index, key);
        if (index === 0) ctx.moveTo(p.x, p.y);
        else ctx.lineTo(p.x, p.y);
      });
      ctx.stroke();
    });

    ctx.fillStyle = colors.text;
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    const labels = [0, Math.floor((data.length - 1) / 2), data.length - 1].filter((v, i, a) => a.indexOf(v) === i);
    labels.forEach((index) => {
      const p = point(index, enabled[0]);
      ctx.fillText(niceTime(data[index].t), Math.min(width - 130, Math.max(6, p.x - 48)), height - 28);
    });

    if (hoverIndex !== undefined && data[hoverIndex]) {
      const x = point(hoverIndex, enabled[0]).x;
      ctx.strokeStyle = 'rgba(255,255,255,0.35)';
      ctx.beginPath();
      ctx.moveTo(x, padding.top);
      ctx.lineTo(x, padding.top + plotH);
      ctx.stroke();
      const boxW = 188;
      const boxH = 76;
      const boxX = Math.min(width - boxW - 8, Math.max(8, x + 12));
      const boxY = padding.top + 8;
      ctx.fillStyle = colors.panel;
      ctx.strokeStyle = colors.grid;
      ctx.beginPath();
      ctx.roundRect(boxX, boxY, boxW, boxH, 10);
      ctx.fill();
      ctx.stroke();
      ctx.fillStyle = '#ecf4fb';
      ctx.textAlign = 'left';
      ctx.textBaseline = 'top';
      ctx.fillText(niceTime(data[hoverIndex].t), boxX + 10, boxY + 10);
      ctx.fillStyle = colors.total;
      ctx.fillText(`Total: ${data[hoverIndex].total || 0}`, boxX + 10, boxY + 31);
      ctx.fillStyle = colors.blocked;
      ctx.fillText(`Blocked: ${data[hoverIndex].blocked || 0}`, boxX + 10, boxY + 52);
    }
  }

  function setupChart(canvas) {
    let hoverIndex;
    const render = () => drawChart(canvas, hoverIndex);
    canvas.addEventListener('mousemove', (event) => {
      const data = parseSeries(canvas);
      if (!data.length) return;
      const rect = canvas.getBoundingClientRect();
      const x = event.clientX - rect.left;
      const plotStart = 52;
      const plotEnd = rect.width - 18;
      const ratio = Math.min(1, Math.max(0, (x - plotStart) / Math.max(1, plotEnd - plotStart)));
      hoverIndex = Math.round(ratio * (data.length - 1));
      render();
    });
    canvas.addEventListener('mouseleave', () => {
      hoverIndex = undefined;
      render();
    });
    render();
    window.addEventListener('resize', render);
  }

  document.querySelectorAll('canvas.sparkline').forEach((canvas) => {
    drawSparkline(canvas);
    window.addEventListener('resize', () => drawSparkline(canvas));
  });
  document.querySelectorAll('canvas[data-chart="traffic"]').forEach(setupChart);

  // Accessible show/hide toggle for password fields (setup, administration
  // password change). Each toggle button lives inside a .password-field
  // wrapper alongside the input it controls.
  document.querySelectorAll('[data-password-toggle]').forEach((button) => {
    button.addEventListener('click', () => {
      const wrapper = button.closest('.password-field');
      const input = wrapper && wrapper.querySelector('[data-password-input]');
      if (!input) return;
      const showing = input.type === 'text';
      input.type = showing ? 'password' : 'text';
      button.textContent = showing ? 'Show' : 'Hide';
      button.setAttribute('aria-pressed', String(!showing));
      button.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
    });
  });

  // Client-side password-confirmation check for forms carrying
  // data-password-match (setup, administration change-password): mirrors
  // the server-side check so a mismatch is caught before submission, using
  // the browser's native validation UI. The server always re-validates
  // regardless -- this is a usability improvement, not the source of truth.
  document.querySelectorAll('form[data-password-match]').forEach((form) => {
    const password = form.querySelector('[name="password"], [name="new_password"]');
    const confirm = form.querySelector('[name="confirm_password"], [name="confirm_new_password"]');
    if (!password || !confirm) return;
    const check = () => {
      confirm.setCustomValidity(confirm.value !== password.value ? 'Passwords do not match.' : '');
    };
    password.addEventListener('input', check);
    confirm.addEventListener('input', check);
    form.addEventListener('submit', (event) => {
      check();
      if (!confirm.checkValidity()) {
        event.preventDefault();
        confirm.reportValidity();
      }
    });
  });
}());
