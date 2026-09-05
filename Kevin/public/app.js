// AiTM PCAP Detector — Frontend Logic
(function() {
  'use strict';

  // API base - relative path works for same-origin Workers and Pages
  var API_BASE = '';

  // State
  var currentResult = null;

  // DOM elements
  var dropzone = document.getElementById('dropzone');
  var fileInput = document.getElementById('file-input');
  var demoBtn = document.getElementById('demo-btn');
  var newAnalysisBtn = document.getElementById('new-analysis-btn');
  var uploadSection = document.getElementById('upload-section');
  var resultsSection = document.getElementById('results-section');
  var uploadStatus = document.getElementById('upload-status');
  var limitationsLink = document.getElementById('limitations-link');
  var limitationsPopup = document.getElementById('limitations-popup');

  // ===== Theme Toggle =====
  var themeToggle = document.querySelector('[data-theme-toggle]');
  var html = document.documentElement;
  var theme = window.matchMedia('(prefers-color-scheme:dark)').matches ? 'dark' : 'light';
  html.setAttribute('data-theme', theme);

  themeToggle.addEventListener('click', function() {
    theme = theme === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', theme);
    themeToggle.setAttribute('aria-label', 'Switch to ' + (theme === 'dark' ? 'light' : 'dark') + ' mode');
    themeToggle.innerHTML = theme === 'dark'
      ? '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>'
      : '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
  });

  // ===== Tab Switching =====
  var tabs = document.querySelectorAll('.tab');
  tabs.forEach(function(tab) {
    tab.addEventListener('click', function() {
      var target = tab.getAttribute('data-tab');
      tabs.forEach(function(t) { t.classList.remove('active'); });
      document.querySelectorAll('.tab-content').forEach(function(c) { c.classList.remove('active'); });
      tab.classList.add('active');
      var content = document.getElementById('tab-' + target);
      if (content) content.classList.add('active');
    });
  });

  // ===== Upload Handlers =====
  dropzone.addEventListener('click', function() { fileInput.click(); });

  dropzone.addEventListener('dragover', function(e) {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });

  dropzone.addEventListener('dragleave', function() {
    dropzone.classList.remove('dragover');
  });

  dropzone.addEventListener('drop', function(e) {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', function(e) {
    if (e.target.files.length > 0) {
      handleFile(e.target.files[0]);
    }
  });

  demoBtn.addEventListener('click', function() {
    showStatus('loading', 'Loading demo analysis...');
    fetch(API_BASE + '/api/demo')
      .then(function(res) { return res.json(); })
      .then(function(data) {
        if (data.success && data.result) {
          currentResult = data.result;
          renderResults(data.result);
        } else {
          showStatus('error', data.error || 'Failed to load demo');
        }
      })
      .catch(function(err) {
        showStatus('error', 'Connection error: ' + err.message);
      });
  });

  newAnalysisBtn.addEventListener('click', function() {
    uploadSection.classList.remove('hidden');
    resultsSection.classList.add('hidden');
    uploadStatus.classList.add('hidden');
    fileInput.value = '';
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });

  // Limitations popup
  if (limitationsLink) {
    limitationsLink.addEventListener('click', function(e) {
      e.preventDefault();
      limitationsPopup.classList.toggle('hidden');
    });
    document.addEventListener('click', function(e) {
      if (!limitationsPopup.contains(e.target) && e.target !== limitationsLink) {
        limitationsPopup.classList.add('hidden');
      }
    });
  }

  // ===== File Upload =====
  function handleFile(file) {
    var ext = file.name.split('.').pop().toLowerCase();
    if (ext !== 'pcap' && ext !== 'pcapng' && ext !== 'cap') {
      showStatus('error', 'Invalid file type. Please upload a .pcap or .pcapng file.');
      return;
    }

    if (file.size > 100 * 1024 * 1024) {
      showStatus('error', 'File too large. Maximum size is 100MB.');
      return;
    }

    showStatus('loading', 'Uploading and analyzing ' + file.name + '...');

    var formData = new FormData();
    formData.append('pcap', file);

    fetch(API_BASE + '/api/analyze', {
      method: 'POST',
      body: formData
    })
      .then(function(res) { return res.json(); })
      .then(function(data) {
        if (data.success && data.result) {
          currentResult = data.result;
          renderResults(data.result);
        } else {
          showStatus('error', data.error || 'Analysis failed');
        }
      })
      .catch(function(err) {
        showStatus('error', 'Connection error: ' + err.message);
      });
  }

  function showStatus(type, message) {
    uploadStatus.className = 'upload-status ' + type;
    uploadStatus.classList.remove('hidden');
    var icon = type === 'loading' ? '<span class="spinner"></span> ' : '';
    uploadStatus.innerHTML = icon + escapeHtml(message);
  }

  // ===== Render Results =====
  function renderResults(result) {
    uploadSection.classList.add('hidden');
    resultsSection.classList.remove('hidden');

    document.getElementById('filename-display').textContent = result.filename;

    var s = result.summary;

    // Threat score
    var scoreCard = document.getElementById('threat-score-card');
    scoreCard.className = 'summary-card threat-score-card ' + s.threatLevel.toLowerCase();
    document.getElementById('threat-score-value').textContent = s.threatScore;

    var badge = document.getElementById('threat-level-badge');
    badge.textContent = s.threatLevel;
    badge.className = 'summary-badge ' + s.threatLevel.toLowerCase();

    // Findings summary
    document.getElementById('findings-count').textContent = s.findingsCount;
    var breakdown = [];
    if (s.criticalCount) breakdown.push(s.criticalCount + ' critical');
    if (s.highCount) breakdown.push(s.highCount + ' high');
    if (s.mediumCount) breakdown.push(s.mediumCount + ' medium');
    if (s.lowCount) breakdown.push(s.lowCount + ' low');
    document.getElementById('findings-breakdown').textContent = breakdown.join(' · ') || 'no findings';

    // Packets
    document.getElementById('packets-count').textContent = s.totalPackets.toLocaleString();
    document.getElementById('flows-info').textContent = s.tcpFlows + ' TCP · ' + s.udpFlows + ' UDP flows';

    // Domains
    document.getElementById('domains-count').textContent = s.uniqueDomains;
    document.getElementById('domains-info').textContent = s.dnsQueriesCount + ' DNS queries';

    // Render tabs
    renderFindings(result.findings || []);
    renderDomains(result.domains || []);
    renderTLS(result.tlsSessions || []);
    renderHTTP(result.httpFlows || []);
    renderTimeline(result.flowTimeline || []);
    renderIOC(result.iocMetadata || {});

    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  // ===== Render Findings =====
  function renderFindings(findings) {
    var container = document.getElementById('findings-list');
    if (!findings.length) {
      container.innerHTML = '<div class="finding-card"><p class="finding-description">No security findings detected in this capture.</p></div>';
      return;
    }

    container.innerHTML = findings.map(function(f, i) {
      var evidenceHtml = (f.evidence || []).map(function(ev) {
        return '<div class="evidence-row">' +
          '<span class="evidence-field">' + escapeHtml(ev.field) + '</span>' +
          '<span class="evidence-value">' + escapeHtml(ev.value) + '</span>' +
          '</div>' +
          (ev.context ? '<div class="evidence-row"><span class="evidence-field"></span><span class="evidence-context">' + escapeHtml(ev.context) + '</span></div>' : '');
      }).join('');

      return '<div class="finding-card ' + f.severity + '" data-finding="' + i + '">' +
        '<div class="finding-header">' +
          '<div>' +
            '<h3 class="finding-title">' + escapeHtml(f.title) + '</h3>' +
            '<p class="finding-description">' + escapeHtml(f.description) + '</p>' +
          '</div>' +
          '<span class="severity-badge ' + f.severity + '">' + f.severity + '</span>' +
        '</div>' +
        '<div class="finding-details hidden">' +
          '<div class="finding-evidence">' + evidenceHtml + '</div>' +
          (f.mitigation ? '<div class="finding-mitigation"><strong>Mitigation:</strong> ' + escapeHtml(f.mitigation) + '</div>' : '') +
        '</div>' +
      '</div>';
    }).join('');

    // Add click handlers for expand/collapse
    container.querySelectorAll('.finding-card').forEach(function(card) {
      card.addEventListener('click', function() {
        var details = card.querySelector('.finding-details');
        if (details) {
          details.classList.toggle('hidden');
        }
      });
    });
  }

  // ===== Render Domains Table =====
  function renderDomains(domains) {
    var tbody = document.getElementById('domains-table-body');
    if (!domains.length) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--color-text-muted)">No domains found</td></tr>';
      return;
    }

    tbody.innerHTML = domains.map(function(d) {
      return '<tr>' +
        '<td>' + escapeHtml(d.domain) + '</td>' +
        '<td>' + (d.ips || []).map(function(ip) { return escapeHtml(ip); }).join('<br>') + '</td>' +
        '<td>' + d.queryCount + '</td>' +
        '<td>' + (d.brand ? '<span class="tag warning">' + escapeHtml(d.brand) + '</span>' : '—') + '</td>' +
        '<td>' + (d.isLookalike ? '<span class="tag danger">YES</span>' : '<span class="tag success">NO</span>') + '</td>' +
        '<td>' + (d.ttl || '—') + '</td>' +
      '</tr>';
    }).join('');
  }

  // ===== Render TLS Sessions =====
  function renderTLS(sessions) {
    var tbody = document.getElementById('tls-table-body');
    if (!sessions.length) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--color-text-muted)">No TLS sessions found</td></tr>';
      return;
    }

    tbody.innerHTML = sessions.map(function(t) {
      return '<tr>' +
        '<td>' + escapeHtml(t.sni) + '</td>' +
        '<td>' + escapeHtml(t.clientIP || '—') + '</td>' +
        '<td>' + escapeHtml(t.serverIP || '—') + '</td>' +
        '<td>' + (t.serverPort || '—') + '</td>' +
        '<td>' + escapeHtml(t.tlsVersion || '—') + '</td>' +
        '<td>' + escapeHtml(t.alpn || '—') + '</td>' +
        '<td>' + (t.isSuspicious ? '<span class="tag danger">YES</span>' : '<span class="tag neutral">NO</span>') + '</td>' +
      '</tr>';
    }).join('');
  }

  // ===== Render HTTP Flows =====
  function renderHTTP(flows) {
    var tbody = document.getElementById('http-table-body');
    if (!flows.length) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--color-text-muted)">No HTTP flows found</td></tr>';
      return;
    }

    tbody.innerHTML = flows.map(function(h) {
      return '<tr>' +
        '<td><span class="' + (h.method === 'POST' ? 'tag warning' : 'tag neutral') + '">' + escapeHtml(h.method) + '</span></td>' +
        '<td>' + escapeHtml(h.host) + '</td>' +
        '<td>' + escapeHtml(h.path) + '</td>' +
        '<td>' + (h.statusCode || '—') + '</td>' +
        '<td>' + (h.location ? escapeHtml(h.location) : '—') + '</td>' +
        '<td>' + (h.hasSetCookie ? '<span class="tag warning">YES</span>' : '—') + '</td>' +
        '<td>' + (h.isLogin ? '<span class="tag danger">YES</span>' : '—') + '</td>' +
      '</tr>';
    }).join('');
  }

  // ===== Render Timeline =====
  function renderTimeline(timeline) {
    var container = document.getElementById('timeline-list');
    if (!timeline.length) {
      container.innerHTML = '<p style="color:var(--color-text-muted);text-align:center;padding:2rem">No timeline events</p>';
      return;
    }

    container.innerHTML = timeline.map(function(t) {
      var time = t.time ? t.time.replace('T', ' ').replace(/\.\d+Z$/, 'Z').replace('Z', '') : '';
      return '<div class="timeline-item">' +
        '<span class="timeline-time">' + escapeHtml(time) + '</span>' +
        '<span class="timeline-dot ' + (t.severity || 'info') + '"></span>' +
        '<div class="timeline-content">' +
          '<div class="timeline-event">' + escapeHtml(t.event) + '</div>' +
          '<div class="timeline-detail">' + escapeHtml(t.detail) + '</div>' +
        '</div>' +
      '</div>';
    }).join('');
  }

  // ===== Render IOC Summary =====
  function renderIOC(ioc) {
    function renderList(items, formatter) {
      if (!items || !items.length) return '<li class="ioc-empty">No items found</li>';
      return items.map(formatter).join('');
    }

    document.getElementById('ioc-lookalike').innerHTML = renderList(ioc.lookalikeDomains, function(d) {
      return '<li>' + escapeHtml(d) + '</li>';
    });

    document.getElementById('ioc-sni').innerHTML = renderList(ioc.suspiciousSNIs, function(s) {
      return '<li>' + escapeHtml(s) + '</li>';
    });

    document.getElementById('ioc-redirects').innerHTML = renderList(ioc.redirectChains, function(r) {
      return '<li>' + escapeHtml(r) + '</li>';
    });

    document.getElementById('ioc-logins').innerHTML = renderList(ioc.loginPOSTs, function(l) {
      return '<li>' + escapeHtml(l) + '</li>';
    });

    document.getElementById('ioc-matches').innerHTML = renderList(ioc.iocMatches, function(m) {
      return '<li><span class="severity-badge ' + m.severity + '">' + m.severity + '</span>' + escapeHtml(m.value) + ' <span class="evidence-context">(' + escapeHtml(m.type) + ')</span></li>';
    });
  }

  // ===== Utility =====
  function escapeHtml(text) {
    if (text == null) return '';
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(String(text)));
    return div.innerHTML;
  }

})();