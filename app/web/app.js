/* ============================================================
   银狐进程监视器 · 前端逻辑（零依赖）
   ============================================================ */
'use strict';

const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));

const LEVEL_ZH = { critical: '严重', high: '高危', medium: '中危', low: '低危', clean: '正常' };
const LEVEL_ORDER = { critical: 4, high: 3, medium: 2, low: 1, clean: 0 };
const KIND_ZH = {
  task: '计划任务', service: '系统服务', driver: '内核驱动',
  hosts: 'hosts', registry: '注册表', file: '文件特征',
};

let STATE = null;
let SORT = { key: 'score', dir: -1 };
let FILTER = { q: '', level: 'all', onlyConn: false };
let ART_FILTER = 'all';
let RULES_LOADED = false;
let openArt = new Set();

/* 会话令牌：由服务端注入到 <meta>，POST 必须携带。
   作用是把跨域伪造请求挡在门外（自定义头会强制浏览器预检，跨域预检必然失败）。 */
const TOKEN = (document.querySelector('meta[name="yinhu-token"]') || {}).content || '';

/** 统一的 POST 封装 —— 所有写操作都必须走这里，确保带上令牌与正确的 Content-Type */
async function api(path, payload) {
  const r = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Yinhu-Token': TOKEN },
    body: JSON.stringify(payload || {}),
  });
  try {
    return await r.json();
  } catch (e) {
    return { ok: false, msg: `请求被拒绝（HTTP ${r.status}）` };
  }
}

/* ---------------------------------------------------- 工具 */
function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function fmtUptime(sec) {
  sec = Math.max(0, Math.floor(sec || 0));
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
  const p = (n) => String(n).padStart(2, '0');
  return h > 0 ? `${p(h)}:${p(m)}:${p(s)}` : `${p(m)}:${p(s)}`;
}
function toast(msg, kind = '') {
  const el = document.createElement('div');
  el.className = 'toast ' + kind;
  el.textContent = msg;
  $('#toasts').appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity .3s'; }, 3400);
  setTimeout(() => el.remove(), 3800);
}
function sigView(p) {
  const s = p.signature;
  if (!s) return { cls: 'none', mark: '…', txt: '校验中', cn: '' };
  if (s.kind === 'ok') return { cls: 'ok', mark: '✓', txt: '签名有效', cn: s.cn || s.signer || '' };
  if (s.kind === 'forged') return { cls: 'bad', mark: '⚠', txt: '签名伪造', cn: s.cn || '' };
  if (s.kind === 'untrusted') return { cls: 'warn', mark: '⚠', txt: '根证书不受信任', cn: s.cn || '' };
  if (s.kind === 'noimage') return { cls: 'none', mark: '·', txt: '无镜像文件', cn: '系统伪进程或 VBS 隔离组件，没有对应的可执行文件' };
  if (s.kind === 'packaged') return { cls: 'none', mark: '□', txt: 'MSIX 包签名', cn: '由应用包整体签名保护，不单独签名' };
  if (s.kind === 'unsigned') return { cls: 'none', mark: '—', txt: '未签名', cn: '' };
  return { cls: 'none', mark: '?', txt: s.status_zh || '校验失败', cn: s.cn || '' };
}

/* ---------------------------------------------------- 轮询 */
async function poll() {
  try {
    const r = await fetch('/api/state');
    STATE = await r.json();
    render();
  } catch (e) {
    $('#pillStatus').className = 'pill bad';
    $('#pillStatus').innerHTML = '<i class="dot"></i><span>连接中断</span>';
  }
}

/* ---------------------------------------------------- 渲染 */
function render() {
  const s = STATE.summary;
  const L = s.levels;

  /* 顶栏状态 */
  const integ = (STATE.security || {}).integrity || {};
  const busy = s.artifact_busy || s.sig_busy || s.scan_count === 0;
  const pill = $('#pillStatus');
  if (integ.status === 'changed' || integ.status === 'baseline_lost') {
    pill.className = 'pill bad';
    pill.innerHTML = '<i class="dot"></i><span>⚠ 程序文件已被改动</span>';
  } else if (s.scan_count === 0) {
    pill.className = 'pill busy';
    pill.innerHTML = '<i class="dot"></i><span>首次扫描中…</span>';
  } else if (busy) {
    pill.className = 'pill busy';
    pill.innerHTML = '<i class="dot"></i><span>扫描中…</span>';
  } else if (L.critical > 0) {
    pill.className = 'pill bad';
    pill.innerHTML = `<i class="dot"></i><span>发现 ${L.critical} 个严重进程</span>`;
  } else if (L.high > 0) {
    pill.className = 'pill warn';
    pill.innerHTML = `<i class="dot"></i><span>${L.high} 个高危进程待核查</span>`;
  } else {
    pill.className = 'pill';
    pill.innerHTML = '<i class="dot"></i><span>监控中 · 未见异常</span>';
  }

  const pa = $('#pillAdmin');
  pa.className = 'pill ' + (s.admin ? '' : 'warn');
  pa.innerHTML = s.admin
    ? '<i class="dot"></i><span>管理员权限</span>'
    : '<i class="dot"></i><span>普通权限 · 部分检测受限</span>';
  pa.title = s.admin ? '已获得完整检测能力'
    : '建议右键以管理员身份运行，才能读取 Defender 排除项与受保护进程信息';

  $('#pillUptime').innerHTML = `<span>运行 ${fmtUptime(s.uptime)}</span>`;

  /* KPI */
  const netSum = (STATE.net || {}).summary || {};
  const netLv = netSum.levels || {};
  const kpi = [
    ['', s.total, '进程总数', `扫描耗时 ${s.scan_ms} ms · 第 ${s.scan_count} 轮`],
    ['crit', L.critical, '严重风险进程', '疑似银狐本体或注入载体'],
    ['high', L.high, '高危进程', '需人工核查'],
    ['med', L.medium, '中危 / 可疑', '未签名外联、随机命名等'],
    ['', s.artifact_findings, '系统制品异常', `任务 ${s.tasks} · 服务 ${s.services} · 驱动 ${s.drivers}`],
    ['ok', s.connections, '网络连接', s.sig_pending > 0 ? `签名待校验 ${s.sig_pending}` : '签名库已就绪'],
  ];
  if (STATE.net) {
    const regN = (netSum.high_reg || 0) + (netSum.regular || 0) - (netSum.high_reg || 0);
    const badN = (netLv.critical || 0) + (netLv.high || 0);
    kpi.push([badN > 0 ? 'crit' : (regN > 0 ? 'med' : 'ok'), netSum.high_reg || 0,
      '高规律性外联',
      badN > 0 ? `其中 ${badN} 个已判可疑` : `规律性 ≥70 共 ${regN} 个`]);
  }
  $('#kpis').innerHTML = kpi.map(([cls, v, label, sub]) => `
    <div class="kpi ${cls}">
      <b>${esc(v)}</b><span>${esc(label)}</span><i>${esc(sub)}</i>
    </div>`).join('');

  /* Tab 计数 */
  const risky = STATE.processes.filter((p) => LEVEL_ORDER[p.level] >= 3).length;
  $('#tabProcCount').textContent = risky;
  $('#tabProcCount').className = L.critical > 0 ? 'crit' : (L.high > 0 ? 'high' : '');
  $('#tabArtCount').textContent = s.artifact_findings;
  $('#tabArtCount').className = s.artifact_levels.critical > 0 ? 'crit'
    : (s.artifact_levels.high > 0 ? 'high' : '');
  $('#tabAlertCount').textContent = STATE.alerts.length;
  if (STATE.net) {
    const focusN = (STATE.net.flows || []).filter(netIsFocus).length;
    const netBad = (netLv.critical || 0) + (netLv.high || 0);
    $('#tabNetCount').textContent = focusN;
    $('#tabNetCount').className = netBad > 0 ? 'crit'
      : ((netSum.high_reg || 0) > 0 ? 'high' : '');
  }

  renderProcTable();
  renderNet();
  renderArtifacts();
  renderAlerts();
  renderSecurity();
  if (!RULES_LOADED) loadRules();
}

/* ---------------------------- 进程表 */
function renderProcTable() {
  if (!STATE) return;
  let list = STATE.processes.slice();

  if (FILTER.level === 'risky') list = list.filter((p) => LEVEL_ORDER[p.level] >= 2);
  else if (FILTER.level !== 'all') list = list.filter((p) => p.level === FILTER.level);
  if (FILTER.onlyConn) list = list.filter((p) => (p.connections || []).length > 0);

  const q = FILTER.q.trim().toLowerCase();
  if (q) {
    list = list.filter((p) =>
      (p.name || '').toLowerCase().includes(q) ||
      (p.exe || '').toLowerCase().includes(q) ||
      (p.cmdline_str || '').toLowerCase().includes(q) ||
      String(p.pid).includes(q));
  }

  const k = SORT.key, d = SORT.dir;
  list.sort((a, b) => {
    let va, vb;
    if (k === 'score') { va = a.score; vb = b.score; }
    else if (k === 'pid') { va = a.pid; vb = b.pid; }
    else if (k === 'name') { va = (a.name || '').toLowerCase(); vb = (b.name || '').toLowerCase(); }
    else if (k === 'exe') { va = (a.exe || '').toLowerCase(); vb = (b.exe || '').toLowerCase(); }
    else if (k === 'sig') { va = (a.signature || {}).kind || ''; vb = (b.signature || {}).kind || ''; }
    else if (k === 'conn') { va = (a.connections || []).length; vb = (b.connections || []).length; }
    else { va = a.score; vb = b.score; }
    if (va < vb) return -1 * d;
    if (va > vb) return 1 * d;
    return (a.name || '').localeCompare(b.name || '');
  });

  $('#procInfo').textContent = `${list.length} / ${STATE.processes.length} 项`;

  const rows = list.map((p) => {
    const sv = sigView(p);
    const hits = (p.findings || []).slice(0, 3).map((f) =>
      `<span class="hit ${f.severity}" title="${esc(f.evidence)}">${esc(f.title)}</span>`).join('');
    const more = (p.findings || []).length > 3
      ? `<span class="hit">+${p.findings.length - 3}</span>` : '';
    const nc = (p.connections || []).length;
    return `<tr class="${p.level}" data-pid="${p.pid}">
      <td><span class="badge ${p.level}">${LEVEL_ZH[p.level]}</span>
          <span class="score ${p.level}">${p.score}</span></td>
      <td><span class="cname">${esc(p.name)}<small>${esc(p.username || '')}</small></span></td>
      <td class="mono">${p.pid}</td>
      <td><div class="pth" title="${esc(p.exe)}">${esc(p.exe || '（无法读取路径）')}</div></td>
      <td><span class="sig ${sv.cls}">${sv.mark} ${esc(sv.txt)}${sv.cn ? `<small title="${esc(sv.cn)}">${esc(sv.cn)}</small>` : ''}</span></td>
      <td>${nc ? `<span class="netdot"></span> <span class="mono">${nc}</span>` : '<span class="netdot none"></span>'}</td>
      <td><div class="hits">${hits}${more}</div></td>
    </tr>`;
  }).join('');

  $('#procBody').innerHTML = rows ||
    `<tr><td colspan="7" style="text-align:center;padding:34px;color:var(--dim)">
       没有符合条件的进程</td></tr>`;
}

/* ============================================================
   网络监控 —— 心跳规律性
   ------------------------------------------------------------
   界面上刻意把「规律性」与「风险」做成两个独立维度：
     · 规律性 = 纯时序指标（事件间隔的变异系数换算），回答"有多像机器在打拍子"；
     · 风险   = 规则判定结果。
   软件更新检查、遥测上报同样很规律，所以规律性高不等于恶意 ——
   把两者分开显示，用户既能看到"最规律的外联是哪些"，又不会被假告警淹没。
   ============================================================ */
const NET = {
  filter: 'focus',
  q: '',
  onlyBytes: false,
  sort: { key: 'score', dir: -1 },
  touched: false,
  ticksFor: '',
  timer: null,
};

const C = {
  crit: '#ff5c5c', high: '#ffa53d', med: '#ffd666', low: '#63b3ff',
  ok: '#3fb950', accent: '#60a5fa', dim: '#5d6f88', cyan: '#22d3ee', gold: '#ffc53d',
};

function regClass(reg) {
  if (reg == null) return 'none';
  if (reg >= 85) return 'r85';
  if (reg >= 70) return 'r70';
  if (reg >= 55) return 'r55';
  return 'r0';
}
function regText(reg) { return reg == null ? '—' : String(Math.round(reg)); }

function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
  return (n / 1073741824).toFixed(2) + ' GB';
}
function fmtPeriod(sec) {
  if (sec == null) return '—';
  sec = Number(sec);
  if (sec < 90) return sec.toFixed(1) + ' 秒';
  if (sec < 3600) return (sec / 60).toFixed(1) + ' 分钟';
  return (sec / 3600).toFixed(1) + ' 小时';
}
function durLabel(sec) {
  sec = Number(sec) || 0;
  if (sec < 60) return sec + ' 秒';
  return (sec / 60) + ' 分钟';
}
function durHint(sec) {
  const p = Math.max(2, Math.round((Number(sec) || 0) / 4));
  return `最长可识别约 ${p} 秒周期的心跳（需 ≥3 个完整间隔）`;
}
function clockOf(sec) {
  sec = Math.max(0, Math.floor(sec || 0));
  const m = Math.floor(sec / 60), s = sec % 60;
  return String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0');
}

/** 事件直方图：心跳在图上表现为等间距尖峰，是最直观的证据 */
function bucketSvg(arr, color) {
  const n = arr.length || 1;
  const max = Math.max(1, ...arr);
  const w = 620, h = 78, bw = w / n;
  let bars = '';
  for (let i = 0; i < n; i++) {
    if (!arr[i]) continue;
    const bh = Math.max(2, (arr[i] / max) * (h - 6));
    bars += `<rect x="${(i * bw).toFixed(2)}" y="${(h - bh).toFixed(2)}"`
      + ` width="${Math.max(1, bw - 1.4).toFixed(2)}" height="${bh.toFixed(2)}"`
      + ` rx="1" fill="${color}"/>`;
  }
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">${bars}</svg>`;
}

/** 间隔序列图：虚线是平均值，柱子越齐 → 规律性越高 */
function intervalSvg(vals, mean) {
  const n = vals.length || 1;
  const max = Math.max(0.001, ...vals, Number(mean) || 0);
  const w = 620, h = 96, pad = 20;
  const bw = (w - 4) / n;
  let bars = '';
  vals.forEach((v, i) => {
    const bh = (v / max) * (h - pad - 8);
    bars += `<rect x="${(2 + i * bw).toFixed(2)}" y="${(h - pad - bh).toFixed(2)}"`
      + ` width="${Math.max(1, bw - 1.8).toFixed(2)}" height="${bh.toFixed(2)}"`
      + ` rx="1" fill="${C.accent}" opacity=".85"/>`;
  });
  const my = h - pad - ((Number(mean) || 0) / max) * (h - pad - 8);
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
    ${bars}
    <line x1="2" y1="${my.toFixed(2)}" x2="${w - 2}" y2="${my.toFixed(2)}"
      stroke="${C.med}" stroke-width="1.2" stroke-dasharray="5 4"/>
    <text x="${w - 3}" y="${Math.max(11, my - 4).toFixed(2)}" text-anchor="end"
      fill="${C.med}" font-size="11">平均 ${esc(fmtPeriod(mean))}</text>
  </svg>`;
}

function netIsFocus(f) {
  return (f.regularity != null && f.regularity >= 55) || f.score >= 30;
}

function renderNet() {
  const net = STATE && STATE.net;
  const pane = $('#pane-net');
  if (!net) {
    $('#netBody').innerHTML = '';
    $('#netEmpty').classList.add('show');
    $('#netEmptyWhy').textContent = '本次启动未启用网络检测（使用了 --no-net 参数）。';
    $('#netProgMeta').textContent = '网络检测未启用';
    return;
  }
  renderNetControl(net);
  renderNetTable(net);
  renderNetNotes(net);
}

function renderNetControl(net) {
  const stops = net.duration_stops || [30, 60, 120, 180, 300, 600, 900];
  const sl = $('#netSlider');
  const ses = net.session || {};

  const key = stops.join(',');
  if (NET.ticksFor !== key) {
    NET.ticksFor = key;
    sl.max = String(stops.length - 1);
    $('#netTicks').innerHTML = stops.map((s, i) =>
      `<span data-i="${i}">${esc(durLabel(s))}</span>`).join('');
  }

  if (!NET.touched) {
    const want = ses.duration || net.default_duration || stops[2];
    let idx = 0, best = Infinity;
    stops.forEach((v, i) => { const dd = Math.abs(v - want); if (dd < best) { best = dd; idx = i; } });
    sl.value = String(idx);
    $('#netDurVal').textContent = durLabel(stops[idx]);
    $('#netDurHint').textContent = durHint(stops[idx]);
  }
  // 轨道填充 + 当前档位高亮（跟随滑块实际位置，用户拖动时也即时更新）
  const idxNow = Number(sl.value) || 0;
  sl.style.setProperty('--fill', (stops.length > 1 ? (idxNow / (stops.length - 1)) * 100 : 0) + '%');
  $$('#netTicks span').forEach((sp, i) => sp.classList.toggle('on', i === idxNow));

  const p = Math.round((ses.progress || 0) * 100);
  $('#netBar').style.width = p + '%';
  $('#netBar').className = ses.phase === 'done' ? 'done' : '';

  const st = net.summary || {};
  const lv = st.levels || {};
  const phaseTxt = ses.phase === 'collecting'
    ? `<b class="live">采集中</b>` : `<b class="fin">本轮已完成</b>`;
  $('#netProgMeta').innerHTML =
    `${phaseTxt} · 已观测 ${clockOf(ses.elapsed)} / ${clockOf(ses.duration)}` +
    `（${p}%） · 活动连接 ${net.live_conns} 条 · 流量条目 ${st.flows || 0} 个 · ` +
    `可评估规律性 ${st.evaluated || 0} 个` +
    (st.high_reg ? ` · <b class="hl">规律性 ≥85 的 ${st.high_reg} 个</b>` : '') +
    ((lv.critical || lv.high) ? ` · <b class="hl">可疑 ${(lv.critical || 0) + (lv.high || 0)} 个</b>` : '') +
    ` · 采样 ${net.sample_interval} 秒/次（${net.sample_ms} ms）` +
    ` · 字节统计 ${net.estats ? '可用' : '不可用'}`;

  $('#netStart').disabled = false;
  $('#netStop').disabled = ses.phase !== 'collecting';
}

function renderNetTable(net) {
  let list = (net.flows || []).slice();

  if (NET.filter === 'focus') list = list.filter(netIsFocus);
  else if (NET.filter === 'regular') list = list.filter((f) => f.regularity != null && f.regularity >= 70);
  else if (NET.filter === 'risky') list = list.filter((f) => f.score >= 30);
  if (NET.onlyBytes) list = list.filter((f) => (f.bytes_out + f.bytes_in) > 0);

  const q = NET.q.trim().toLowerCase();
  if (q) {
    list = list.filter((f) =>
      (f.name || '').toLowerCase().includes(q) ||
      (f.exe || '').toLowerCase().includes(q) ||
      (f.rip || '').toLowerCase().includes(q) ||
      String(f.rport).includes(q) ||
      String(f.pid).includes(q));
  }

  const k = NET.sort.key, d = NET.sort.dir;
  list.sort((a, b) => {
    let va, vb;
    if (k === 'regularity') { va = a.regularity == null ? -1 : a.regularity; vb = b.regularity == null ? -1 : b.regularity; }
    else if (k === 'name') { va = (a.name || '').toLowerCase(); vb = (b.name || '').toLowerCase(); }
    else if (k === 'rip') { va = (a.rip || '') + ':' + a.rport; vb = (b.rip || '') + ':' + b.rport; }
    else if (k === 'bytes') { va = a.bytes_out + a.bytes_in; vb = b.bytes_out + b.bytes_in; }
    else if (k === 'events') { va = a.conn_events + a.byte_events; vb = b.conn_events + b.byte_events; }
    else { va = a.score; vb = b.score; }
    if (va < vb) return -1 * d;
    if (va > vb) return 1 * d;
    return (a.name || '').localeCompare(b.name || '');
  });

  $('#netInfo').textContent = `${list.length} / ${(net.flows || []).length} 项`;
  $('#netEmpty').classList.toggle('show', list.length === 0);
  if (!list.length) {
    $('#netEmptyWhy').textContent = (net.flows || []).length
      ? '当前筛选条件下没有匹配项 —— 试试切到「全部」。'
      : '观测期间未捕获到任何外联流量。';
  }

  $('#netBody').innerHTML = list.map((f) => {
    const rc = regClass(f.regularity);
    const chips = (f.findings || []).slice(0, 3).map((x) =>
      `<span class="hit ${x.severity}" title="${esc(x.evidence)}">${esc(x.title)}</span>`).join('');
    const tags = [
      `<span class="tag">${esc(f.ip_scope_zh)}</span>`,
      `<span class="tag">${esc((f.proto || '').toUpperCase())}</span>`,
    ];
    if (f.ioc_ip) tags.push('<span class="tag bad">命中 IOC</span>');
    if (f.port_class === 'silverfox') tags.push('<span class="tag bad">银狐端口</span>');
    if (f.proc_untrusted) tags.push('<span class="tag warn">进程未签名</span>');
    if (f.resolution_limited) tags.push('<span class="tag dim">精度受限</span>');

    const sub = [];
    if (f.regularity_source) sub.push(esc(f.regularity_source));
    if (f.avg_interval != null) sub.push(`周期 ${esc(fmtPeriod(f.avg_interval))}`);
    if (f.jitter_pct != null) sub.push(`抖动 ${esc(String(f.jitter_pct))}%`);

    return `<tr class="${f.level} netrow${f.regularity != null && f.regularity >= 85 ? ' reg-hi' : ''}"
        data-nkey="${esc(f.key)}">
      <td><span class="badge ${f.level}">${LEVEL_ZH[f.level]}</span>
          <span class="score ${f.level}">${Math.round(f.score)}</span></td>
      <td>
        <div class="regcell ${rc}">
          <div class="regbar"><i style="width:${f.regularity == null ? 0 : f.regularity}%"></i></div>
          <span class="regnum">${regText(f.regularity)}</span>
        </div>
        <div class="regsub">${sub.join(' · ') || (f.note ? esc(f.note) : '样本不足')}</div>
      </td>
      <td><span class="cname">${esc(f.name)}<small>PID ${f.pid} · ${esc(f.signature_zh)}</small></span></td>
      <td>
        <div class="remote mono">${esc(f.rip)}:${f.rport}</div>
        <div class="rsub">${tags.join('')}</div>
      </td>
      <td>
        <div class="mono bytes">↑${esc(fmtBytes(f.bytes_out))} ↓${esc(fmtBytes(f.bytes_in))}</div>
        <div class="rsub">连接 ${f.live_conns} 条 · 建立事件 ${f.conn_events} · 数据事件 ${f.byte_events}</div>
      </td>
      <td>
        <div class="hits">${chips || '<span class="hit none">未命中规则</span>'}</div>
        <div class="verdict">${esc(f.verdict)}</div>
      </td>
    </tr>`;
  }).join('');
}

function renderNetNotes(net) {
  const hist = (net.history || [])[0];
  const notes = [];
  notes.push(`<b>判定方法</b>：<b>规律性</b>由事件间隔的变异系数换算（0–100，越大越像机器打拍子）；`
    + `<b>风险</b>由规则判定。软件更新检查、遥测上报同样具有周期性，`
    + `因此规律性高<b>不等于</b>恶意 —— 只有与可疑进程或可疑目标共振时才会升级为告警。`);
  notes.push(`<b>两条证据流</b>：① 连接建立间隔 —— 覆盖"连上→发数据→断开→再连"型心跳；`
    + `② 数据突发间隔 —— 覆盖<b>长连接上的心跳</b>（靠 TCP 每连接字节计数器识别，`
    + `不抓包、不解密）。`);
  if (!net.estats) {
    notes.push(`<span class="warn">⚠ 字节统计不可用</span>：${esc(net.estats_note || '')}。`
      + `本次仅依据连接建立事件判定，<b>长连接型心跳可能漏检</b>；建议以管理员身份运行。`);
  }
  if (hist) {
    notes.push(`<b>上一轮</b>：${esc(hist.started_at)} 起观测 ${esc(durLabel(hist.duration))}，`
      + `流量条目 ${hist.flows} 个，规律性 ≥70 的 ${hist.regular} 个，`
      + `严重 ${hist.critical} / 高危 ${hist.high}。`);
  }
  notes.push(`<b>观测边界</b>：采样周期 ${net.sample_interval} 秒 —— 短于该周期的行为会混叠；`
    + `只读本机连接表与 TCP 统计计数器，<b>不发起任何网络请求</b>（无 DNS 解析）；`
    + `UDP 无远端信息，不参与规律性判定。`);
  $('#netNotes').innerHTML = notes.map((n) => `<div class="netnote">${n}</div>`).join('');
}

/* ---------------------------- 网络详情 ---------------------------- */
async function openNetDetail(key) {
  $('#drawer').classList.add('show');
  $('#mask').classList.add('show');
  $('#dName').textContent = '加载中…';
  $('#dSub').textContent = '';
  $('#dBody').innerHTML = '<div style="color:var(--dim);padding:22px 0">正在读取网络流量详情…</div>';
  let d;
  try {
    d = await fetch('/api/net/flow?key=' + encodeURIComponent(key)).then((r) => r.json());
  } catch (e) {
    $('#dBody').innerHTML = '<div style="color:var(--crit)">读取失败</div>';
    return;
  }
  if (d.error) {
    $('#dName').textContent = d.error;
    $('#dBody').innerHTML = '';
    return;
  }
  renderNetDetail(d);
}

function renderNetDetail(d) {
  $('#dName').textContent = `${d.name} → ${d.rip}:${d.rport}`;
  $('#dSub').textContent = d.exe || `PID ${d.pid}`;

  const rc = regClass(d.regularity);
  const findHtml = (d.findings || []).map((f) => `
    <div class="dfind ${f.severity}">
      <div class="ft"><span class="badge ${f.severity}">${f.severity_zh}</span>
        [${esc(f.rule_id)}] ${esc(f.title)}</div>
      <div class="ev">${esc(f.evidence)}</div>
      ${f.advice ? `<div class="ad">${esc(f.advice)}</div>` : ''}
    </div>`).join('') || '<div style="color:var(--ok);font-size:12.5px">未命中任何网络规则</div>';

  const cs = d.conn_series, bs = d.byte_series, bk = d.buckets;
  const connBlock = cs
    ? `<div class="dsec"><h4>连接建立间隔（${cs.n} 个间隔，来自 ${cs.events} 次连接建立）</h4>
        ${intervalSvg(cs.intervals, cs.mean)}
        <div class="kvline">平均 ${esc(fmtPeriod(cs.mean))} · 中位 ${esc(fmtPeriod(cs.median))} ·
          抖动 ${esc(String(cs.jitter_pct))}% · 变异系数 ${esc(String(cs.cv))} ·
          极差 ${esc(fmtPeriod(cs.min))} ~ ${esc(fmtPeriod(cs.max))} ·
          规律性 <b>${esc(String(cs.regularity))}</b></div>
       </div>`
    : `<div class="dsec"><h4>连接建立间隔</h4>
        <div class="kvline dim">观测到的连接建立次数不足，无法给出间隔统计。</div></div>`;

  const byteBlock = bs
    ? `<div class="dsec"><h4>数据突发间隔（${bs.n} 个间隔，来自 ${bs.events} 次数据突发）</h4>
        ${intervalSvg(bs.intervals, bs.mean)}
        <div class="kvline">平均 ${esc(fmtPeriod(bs.mean))} · 抖动 ${esc(String(bs.jitter_pct))}% ·
          变异系数 ${esc(String(bs.cv))} · 规律性 <b>${esc(String(bs.regularity))}</b></div>
        ${d.byte_amounts && d.byte_amounts.length ? `
        <div class="kvline">每次突发的字节量（前 24 次）：
          <span class="mono">${d.byte_amounts.slice(0, 24).map((x) => esc(fmtBytes(x))).join('、')}</span></div>` : ''}
       </div>`
    : `<div class="dsec"><h4>数据突发间隔</h4>
        <div class="kvline dim">${d.byte_events ? '数据事件过少，样本不足以判断周期。'
          : '该连接期间没有观测到数据传输（或字节统计不可用）。'}</div></div>`;

  const bucketBlock = bk ? `
    <div class="dsec">
      <h4>周期性直方图（每格 ${esc(String(bk.width))} 秒）</h4>
      <div class="sparklabel">数据字节量</div>
      ${bucketSvg(bk.bytes, C.accent)}
      <div class="sparklabel">连接建立次数</div>
      ${bucketSvg(bk.conns, C.cyan)}
      <div class="kvline dim">心跳在图上表现为<b>等间距的尖峰</b>；
        若尖峰间距均匀、高度相近，说明周期性明显。</div>
    </div>` : '';

  const noteHtml = (d.notes || []).length
    ? `<div class="dsec"><h4>观测说明</h4>${d.notes.map((n) => `<div class="kvline">· ${esc(n)}</div>`).join('')}</div>`
    : '';

  $('#dBody').innerHTML = `
    <div class="dsec">
      <div class="netverdict ${d.level}">
        <div class="nvscore">${Math.round(d.score)}<small>风险分</small></div>
        <div class="nvreg ${rc}">
          <div class="nvnum">${regText(d.regularity)}<small>规律性</small></div>
        </div>
        <div class="nvtext">
          <b>${esc(LEVEL_ZH[d.level])} · ${esc(d.verdict)}</b>
          <div class="kvline">${d.regularity_source ? '证据来源：' + esc(d.regularity_source) : '无可评估的时序证据'}
            ${d.avg_interval != null ? ' · 平均周期 ' + esc(fmtPeriod(d.avg_interval)) : ''}
            ${d.jitter_pct != null ? ' · 抖动 ' + esc(String(d.jitter_pct)) + '%' : ''}</div>
        </div>
      </div>
    </div>

    <div class="dsec"><h4>命中规则（${(d.findings || []).length}）</h4>${findHtml}</div>

    ${bucketBlock}
    ${connBlock}
    ${byteBlock}

    <div class="dsec">
      <h4>远端端点</h4>
      <dl class="kv">
        <dt>地址</dt><dd class="mono">${esc(d.rip)}:${d.rport}</dd>
        <dt>地址归属</dt><dd>${esc(d.ip_scope_zh)}</dd>
        <dt>端口分类</dt><dd>${esc(d.port_class === 'silverfox' ? '银狐公开报告点名的 C2 端口段'
          : d.port_class === 'abused' ? '常被远控滥用的端口'
          : d.port_class === 'common' ? '常见服务端口' : '非标准端口')}</dd>
        <dt>命中 C2 清单</dt><dd>${d.ioc_ip ? '<span style="color:var(--crit)">是</span>' : '否'}</dd>
        <dt>端点风险</dt><dd>${Math.round(d.endpoint_score)} 分
          ${(d.endpoint_why || []).length ? '<br><span class="dim">' + d.endpoint_why.map(esc).join('；') + '</span>' : ''}</dd>
      </dl>
    </div>

    <div class="dsec">
      <h4>本机进程</h4>
      <dl class="kv">
        <dt>进程 / PID</dt><dd>${esc(d.name)} / ${d.pid}</dd>
        <dt>路径</dt><dd class="mono">${esc(d.exe || '—')}</dd>
        <dt>数字签名</dt><dd>${esc(d.signature_zh)}</dd>
        <dt>进程风险</dt><dd>${esc(LEVEL_ZH[d.proc_level] || d.proc_level)} · ${Math.round(d.proc_score)} 分
          ${d.proc_untrusted ? '<span style="color:var(--high)">（签名不可信）</span>' : ''}</dd>
        <dt>UDP 端口</dt><dd class="mono">${(d.udp_ports || []).join('、') || '—'}</dd>
      </dl>
    </div>

    <div class="dsec">
      <h4>观测统计</h4>
      <dl class="kv">
        <dt>连接实例数</dt><dd>${d.instances} 个（当前存活 ${d.live_conns} 条）</dd>
        <dt>计数重置次数</dt><dd>${d.resets} 次${d.resets ? '<span class="dim">（四元组被新连接复用，属正常）</span>' : ''}</dd>
        <dt>累计流量</dt><dd>↑ ${esc(fmtBytes(d.bytes_out))}　↓ ${esc(fmtBytes(d.bytes_in))}</dd>
        <dt>静默比例</dt><dd>${Math.round((d.idle_ratio || 0) * 100)}%
          <span class="dim">（心跳型应为高静默 + 离散突发）</span></dd>
        <dt>样本置信度</dt><dd>${Math.round((d.regularity_confidence || 0) * 100)}%
          ${d.resolution_limited ? '<span style="color:var(--high)">· 间隔接近采样精度，可靠性下降</span>' : ''}</dd>
      </dl>
    </div>

    ${noteHtml}`;
}

/* ---------------------------- 系统制品 */
function renderArtifacts() {
  if (!STATE) return;
  let list = STATE.artifacts.slice();
  if (ART_FILTER !== 'all') list = list.filter((a) => a.kind === ART_FILTER);
  $('#artInfo').textContent = `${list.length} 项`;
  $('#artEmpty').classList.toggle('show', list.length === 0);

  $('#artList').innerHTML = list.map((a) => {
    const open = openArt.has(a.id) ? ' open' : '';
    const fs = a.findings.map((f) => `
      <div class="finding">
        <div class="ft"><span class="badge ${f.severity}">${f.severity_zh}</span>
          [${esc(f.rule_id)}] ${esc(f.title)}</div>
        <div class="ev">${esc(f.evidence)}</div>
        ${f.advice ? `<div class="ad">${esc(f.advice)}</div>` : ''}
      </div>`).join('');
    return `<div class="artcard ${a.level}${open}" data-aid="${esc(a.id)}">
      <div class="arthead">
        <span class="artkind">${esc(KIND_ZH[a.kind] || a.kind)}</span>
        <h3>${esc(a.title)}</h3>
        <span class="badge ${a.level}">${LEVEL_ZH[a.level]} · ${a.score}</span>
      </div>
      <div class="artsub">${esc(a.subtitle || '')}</div>
      <div class="artbody">${fs}</div>
    </div>`;
  }).join('');
}

/* ---------------------------- 告警 */
function renderAlerts() {
  if (!STATE) return;
  const list = STATE.alerts;
  $('#alertEmpty').classList.toggle('show', list.length === 0);
  $('#alertList').innerHTML = list.map((a) => {
    const rules = (a.rules || []).map((r) => `
      <div class="alarm-rule">[${esc(r.id)}] ${esc(r.title)}
        <div class="ev">${esc(r.evidence)}</div></div>`).join('');
    return `<div class="alertitem ${a.level}${a.net ? ' netalert' : ''}"
        ${a.net_key ? `data-nkey="${esc(a.net_key)}"` : ''}>
      <div class="alarm-head">
        <time>${esc(a.time)}</time>
        <span class="badge ${a.level}">${LEVEL_ZH[a.level]}</span>
        <b>${esc(a.name)}</b>
        ${a.pid ? `<span class="mono" style="color:var(--dim)">PID ${a.pid}</span>` : ''}
        ${a.net ? '<span class="nettag">网络</span>' : ''}
      </div>
      ${a.exe ? `<div class="artsub">${esc(a.exe)}</div>` : ''}
      <div class="alarm-rules">${rules}</div>
    </div>`;
  }).join('');
}

/* ---------------------------- 安全状态 */
// 已知项由 /api/state 一并返回（见 renderSecurity 里的 STATE.whitelist）。
// 这里只负责立即拉一次最新状态，让刚增删的条目马上可见。
function refreshWhitelist() {
  poll();
}

function renderSecurity() {
  const sec = STATE && STATE.security;
  if (!sec) return;
  const it = sec.integrity || {};
  const itCls = it.status === 'ok' ? '' : (it.status === 'changed' || it.status === 'baseline_lost' ? 'bad'
    : (it.status === 'first_run' ? 'info' : 'warn'));
  const itIcon = it.status === 'ok' ? '✓' : (it.status === 'changed' || it.status === 'baseline_lost' ? '⚠' : '•');

  const changed = (it.changed || []).concat(it.added || [], it.removed || []);

  $('#secChecked').textContent = sec.bind ? `监听 ${sec.bind}` : '';

  // 已知项管理卡片
  const wl = STATE.whitelist || { entries: [] };
  const ent = wl.entries || [];
  const badGuard = ent.filter((e) => !e.guard_ok).length;
  const wlCard = `
    <div class="seccard ${badGuard ? 'warn' : ''}">
      <h5>已知项（不再告警的条目）</h5>
      <div class="big">${ent.length} 条${badGuard ? ` · ${badGuard} 条守卫失效` : ''}</div>
      ${ent.length ? `<div class="sub">${
        ent.map((e) => `<div class="wlrow">
            <code>${esc(e.rule_id)}</code> ${esc(e.match.type)}:${esc((e.match.value || '').slice(0, 34))}
            ${e.guard && e.guard.file
              ? `<span class="guardtag ${e.guard_ok ? 'ok' : 'bad'}">${
                  e.guard_ok ? '哈希一致' : (e.guard_exists ? '文件已变化' : '文件不存在')}</span>`
              : ''}
            <button class="btn mini" data-wlrm="${esc(e.id)}">移除</button>
          </div>`).join('')
      }</div>` : '<div class="sub">暂无。在告警详情里点「标记为已知项」即可添加。</div>'}
      <div class="sub" style="margin-top:8px">
        每条已知项都绑定<b>被执行文件的哈希</b>：文件一旦被改动，忽略立即失效、告警自动回来。
        因此它不会成为攻击者的"免死金牌"。
      </div>
    </div>`;

  $$('#secBox [data-wlrm]').forEach((el) => {
    el.addEventListener('click', async (ev) => {
      ev.stopPropagation();
      const ok = await confirmBox({
        title: '移除已知项',
        body: '<p>移除后，该条告警会重新出现。确定吗？</p>',
        okText: '移除',
      });
      if (!ok) return;
      const r = await api('/api/whitelist/remove', { id: el.dataset.wlrm });
      toast(r.msg, r.ok ? 'ok' : 'err');
      await refreshWhitelist();
    });
  });

  $('#secBox').innerHTML = `
    <div class="seccard ${itCls}">
      <h5>程序文件完整性</h5>
      <div class="big">${itIcon} ${esc(it.status_zh || '校验中…')}</div>
      <div class="sub">
        已校验 <code>${esc(it.checked || 0)}</code> 个文件<br>
        基线建立于 ${esc(it.baseline_time || '—')}
      </div>
      <div class="sub" style="margin-top:8px;border-top:1px solid var(--border);padding-top:8px">
        本进程 PID <code>${esc(sec.self_pid || '—')}</code> ·
        自身辅助子进程 <code>${esc(sec.own_children || 0)}</code> 个<br>
        <span style="color:var(--dim)">
          签名校验需要调用 PowerShell，这些子进程的命令行天然带"Base64 执行 / 绕过策略"特征。
          它们按 <b>PID + 创建时间</b>精确排除，且随本进程退出被内核连带回收 ——
          不会出现在告警里，也不会留下孤儿。
        </span>
      </div>
      ${changed.length ? `<div class="chg">${changed.slice(0, 8).map(esc).join('<br>')}</div>
        <div class="acts"><button class="btn" id="btnAcceptIntegrity">确认是我改的，重建基线</button></div>` : ''}
      <div class="sub" style="margin-top:7px">
        说明：同权限的攻击者可以同时改代码与基线，本自检无法发现那种情况。
        它的作用是发现意外损坏，以及顺手改一把的普通恶意程序。
      </div>
    </div>

    <div class="seccard info">
      <h5>网络暴露面</h5>
      <div class="big">仅本机可访问</div>
      <div class="sub">
        监听地址 <code>${esc(sec.bind || '—')}</code><br>
        ${sec.loopback_only ? '只绑定回环地址，局域网与公网均无法连接' : '⚠ 非回环绑定'}
      </div>
    </div>

    <div class="seccard">
      <h5>数据流向</h5>
      <div class="big">零外联 · 数据不出本机</div>
      <div class="sub">
        ${esc(sec.egress || '')}<br>
        采集到的进程、路径、哈希全部留在本机内存与报告中，不上传任何服务器。
      </div>
    </div>

    <div class="seccard">
      <h5>写操作防护（POST 四层校验）</h5>
      <div class="big">${sec.token_enabled ? '已启用' : '未启用'}</div>
      <div class="sub"><ul>${(sec.post_guards || []).map((g) => `<li>${esc(g)}</li>`).join('')}</ul></div>
      <div class="sub" style="margin-top:7px">
        目的：防止任意网页通过跨站请求伪造调用本工具的结束进程 / 关停接口。
      </div>
    </div>

    <div class="seccard info">
      <h5>检测能力来源</h5>
      <div class="big">${esc(sec.rule_count || 0)} 条规则 · IOC ${esc(sec.ioc_version || '')}</div>
      <div class="sub">依据以下公开报告编制：<ul>${
        (sec.ioc_sources || []).map((s) => `<li>${esc(s)}</li>`).join('')}</ul></div>
    </div>
    ${wlCard}`;

  const b = $('#btnAcceptIntegrity');
  if (b) {
    b.addEventListener('click', async () => {
      const ok = await confirmBox({
        title: '重建完整性基线',
        body: `<div class="danger-note">⚠️ 只有在确认这些改动是你自己做的
            （例如更新了 IOC 文件）时才这样做。<br>
            若你不清楚为什么文件变了，说明程序可能已被篡改 ——
            此时应该重新获取一份干净的副本，而不是接受当前状态。</div>
          <p>将把当前文件状态记录为新的基线。</p>`,
        okText: '确认重建',
      });
      if (!ok) return;
      const r = await api('/api/integrity/accept');
      toast(r.msg, r.ok ? 'ok' : 'err');
      poll();
    });
  }
}

/* ---------------------------- 规则 / IOC */
async function loadRules() {
  RULES_LOADED = true;
  try {
    const [rr, ii] = await Promise.all([
      fetch('/api/rules').then((r) => r.json()),
      fetch('/api/iocs').then((r) => r.json()),
    ]);
    $('#ruleCount').textContent = `${rr.length} 条`;
    $('#ruleList').innerHTML = rr.map((r) => `
      <div class="rulerow">
        <span class="rid">${esc(r.rule_id)}</span>
        <div>
          <div class="rt"><span class="badge ${r.severity}">${esc(r.severity_zh)}</span>
            ${esc(r.title)}</div>
          <div class="rd">${esc(r.desc)}</div>
        </div>
      </div>`).join('');

    $('#iocVer').textContent = 'v' + ii.version;
    const grp = (title, arr, bad) => arr && arr.length ? `
      <div class="iocgrp"><h4>${esc(title)}</h4>
        <div class="items">${arr.map((x) =>
          `<code class="${bad ? 'bad' : ''}">${esc(x)}</code>`).join('')}</div>
      </div>` : '';
    $('#iocBox').innerHTML =
      grp('C2 / 传播域名', ii.domains, true) +
      grp('C2 IP 地址', ii.ips, true) +
      grp('银狐常用非标端口', ii.ports, true) +
      grp('恶意文件名', ii.filenames, true) +
      grp('恶意计划任务名', ii.task_names, true) +
      grp('被滥用 / 伪造签名主体', ii.signers, true) +
      grp('易受攻击驱动（BYOVD）', ii.drivers, true) +
      grp('被劫持的安全厂商域名', ii.hosts_targets, true) +
      grp('银狐专用注册表键', ii.reg_keys, true) +
      `<div class="iocgrp"><h4>情报来源</h4>
         <ul class="ioc-src">${(ii.sources || []).map((s) => `<li>${esc(s)}</li>`).join('')}</ul>
       </div>`;
  } catch (e) {
    RULES_LOADED = false;
  }
}

/* ---------------------------- 详情抽屉 */
async function openDetail(pid) {
  $('#drawer').classList.add('show');
  $('#mask').classList.add('show');
  $('#dName').textContent = '加载中…';
  $('#dSub').textContent = '';
  $('#dBody').innerHTML = '<div style="color:var(--dim);padding:22px 0">正在读取进程详情…</div>';
  let d;
  try {
    d = await fetch('/api/detail?pid=' + pid).then((r) => r.json());
  } catch (e) {
    $('#dBody').innerHTML = '<div style="color:var(--crit)">读取失败</div>';
    return;
  }
  if (d.error) { $('#dName').textContent = d.error; $('#dBody').innerHTML = ''; return; }

  const p = d.process, h = d.hashes || {}, dt = d.detail || {};
  $('#dName').textContent = p.name;
  $('#dSub').textContent = p.exe || '（路径不可读）';

  const findHtml = (p.findings || []).map((f) => `
    <div class="dfind ${f.severity}">
      <div class="ft"><span class="badge ${f.severity}">${f.severity_zh}</span>
        [${esc(f.rule_id)}] ${esc(f.title)}</div>
      <div class="ev">${esc(f.evidence)}</div>
      ${f.advice ? `<div class="ad">${esc(f.advice)}</div>` : ''}
      <div class="facts">
        <button class="btn mini" data-known="${esc(f.rule_id)}" data-pid="${p.pid}">
          标记为已知项</button>
        <span class="knownhint">仅忽略"本条规则 + 本对象"的这条告警，不影响其他检测</span>
      </div>
    </div>`).join('') || '<div style="color:var(--ok);font-size:12.5px">未命中任何检测规则</div>';

  const chainHtml = (d.chain || []).map((c, i) => `
    ${i ? '<div class="arrow">↑ 父进程</div>' : ''}
    <div class="node ${i === 0 ? 'cur' : ''}">
      <span class="pid">${c.pid}</span><b>${esc(c.name)}</b>
      <span class="px" title="${esc(c.exe)}">${esc(c.exe)}</span>
    </div>`).join('');

  const conns = (p.connections || []);
  const connHtml = conns.length ? conns.map((c) => `
    <div class="connrow"><span class="st">${esc(c.status || '')}</span>
      <span>${esc(c.laddr || '')} → ${esc(c.raddr || '—')}</span></div>`).join('')
    : '<div style="color:var(--dim);font-size:12px">无网络连接</div>';

  const mods = (dt.modules || []);
  const modHtml = mods.length
    ? mods.slice(0, 60).map((m) => `<div class="modrow">${esc(m.path)}</div>`).join('')
      + (mods.length > 60 ? `<div class="modrow" style="color:var(--dim)">… 另有 ${mods.length - 60} 个模块</div>` : '')
    : `<div style="color:var(--dim);font-size:12px">${esc(dt.error || '未读取到模块信息')}</div>`;

  const sv = sigView(p);
  const startT = p.create_time ? new Date(p.create_time * 1000).toLocaleString('zh-CN') : '—';

  $('#dBody').innerHTML = `
    <div class="dsec">
      <h4>命中规则（${(p.findings || []).length}）</h4>
      ${findHtml}
    </div>

    <div class="dsec">
      <h4>处置操作</h4>
      <div class="dact">
        <button class="btn" data-act="open" data-path="${esc(p.exe)}">打开文件位置</button>
        <button class="btn" data-act="copy" data-path="${esc(p.exe)}">复制路径</button>
        ${p.pid > 4 ? `<button class="btn danger" data-act="kill" data-pid="${p.pid}"
          data-name="${esc(p.name)}">结束进程</button>` : ''}
      </div>
    </div>

    <div class="dsec">
      <h4>基本信息</h4>
      <dl class="kv">
        <dt>PID / PPID</dt><dd>${p.pid} / ${p.ppid || '—'}</dd>
        <dt>父进程</dt><dd>${esc(p.parent_name || '—')}</dd>
        <dt>运行账户</dt><dd>${esc(p.username || '—')}</dd>
        <dt>启动时间</dt><dd>${esc(startT)}</dd>
        <dt>CPU / 内存</dt><dd>${p.cpu}% / ${p.rss_mb} MB</dd>
        <dt>线程数 / 状态</dt><dd>${dt.threads || '—'} / ${esc(dt.status || '—')}</dd>
      </dl>
    </div>

    <div class="dsec">
      <h4>命令行</h4>
      <div class="modrow" style="white-space:pre-wrap">${
        esc(p.cmdline_str || (p.cmdline_denied
          ? '（受保护进程，系统拒绝读取命令行 —— 属正常现象）'
          : (p.cmdline_loaded ? '（不可读，可能受权限限制）'
                              : '（本轮尚未采集，下一轮自动补上）')))}</div>
    </div>

    <div class="dsec">
      <h4>进程链</h4>
      <div class="chain">${chainHtml || '<div style="color:var(--dim);font-size:12px">—</div>'}</div>
    </div>

    <div class="dsec">
      <h4>数字签名</h4>
      <dl class="kv">
        <dt>校验结果</dt><dd><span class="sig ${sv.cls}">${sv.mark} ${esc(sv.txt)}</span></dd>
        <dt>签名主体</dt><dd>${esc(sv.cn || '—')}</dd>
        <dt>证书主体全名</dt><dd>${esc((p.signature || {}).signer || '—')}</dd>
        <dt>证书有效期至</dt><dd>${esc((p.signature || {}).notafter || '—')}</dd>
      </dl>
    </div>

    <div class="dsec">
      <h4>文件信息</h4>
      <dl class="kv">
        <dt>文件大小</dt><dd>${h.size ? (h.size / 1048576).toFixed(2) + ' MB' : '—'}</dd>
        <dt>修改时间</dt><dd>${esc(h.mtime || '—')}</dd>
        <dt>文件头</dt><dd>${esc(h.magic || '—')}</dd>
        <dt>MD5</dt><dd>${esc(h.md5 || '—')}</dd>
        <dt>SHA-256</dt><dd>${esc(h.sha256 || '—')}</dd>
      </dl>
    </div>

    <div class="dsec">
      <h4>网络连接（${conns.length}）</h4>
      <div class="connlist">${connHtml}</div>
    </div>

    <div class="dsec">
      <h4>加载模块（${mods.length}）</h4>
      <div class="modlist">${modHtml}</div>
    </div>`;
}

function closeDetail() {
  $('#drawer').classList.remove('show');
  $('#mask').classList.remove('show');
}

/* ---------------------------- 弹窗 */
let modalResolve = null;
function confirmBox({ title, body, okText = '确认', danger = true }) {
  $('#mTitle').textContent = title;
  $('#mBody').innerHTML = body;
  $('#mOk').textContent = okText;
  $('#mOk').className = 'btn ' + (danger ? 'danger' : 'primary');
  $('#modalMask').classList.add('show');
  return new Promise((res) => { modalResolve = res; });
}
// 与 confirmBox 同款弹窗，但带一个文本输入框（用于让用户写备注）。
// 确定返回输入内容（可能是空串），取消返回 null。
function promptBox({ title, body, okText = '确定', defaultValue = '', placeholder = '' }) {
  $('#mTitle').textContent = title;
  $('#mBody').innerHTML = body + `<div style="margin-top:11px">
    <input id="mInput" type="text" placeholder="${esc(placeholder)}"
      value="${esc(defaultValue)}"
      style="width:100%;box-sizing:border-box;padding:7px 9px;border-radius:7px;
             border:1px solid var(--border);background:var(--panel);
             color:var(--fg);font-size:12.5px;outline:none">
  </div>`;
  $('#mOk').textContent = okText;
  $('#mOk').className = 'btn primary';
  $('#modalMask').classList.add('show');
  setTimeout(() => { const el = $('#mInput'); if (el) el.focus(); }, 50);
  return new Promise((res) => {
    modalResolve = (v) => {
      const el = $('#mInput');
      res(v ? (el ? el.value : '') : null);
    };
  });
}

function closeModal(v) {
  $('#modalMask').classList.remove('show');
  if (modalResolve) { modalResolve(v); modalResolve = null; }
}

/* ---------------------------- 事件绑定 */
document.addEventListener('DOMContentLoaded', () => {

  $$('.tab').forEach((t) => t.addEventListener('click', () => {
    $$('.tab').forEach((x) => x.classList.remove('active'));
    $$('.tabpane').forEach((x) => x.classList.remove('active'));
    t.classList.add('active');
    $('#pane-' + t.dataset.tab).classList.add('active');
    // 切到规则页时刷新已知项，保证刚增删的条目立即可见
    if (t.dataset.tab === 'rules') refreshWhitelist();
  }));

  $('#q').addEventListener('input', (e) => { FILTER.q = e.target.value; renderProcTable(); });
  $('#chkConn').addEventListener('change', (e) => { FILTER.onlyConn = e.target.checked; renderProcTable(); });

  $$('#segLevel button').forEach((b) => b.addEventListener('click', () => {
    $$('#segLevel button').forEach((x) => x.classList.remove('on'));
    b.classList.add('on');
    FILTER.level = b.dataset.lv;
    renderProcTable();
  }));

  $$('#segArtKind button').forEach((b) => b.addEventListener('click', () => {
    $$('#segArtKind button').forEach((x) => x.classList.remove('on'));
    b.classList.add('on');
    ART_FILTER = b.dataset.kind;
    renderArtifacts();
  }));

  /* ---------- 网络监控：时长滑块 ---------- */
  // 拖动时先本地更新显示（不卡顿），停手 550ms 后才提交 —— 否则每移动一格
  // 就打一次接口，既浪费又会让会话被反复重开。
  $('#netSlider').addEventListener('input', (e) => {
    NET.touched = true;
    const stops = (STATE.net && STATE.net.duration_stops) || [30, 60, 120, 180, 300, 600, 900];
    const i = Number(e.target.value) || 0;
    const d = stops[i] || 120;
    $('#netDurVal').textContent = durLabel(d);
    $('#netDurHint').textContent = durHint(d);
    e.target.style.setProperty('--fill',
      (stops.length > 1 ? (i / (stops.length - 1)) * 100 : 0) + '%');
    $$('#netTicks span').forEach((sp, k) => sp.classList.toggle('on', k === i));
    clearTimeout(NET.timer);
    NET.timer = setTimeout(async () => {
      const r = await api('/api/net/duration', { duration: d });
      if (r.msg) toast(r.msg, r.ok ? 'ok' : 'err');
      poll();
    }, 550);
  });

  $('#netStart').addEventListener('click', async () => {
    const stops = (STATE.net && STATE.net.duration_stops) || [30, 60, 120, 180, 300, 600, 900];
    const d = stops[Number($('#netSlider').value)] || 120;
    const r = await api('/api/net/start', { duration: d });
    toast(r.msg || '已开始', r.ok ? 'ok' : 'err');
    poll();
  });

  $('#netStop').addEventListener('click', async () => {
    const r = await api('/api/net/stop');
    toast(r.msg || '已停止', r.ok ? 'ok' : 'err');
    poll();
  });

  $$('#segNet button').forEach((b) => b.addEventListener('click', () => {
    $$('#segNet button').forEach((x) => x.classList.remove('on'));
    b.classList.add('on');
    NET.filter = b.dataset.nf;
    renderNet();
  }));

  $('#netQ').addEventListener('input', (e) => { NET.q = e.target.value; renderNetTable(STATE.net); });
  $('#chkNetBytes').addEventListener('change', (e) => {
    NET.onlyBytes = e.target.checked; renderNetTable(STATE.net);
  });

  $$('#netTable thead th').forEach((th) => th.addEventListener('click', () => {
    const k = th.dataset.nsort;
    if (!k) return;
    if (NET.sort.key === k) NET.sort.dir *= -1;
    else { NET.sort.key = k; NET.sort.dir = -1; }
    renderNetTable(STATE.net);
  }));

  $('#netBody').addEventListener('click', (e) => {
    const tr = e.target.closest('tr[data-nkey]');
    if (tr) openNetDetail(tr.dataset.nkey);
  });

  $('#netTicks').addEventListener('click', (e) => {
    const sp = e.target.closest('span[data-i]');
    if (!sp) return;
    const sl = $('#netSlider');
    sl.value = sp.dataset.i;
    sl.dispatchEvent(new Event('input'));
  });

  // 告警时间线里点网络告警 → 直接打开对应流量详情
  $('#alertList').addEventListener('click', (e) => {
    const it = e.target.closest('.alertitem');
    if (!it) return;
    const k = it.dataset.nkey;
    if (k) { $$('.tab').forEach((x) => x.classList.remove('active'));
      $$('.tabpane').forEach((x) => x.classList.remove('active'));
      $('.tab[data-tab="net"]').classList.add('active');
      $('#pane-net').classList.add('active');
      openNetDetail(k); }
  });

  $$('table.grid thead th').forEach((th) => th.addEventListener('click', () => {
    const k = th.dataset.sort;
    if (!k) return;
    if (SORT.key === k) SORT.dir *= -1;
    else { SORT.key = k; SORT.dir = -1; }
    renderProcTable();
  }));

  $('#procBody').addEventListener('click', (e) => {
    const tr = e.target.closest('tr[data-pid]');
    if (tr) openDetail(Number(tr.dataset.pid));
  });

  $('#artList').addEventListener('click', (e) => {
    const card = e.target.closest('.artcard');
    if (!card) return;
    const id = card.dataset.aid;
    if (openArt.has(id)) openArt.delete(id); else openArt.add(id);
    card.classList.toggle('open');
  });

  $('#dClose').addEventListener('click', closeDetail);
  $('#mask').addEventListener('click', closeDetail);

  $('#dBody').addEventListener('click', async (e) => {
    // 注意顺序：'标记为已知项' 按钮没有 data-act，
    // 若先做 closest('button[data-act]') 的判空返回，这段代码永远到不了。
    const kb = e.target.closest('[data-known]');
    if (kb) {
      const ruleId = kb.dataset.known;
      const pid = Number(kb.dataset.pid);
      const s = await api('/api/whitelist/suggest', { pid, rule_id: ruleId });
      if (!s.ok) { toast(s.msg || '无法生成已知项', 'err'); return; }
      const sg = s.suggest;
      const hasGuard = !!(sg.guard && sg.guard.file);
      const note = await promptBox({
        title: '标记为已知项',
        body: `<div class="danger-note">⚠️ 只在你<b>确认这条告警是预期的</b>时才这样做。
            若你不清楚它为什么出现，请先去查证 —— 把它标记掉会让真正的攻击也静默。</div>
          <p><b>规则</b>：<code>${esc(sg.rule_id)}</code></p>
          <p><b>匹配条件</b>：${esc(sg.match.type)} = <code>${esc(sg.match.value)}</code></p>
          <p><b>守卫文件</b>：${hasGuard
            ? `<code>${esc(sg.guard.file)}</code><br>
               <span style="font-size:11.5px;color:var(--dim)">已绑定当前哈希；
               该文件一旦被改动，这条忽略会立即失效、告警自动回来。</span>`
            : '<span style="color:var(--high)">未找到可绑定的文件 —— 忽略范围较大，请谨慎。</span>'}</p>`,
        okText: '确认标记',
        placeholder: '为什么它是正常的？（写一句备注，日后你能看懂）',
      });
      if (note === null) return;
      const r = await api('/api/whitelist/add', {
        rule_id: sg.rule_id, match: sg.match, guard: sg.guard, note,
      });
      toast(r.msg, r.ok ? 'ok' : 'err');
      await refreshWhitelist();
      closeDetail();
      return;
    }

    const btn = e.target.closest('button[data-act]');
    if (!btn) return;
    const act = btn.dataset.act;

    if (act === 'open') {
      const r = await api('/api/open', { path: btn.dataset.path });
      toast(r.msg, r.ok ? 'ok' : 'err');
    } else if (act === 'copy') {
      try { await navigator.clipboard.writeText(btn.dataset.path); toast('路径已复制', 'ok'); }
      catch (err) { toast('复制失败，请手动选择', 'err'); }
    } else if (act === 'kill') {
      const ok = await confirmBox({
        title: '确认结束进程',
        body: `<div class="danger-note">
            ⚠️ 强制结束进程可能导致程序崩溃或数据丢失。<br>
            仅在你确认该进程是恶意程序时执行。
          </div>
          <p>进程：<code>${esc(btn.dataset.name)}</code>　PID：<code>${btn.dataset.pid}</code></p>
          <p>银狐具备看门狗机制，结束单一进程后可能被其他组件重新拉起。
             建议同时检查「系统制品」页中的计划任务与注册表项。</p>`,
        okText: '确认结束',
      });
      if (!ok) return;
      const r = await api('/api/kill', { pid: Number(btn.dataset.pid) });
      toast(r.msg, r.ok ? 'ok' : 'err');
      closeDetail();
    }
  });

  $('#mCancel').addEventListener('click', () => closeModal(false));
  $('#mOk').addEventListener('click', () => closeModal(true));
  $('#modalMask').addEventListener('click', (e) => {
    if (e.target.id === 'modalMask') closeModal(false);
  });

  $('#btnScan').addEventListener('click', async () => {
    await api('/api/scan');
    toast('已触发全量重扫（含系统制品）', 'ok');
  });

  $('#btnExport').addEventListener('click', async () => {
    toast('正在生成报告…');
    const r = await api('/api/export');
    if (r.ok) {
      toast(r.msg, 'ok');
      const ok = await confirmBox({
        title: '报告已生成',
        body: `<p>排查报告已保存到：</p><p><code>${esc(r.path)}</code></p>
               <p>是否现在打开？</p>`,
        okText: '打开报告', danger: false,
      });
      if (ok) await api('/api/open', { path: r.path });
    } else toast(r.msg, 'err');
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { closeDetail(); closeModal(false); }
  });

  poll();
  setInterval(poll, 2000);
});
