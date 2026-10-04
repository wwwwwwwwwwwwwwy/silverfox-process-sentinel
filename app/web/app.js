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
  $('#kpis').innerHTML = [
    ['', s.total, '进程总数', `扫描耗时 ${s.scan_ms} ms · 第 ${s.scan_count} 轮`],
    ['crit', L.critical, '严重风险进程', '疑似银狐本体或注入载体'],
    ['high', L.high, '高危进程', '需人工核查'],
    ['med', L.medium, '中危 / 可疑', '未签名外联、随机命名等'],
    ['', s.artifact_findings, '系统制品异常', `任务 ${s.tasks} · 服务 ${s.services} · 驱动 ${s.drivers}`],
    ['ok', s.connections, '网络连接', s.sig_pending > 0 ? `签名待校验 ${s.sig_pending}` : '签名库已就绪'],
  ].map(([cls, v, label, sub]) => `
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

  renderProcTable();
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
    return `<div class="alertitem ${a.level}">
      <div class="alarm-head">
        <time>${esc(a.time)}</time>
        <span class="badge ${a.level}">${LEVEL_ZH[a.level]}</span>
        <b>${esc(a.name)}</b>
        ${a.pid ? `<span class="mono" style="color:var(--dim)">PID ${a.pid}</span>` : ''}
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
