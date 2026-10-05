/* ============================================================
   银狐进程监视器 · 前端逻辑（零依赖）
   ============================================================ */
'use strict';

const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));

/* ============================================================
   界面文案：专业用语版 / 大白话版
   ------------------------------------------------------------
   为什么做两套：这套工具的检测规则是按公开技术报告写的，术语密度很高
   （制品、外联、规律性、变异系数、IOC、PPID 欺骗…）。懂行的人看术语更快更准；
   不懂的人看术语只会一脸问号 —— 一个安全工具如果让人看不懂，就等于没有。
   所以做成开关，**默认给大白话**：第一次打开的人不该先学会行话才能用。

   约定：
     · 术语本身在"专业版"里保持原样，不要为了通俗而改动检测结论的表述；
     · 大白话版只换说法、不换含义，也不弱化风险等级（"严重"仍然是"严重"）；
     · 涉及具体判断依据的地方（证据、规则号）两版一致 —— 那是可核验的事实。
   ============================================================ */
const LANGS = {
  pro: {
    lang_name: '专业用语',
    lang_switch: '切换为专业用语版',
    app_name: '银狐进程监视器',
    btn_scan: '立即重扫', btn_export: '导出报告',
    pill_init: '初始化', pill_admin_ok: '管理员权限',
    pill_admin_no: '普通权限 · 部分检测受限', pill_admin_check: '权限检测中',
    uptime: '运行',
    st_changed: '⚠ 程序文件已被改动', st_first: '首次扫描中…',
    st_scanning: '扫描中…', st_ok: '监控中 · 未见异常',
    st_crit_n: '发现 {n} 个严重进程', st_high_n: '{n} 个高危进程待核查',
    admin_ok_tip: '已获得完整检测能力',
    admin_no_tip: '建议右键以管理员身份运行，才能读取 Defender 排除项与受保护进程信息',

    tab_proc: '进程监控', tab_net: '网络监控', tab_art: '系统痕迹',
    tab_alert: '告警时间线', tab_rules: '规则与 IOC',

    ph_proc: '搜索进程名 / 路径 / PID / 命令行…',
    seg_all: '全部', seg_risky: '仅异常',
    chk_conn: '仅看有外联',
    th_risk: '风险', th_proc: '进程', th_path: '路径',
    th_sig: '数字签名', th_net: '外联', th_hit: '命中规则',
    no_match: '没有符合条件的进程',

    net_dur: '观测时长', net_restart: '重新检测', net_stop: '停止',
    net_focus: '重点关注', net_regular: '仅高规律', net_risky: '仅可疑',
    ph_net: '搜索进程 / 远端 IP / 端口…', chk_bytes: '仅看有数据传输',
    th_reg: '规律性', th_remote: '远端地址', th_bytes: '流量 / 事件',
    th_verdict: '判定依据',
    net_empty: '本时段未发现规律性异常的网络外联',

    art_empty_title: '未发现异常系统痕迹',
    art_empty_body: '已检查：计划任务、系统服务、内核驱动、hosts 文件、'
                  + 'Defender 排除项、注册表启动项、常驻目录文件。',
    art_kind_all: '全部', art_kind_task: '计划任务', art_kind_service: '系统服务',
    art_kind_driver: '内核驱动', art_kind_hosts: 'hosts',
    art_kind_registry: '注册表', art_kind_file: '文件',
    art_hint: '<b>「系统痕迹」是什么</b>木马除了"正在运行的进程"之外，还会在系统里留下'
            + '<b>需要长期存在</b>的东西 —— 计划任务、系统服务、内核驱动、hosts 文件改动、'
            + '注册表启动项与 Defender 排除项、以及磁盘上落地的伪装文件。'
            + '<b>进程被杀掉之后它们依然存在</b>，所以必须单独查、单独清。',

    alert_empty_title: '暂无告警',
    alert_empty_body: '监控期间新出现的高风险进程与系统痕迹异常会实时记录在此。',

    sec_status: '安全状态', sec_rules: '检测规则库', sec_ioc: 'IOC 指标库',

    d_rules: '命中规则', d_actions: '处置操作', d_basic: '基本信息',
    d_cmd: '命令行', d_chain: '进程链', d_sig: '数字签名',
    d_file: '文件信息', d_net: '网络连接', d_mods: '加载模块',
    d_loading: '加载中…', d_reading: '正在读取进程详情…', d_readfail: '读取失败',
    d_path_unreadable: '（路径不可读）',
    d_more_mods: '… 另有 {n} 个模块', d_no_mods: '未读取到模块信息',
    d_cmd_denied: '（受保护进程，系统拒绝读取命令行 —— 属正常现象）',
    d_cmd_unreadable: '（不可读，可能受权限限制）',
    d_cmd_pending: '（本轮尚未采集，下一轮自动补上）',
    d_sec_rules_n: '命中规则（{n}）', d_sec_net_n: '网络连接（{n}）',
    d_sec_mods_n: '加载模块（{n}）',
    ioc_domains: 'C2 / 传播域名', ioc_ips: 'C2 IP 地址',
    ioc_ports: '银狐常用非标端口', ioc_filenames: '恶意文件名',
    ioc_tasks: '恶意计划任务名', ioc_signers: '被滥用 / 伪造签名主体',
    ioc_drivers: '易受攻击驱动（BYOVD）', ioc_hosts: '被劫持的安全厂商域名',
    ioc_reg: '银狐专用注册表键', ioc_sources: '情报来源',
    rules_hint: '',
    sec_int_sub: '已校验 <code>{n}</code> 个文件<br>基线建立于 {t}',
    sec_int_self: '本进程 PID <code>{pid}</code> · 自身辅助子进程 <code>{n}</code> 个<br>'
                + '<span style="color:var(--dim)">签名校验需要调用 PowerShell，'
                + '这些子进程的命令行天然带"Base64 执行 / 绕过策略"特征。'
                + '它们按 <b>PID + 创建时间</b>精确排除，且随本进程退出被内核连带回收 —— '
                + '不会出现在告警里，也不会留下孤儿。</span>',
    sec_int_note: '说明：同权限的攻击者可以同时改代码与基线，本自检无法发现那种情况。'
                + '它的作用是发现意外损坏，以及顺手改一把的普通恶意程序。',
    sec_int_btn: '确认是我改的，重建基线',
    sec_expose_ok: '仅本机可访问',
    sec_expose_sub: '监听地址 <code>{a}</code><br>{b}',
    sec_expose_loop: '只绑定回环地址，局域网与公网均无法连接',
    sec_expose_bad: '⚠ 非回环绑定',
    sec_flow_ok: '零外联 · 数据不出本机',
    sec_flow_sub: '{eg}<br>采集到的进程、路径、哈希全部留在本机内存与报告中，'
                + '不上传任何服务器。',
    sec_write_on: '已启用', sec_write_off: '未启用',
    sec_write_note: '目的：防止任意网页通过跨站请求伪造调用本工具的结束进程 / 关停接口。',
    sec_source_big: '{n} 条规则 · IOC {v}',
    sec_source_sub: '依据以下公开报告编制：',
    sec_accept_title: '重建完整性基线',
    sec_accept_body: '<div class="danger-note">⚠️ 只有在确认这些改动是你自己做的'
                   + '（例如更新了 IOC 文件）时才这样做。<br>'
                   + '若你不清楚为什么文件变了，说明程序可能已被篡改 —— '
                   + '此时应该重新获取一份干净的副本，而不是接受当前状态。</div>'
                   + '<p>将把当前文件状态记录为新的基线。</p>',
    sec_accept_ok: '确认重建',
    act_open: '打开文件位置', act_copy: '复制路径',
    act_kill: '结束进程', act_known: '标记为已知项',
    known_hint: '仅忽略"本条规则 + 本对象"的这条告警，不影响其他检测',
    no_rule_hit: '未命中任何检测规则',
    no_conn: '无网络连接',

    lv_critical: '严重', lv_high: '高危', lv_medium: '中危',
    lv_low: '低危', lv_clean: '正常',

    kpi_total: '进程总数', kpi_crit: '严重风险进程', kpi_high: '高危进程',
    kpi_med: '中危 / 可疑', kpi_art: '系统痕迹异常', kpi_conn: '网络连接',
    kpi_reg: '高规律性外联',
    kpi_total_sub: '扫描耗时 {ms} ms · 第 {n} 轮',
    kpi_crit_sub: '疑似银狐本体或注入载体', kpi_high_sub: '需人工核查',
    kpi_med_sub: '未签名外联、随机命名等',
    kpi_art_sub: '任务 {t} · 服务 {s} · 驱动 {d}',
    kpi_conn_sub_pending: '签名待校验 {n}', kpi_conn_sub_ready: '签名库已就绪',
    kpi_reg_sub_bad: '其中 {n} 个已判可疑', kpi_reg_sub_ok: '规律性 ≥70 共 {n} 个',

    sec_integrity: '程序文件完整性', sec_expose: '网络暴露面',
    sec_flow: '数据流向', sec_write: '写操作防护（POST 四层校验）',
    sec_source: '检测能力来源',
    wl_title: '已知项（不再告警的条目）',
    wl_none: '暂无。在告警详情里点「标记为已知项」即可添加。',
    wl_note: '每条已知项都绑定<b>被执行文件的哈希</b>：文件一旦被改动，忽略立即失效、告警自动回来。因此它不会成为攻击者的"免死金牌"。',

    sig_checking: '校验中', sig_ok: '签名有效', sig_forged: '签名伪造',
    sig_untrusted: '根证书不受信任', sig_noimage: '无镜像文件',
    sig_noimage_tip: '系统伪进程或 VBS 隔离组件，没有对应的可执行文件',
    sig_packaged: 'MSIX 包签名',
    sig_packaged_tip: '由应用包整体签名保护，不单独签名',
    sig_unsigned: '未签名', sig_failed: '校验失败',
    conn_lost: '连接中断', count_items: '{a} / {b} 项',
    path_unreadable: '（无法读取路径）',
    chain_parent: '↑ 父进程',
    kv_pid: 'PID / PPID', kv_parent: '父进程', kv_user: '运行账户',
    kv_start: '启动时间', kv_cpu: 'CPU / 内存', kv_threads: '线程数 / 状态',
    kv_sigresult: '校验结果', kv_signer: '签名主体', kv_cn: '证书主体全名',
    kv_notafter: '证书有效期至', kv_size: '文件大小', kv_mtime: '修改时间',
    kv_magic: '文件头', kv_hash: '哈希',

    net_disabled: '本次启动未启用网络检测（使用了 --no-net 参数）。',
    net_disabled_short: '网络检测未启用',
    net_phase_live: '采集中', net_phase_done: '本轮已完成',
    net_meta: '已观测 {e} / {d}（{p}%） · 活动连接 {c} 条 · 流量条目 {f} 个 · '
            + '可评估规律性 {v} 个',
    net_meta_high: '规律性 ≥85 的 {n} 个', net_meta_susp: '可疑 {n} 个',
    net_meta_sample: '采样 {s} 秒/次（{ms} ms）',
    net_meta_estats_ok: '字节统计 可用', net_meta_estats_no: '字节统计 不可用',
    net_no_match: '当前筛选条件下没有匹配项 —— 试试切到「全部」。',
    net_no_traffic: '观测期间未捕获到任何外联流量。',
    tag_ioc: '命中 IOC', tag_sf_port: '银狐端口',
    tag_unsigned: '进程未签名', tag_reslim: '精度受限',
    reg_none: '不可评估', reg_noeval: '样本不足',
    sub_period: '周期 {v}', sub_jitter: '抖动 {v}%',
    conn_stat: '连接 {a} 条 · 建立事件 {b} · 数据事件 {c}',
    dur_hint: '最长可识别约 {p} 秒周期的心跳（需 ≥3 个完整间隔）',
    note_method: '<b>判定方法</b>：<b>规律性</b>由事件间隔的变异系数换算（0–100，'
               + '越大越像机器在打拍子）；<b>风险</b>由规则判定。软件更新检查、'
               + '遥测上报同样具有周期性，因此规律性高<b>不等于</b>恶意 —— '
               + '只有与可疑进程或可疑目标共振时才会升级为告警。',
    note_streams: '<b>两条证据流</b>：① 连接建立间隔 —— 覆盖"连上→发数据→断开→再连"'
                + '型心跳；② 数据突发间隔 —— 覆盖<b>长连接上的心跳</b>'
                + '（靠 TCP 每连接字节计数器识别，不抓包、不解密）。',
    note_estats_off: '<span class="warn">⚠ 字节统计不可用</span>：{why}。'
                   + '本次仅依据连接建立事件判定，<b>长连接型心跳可能漏检</b>；'
                   + '建议以管理员身份运行。',
    note_history: '<b>上一轮</b>：{t} 起观测 {d}，流量条目 {f} 个，规律性 ≥70 的 {r} 个，'
                + '严重 {c} / 高危 {h}。',
    note_bounds: '<b>观测边界</b>：采样周期 {s} 秒 —— 短于该周期的行为会混叠；'
               + '只读本机连接表与 TCP 统计计数器，<b>不发起任何网络请求</b>'
               + '（无 DNS 解析）；UDP 无远端信息，不参与规律性判定。',
  },
  plain: {
    lang_name: '大白话',
    lang_switch: '切换为大白话版',
    app_name: '银狐木马监视器',
    btn_scan: '重新检查', btn_export: '导出报告',
    pill_init: '正在启动', pill_admin_ok: '权限完整',
    pill_admin_no: '权限不足 · 有些东西查不到', pill_admin_check: '正在检查权限',
    uptime: '已运行',
    st_changed: '⚠ 程序文件被改过', st_first: '第一次检查中…',
    st_scanning: '正在检查…', st_ok: '正在盯着 · 目前没问题',
    st_crit_n: '发现 {n} 个严重问题', st_high_n: '{n} 个可疑问题待确认',
    admin_ok_tip: '权限完整，能查的都查得到',
    admin_no_tip: '右键以管理员身份运行，才能看到杀毒软件的白名单设置和部分受保护的程序信息',

    tab_proc: '运行中的程序', tab_net: '联网行为', tab_art: '系统里留下的东西',
    tab_alert: '发现的问题', tab_rules: '检查规则与特征库',

    ph_proc: '搜程序名、文件位置、PID…',
    seg_all: '全部', seg_risky: '只看有问题的',
    chk_conn: '只看正在联网的',
    th_risk: '危险程度', th_proc: '程序', th_path: '文件位置',
    th_sig: '官方签名', th_net: '联网', th_hit: '为什么被标记',
    no_match: '没有符合条件的程序',

    net_dur: '检查多久', net_restart: '重新检查', net_stop: '停止',
    net_focus: '重点看这些', net_regular: '只看很规律的', net_risky: '只看可疑的',
    ph_net: '搜程序、对方地址、端口…', chk_bytes: '只看传过数据的',
    th_reg: '规律程度', th_remote: '连到哪里', th_bytes: '数据量 / 次数',
    th_verdict: '判断理由',
    net_empty: '这段时间没发现异常的联网行为',

    art_empty_title: '没发现异常',
    art_empty_body: '这次查了：定时任务、后台服务、系统底层驱动、网址对照表（hosts）、'
                  + '杀毒软件的白名单设置、开机自启项、常见藏身目录里的文件。',
    art_kind_all: '全部', art_kind_task: '定时任务', art_kind_service: '后台服务',
    art_kind_driver: '系统底层驱动', art_kind_hosts: '网址对照表',
    art_kind_registry: '系统设置库', art_kind_file: '文件',
    art_hint: '<b>「系统里留下的东西」是什么</b>木马除了"正在运行的程序"之外，'
            + '还会在系统里留下<b>需要长期存在</b>的东西 —— 定时任务、后台服务、'
            + '系统底层驱动、网址对照表（hosts）的改动、开机自启项、'
            + '杀毒软件的白名单设置，以及藏在磁盘上的伪装文件。'
            + '<b>程序被结束之后它们依然存在</b>，所以必须单独查、单独清。',

    alert_empty_title: '目前没问题',
    alert_empty_body: '盯着这段时间里新出现的可疑程序和系统改动，有问题会实时出现在这里。',

    sec_status: '它自己的安全状况', sec_rules: '检查规则', sec_ioc: '已知木马特征库',

    d_rules: '为什么被标记', d_actions: '可以做什么', d_basic: '基本信息',
    d_cmd: '启动参数', d_chain: '是谁启动的', d_sig: '官方签名',
    d_file: '文件信息', d_net: '联网情况', d_mods: '加载了哪些文件',
    d_loading: '正在加载…', d_reading: '正在读取程序详情…', d_readfail: '读取失败',
    d_path_unreadable: '（读不到文件位置）',
    d_more_mods: '… 还有 {n} 个', d_no_mods: '没读到加载的文件',
    d_cmd_denied: '（系统保护进程，不允许读取启动参数 —— 这是正常的）',
    d_cmd_unreadable: '（读不到，可能是权限不够）',
    d_cmd_pending: '（这次还没读到，下一次会补上）',
    d_sec_rules_n: '为什么被标记（{n}）', d_sec_net_n: '联网情况（{n}）',
    d_sec_mods_n: '加载了哪些文件（{n}）',
    ioc_domains: '木马服务器与下载网址', ioc_ips: '木马服务器 IP',
    ioc_ports: '木马常用端口', ioc_filenames: '已知木马文件名',
    ioc_tasks: '木马用过的定时任务名', ioc_signers: '被冒用或伪造的签名',
    ioc_drivers: '有漏洞、能被利用的驱动', ioc_hosts: '被劫持的安全厂商网址',
    ioc_reg: '木马专用的系统设置项', ioc_sources: '资料从哪来',
    rules_hint: '<b>这一页是技术细节，看不懂可以直接跳过</b> —— '
              + '它列出的是本工具"凭什么下判断"：每一条检查规则、以及已知木马的特征清单。'
              + '放在这里是给你核对用的，平时不需要看。',
    sec_int_sub: '已经核对过 <code>{n}</code> 个文件<br>参照标准建立于 {t}',
    sec_int_self: '本程序 PID <code>{pid}</code> · 自己拉起的辅助进程 <code>{n}</code> 个<br>'
                + '<span style="color:var(--dim)">验签名要临时调用系统自带的脚本工具，'
                + '这些进程的命令行长得"很像坏人"（带编码执行、绕过限制）。'
                + '它们按 <b>PID + 创建时间</b>精确排除，程序一退出就被系统连带回收 —— '
                + '不会出现在提醒里，也不会留下残留。</span>',
    sec_int_note: '说明：跟你同样权限的程序，可以同时改代码和参照标准，'
                + '所以这个自检发现不了那种情况。它的用处是发现意外损坏，'
                + '以及"顺手改一把"的普通恶意程序。',
    sec_int_btn: '确认是我改的，重建参照标准',
    sec_expose_ok: '只有本机能访问',
    sec_expose_sub: '对外地址 <code>{a}</code><br>{b}',
    sec_expose_loop: '只允许本机访问，同一个局域网或公网的其他机器都连不上',
    sec_expose_bad: '⚠ 不限于本机',
    sec_flow_ok: '不联网 · 数据不出这台电脑',
    sec_flow_sub: '{eg}<br>采集到的程序、路径、指纹都只留在本机内存和报告里，'
                + '不会传到任何服务器。',
    sec_write_on: '已开启', sec_write_off: '没开启',
    sec_write_note: '目的：防止随便一个网页偷偷调用本工具，'
                  + '把你的程序结束掉、或者把它自己关掉。',
    sec_source_big: '{n} 条检查规则 · 特征库 {v}',
    sec_source_sub: '判断依据来自这些公开报告：',
    sec_accept_title: '重建参照标准',
    sec_accept_body: '<div class="danger-note">⚠️ 只有在确认这些改动是你自己做的'
                   + '（比如你更新了特征库文件）时才这样做。<br>'
                   + '如果你不清楚文件为什么变了，说明程序可能被人改过 —— '
                   + '这时应该重新弄一份干净的，而不是接受当前状态。</div>'
                   + '<p>会把现在的文件状态记成新的参照标准。</p>',
    sec_accept_ok: '确认重建',
    act_open: '打开所在文件夹', act_copy: '复制路径',
    act_kill: '结束这个程序', act_known: '加入白名单（我知道它没问题）',
    known_hint: '只忽略这一条，不影响别的检查',
    no_rule_hit: '没发现任何问题',
    no_conn: '没有联网',

    lv_critical: '严重', lv_high: '可疑', lv_medium: '留意',
    lv_low: '轻微', lv_clean: '正常',

    kpi_total: '程序总数', kpi_crit: '严重问题', kpi_high: '可疑问题',
    kpi_med: '需要留意', kpi_art: '系统里留下的异常', kpi_conn: '网络连接',
    kpi_reg: '很规律的联网',
    kpi_total_sub: '每轮约 {ms} 毫秒 · 第 {n} 次',
    kpi_crit_sub: '很可能是木马本体，或它塞进来的东西', kpi_high_sub: '需要你自己确认一下',
    kpi_med_sub: '没签名却在联网、名字是乱敲的等等',
    kpi_art_sub: '定时任务 {t} · 后台服务 {s} · 驱动 {d}',
    kpi_conn_sub_pending: '还有 {n} 个文件没验签名', kpi_conn_sub_ready: '签名都验完了',
    kpi_reg_sub_bad: '其中 {n} 个已经判定可疑', kpi_reg_sub_ok: '规律程度 ≥70 的有 {n} 个',

    sec_integrity: '程序文件有没有被改过', sec_expose: '有没有对外开放',
    sec_flow: '数据会不会外传', sec_write: '防别人乱指挥',
    sec_source: '检查依据从哪来',
    wl_title: '白名单（不再提醒的东西）',
    wl_none: '还没有。在问题详情里点「加入白名单」就能添加。',
    wl_note: '每条白名单都记着那个文件的<b>指纹</b>：文件只要被改过（哪怕一个字节），这条忽略就立刻失效、提醒会自己回来。所以它不会变成坏人的"免死金牌"。',

    sig_checking: '正在验签名', sig_ok: '签名正常', sig_forged: '签名是假的',
    sig_untrusted: '签名来路不明', sig_noimage: '没有可执行文件',
    sig_noimage_tip: '系统自带的特殊进程，本身就没有对应的程序文件',
    sig_packaged: '应用商店签名',
    sig_packaged_tip: '由整个应用包统一签名，不单独签',
    sig_unsigned: '没签名', sig_failed: '验签名失败',
    conn_lost: '连接中断', count_items: '{a} / {b} 个',
    path_unreadable: '（读不到文件位置）',
    chain_parent: '↑ 启动它的',
    kv_pid: 'PID / PPID', kv_parent: '是谁启动的', kv_user: '以谁的身份运行',
    kv_start: '什么时候启动的', kv_cpu: 'CPU / 内存', kv_threads: '线程数 / 状态',
    kv_sigresult: '验签名结果', kv_signer: '签名主体', kv_cn: '证书主体全名',
    kv_notafter: '证书有效期到', kv_size: '文件大小', kv_mtime: '修改时间',
    kv_magic: '文件类型', kv_hash: '指纹（哈希）',

    net_disabled: '这次启动没开启联网检测。',
    net_disabled_short: '联网检测没开启',
    net_phase_live: '正在观察', net_phase_done: '这轮已结束',
    net_meta: '已观察 {e} / {d}（{p}%） · 当前连接 {c} 条 · 连过的地址 {f} 个 · '
            + '能看出规律程度的 {v} 个',
    net_meta_high: '规律程度 ≥85 的 {n} 个', net_meta_susp: '可疑的 {n} 个',
    net_meta_sample: '每 {s} 秒查一次（耗时 {ms} 毫秒）',
    net_meta_estats_ok: '数据量统计 可用', net_meta_estats_no: '数据量统计 不可用',
    net_no_match: '这个筛选条件下没有内容 —— 试试切到「全部」。',
    net_no_traffic: '这段时间没抓到任何联网行为。',
    tag_ioc: '已知木马特征', tag_sf_port: '木马常用端口',
    tag_unsigned: '程序没签名', tag_reslim: '精度不够',
    reg_none: '看不出来', reg_noeval: '数据太少',
    sub_period: '每隔 {v}', sub_jitter: '波动 {v}%',
    conn_stat: '连接 {a} 条 · 连上过 {b} 次 · 传过数据 {c} 次',
    dur_hint: '最慢能看出约 {p} 秒一次的规律（至少要看到 3 次间隔）',
    note_method: '<b>怎么判断的</b>：<b>规律程度</b>是按"每次间隔的波动大小"换算的'
               + '（0–100，越接近 100 越像机器定时打拍子）；<b>危险程度</b>由检查规则判定。'
               + '软件更新、系统上报同样很规律，所以<b>规律不等于有问题</b> —— '
               + '只有"很规律"再加上"程序或目标本身可疑"才会升级成告警。',
    note_streams: '<b>看两个东西</b>：① 每次连上的间隔 —— 能抓住"连上→传数据→断开→再连"'
                + '这种定时报到；② 每次传数据的间隔 —— 能抓住<b>一直连着不挂断、'
                + '但每隔一阵子传一次数据</b>那种（靠系统自带的数据量计数器，不抓包、不解密）。',
    note_estats_off: '<span class="warn">⚠ 数据量统计不可用</span>：{why}。'
                   + '这次只能靠"每次连上的间隔"判断，<b>一直连着的那种可能看不出来</b>；'
                   + '建议右键以管理员身份运行。',
    note_history: '<b>上一轮</b>：{t} 开始看了 {d}，连过的地址 {f} 个，'
                + '规律程度 ≥70 的 {r} 个，严重 {c} / 可疑 {h}。',
    note_bounds: '<b>能看到什么、看不到什么</b>：每 {s} 秒查一次，比这更快的动作可能漏掉；'
               + '只读本机的连接列表和系统自带的数据量计数器，'
               + '<b>不会发出任何网络请求</b>；UDP 看不到对方是谁，所以不参与判断。',
  },
};

let LANG = localStorage.getItem('yinhu-lang') || 'plain';
if (!LANGS[LANG]) LANG = 'plain';

function T(k) {
  const d = LANGS[LANG] || LANGS.plain;
  const v = d[k];
  return (v === undefined ? (LANGS.pro[k] !== undefined ? LANGS.pro[k] : k) : v);
}

/** 带占位符的文案：Tn('st_crit_n', {n: 3}) */
function Tn(k, vars) {
  let s = T(k);
  Object.keys(vars || {}).forEach((x) => { s = s.split('{' + x + '}').join(vars[x]); });
  return s;
}

/* 危险等级的名称随语言切换。
   ⚠️ 大白话版只换说法、**不弱化等级**：critical 仍然是"严重"。
   安全工具里把"严重"说成"可能有点问题"，会让人漏掉真正该立刻处理的事。 */
let LEVEL_ZH = {};
function rebuildLevels() {
  LEVEL_ZH = {
    critical: T('lv_critical'), high: T('lv_high'), medium: T('lv_medium'),
    low: T('lv_low'), clean: T('lv_clean'),
  };
}

/* 系统痕迹的类型名。两版都用中文，只是大白话版更口语。 */
let KIND_ZH = {};
function rebuildKinds() {
  KIND_ZH = LANG === 'plain'
    ? { task: '定时任务', service: '后台服务', driver: '系统底层驱动',
        hosts: '网址对照表', registry: '系统设置库', file: '文件' }
    : { task: '计划任务', service: '系统服务', driver: '内核驱动',
        hosts: 'hosts', registry: '注册表', file: '文件特征' };
}

const LEVEL_ORDER = { critical: 4, high: 3, medium: 2, low: 1, clean: 0 };

/* ------------------------------------------------------------ 规则名的大白话版
   规则号是稳定标识，所以按规则号映射；查不到就回退到原名（新增规则不会显示成空白）。
   这里只换"说法"，不改变规则本身的判断依据。 */
const RULE_PLAIN = {
  P001: '冒用系统程序的名字', P002: '启动它的程序不对劲',
  P002B: '可疑程序挂在系统程序名下', P003: '签名是假的（内容被改过）',
  P004: '用了被冒用的签名', P005: '没签名的程序在联网',
  P006: '程序放在谁都能改的目录里', P007: '程序名是乱敲的',
  P008: '可执行文件伪装成图片之类', P009: '改了杀毒软件的白名单',
  P010: '联网下载后直接运行', P010B: '把命令编码藏起来执行',
  P011: '绕过了脚本执行限制', P012: '偷偷加了开机自动运行（最高权限）',
  P013: '破坏系统恢复/日志/防火墙', P014: '强行关掉安全软件',
  P015: '偷偷加了开机自启项', P016: '连到了已知的木马服务器',
  P017: '没签名的程序连到木马常用端口', P018: '命令里出现木马网址',
  P019: '不是浏览器的程序直连公共 DNS', P020: '程序名是已知木马的文件名',
  P021: '程序放在木马常用的目录结构里', P022: '装在 Program Files 的乱名目录里',
  P024: '程序放在开机启动目录', P025: '可疑程序在开端口等连接',
  T001: '定时任务的名称是已知木马用的', T002: '冒用系统更新的名字',
  T003: '藏起来的高频定时任务', T004: '定时任务跑在可疑目录',
  T005: '定时任务名是一句废话长句', T008: '定时任务偷偷跑脚本且脚本可被替换',
  T006: '最高权限的定时任务跑在可疑目录', T007: '混在系统任务里的非系统任务',
  S001: '后台服务指向已知木马文件', S002: '后台服务指向谁都能改的目录',
  S003: '后台服务指向伪装成图片的文件', S004: '后台服务指向乱名程序',
  D001: '加载了有漏洞的驱动', D002: '驱动名是已知木马用的',
  D003: '驱动放在谁都能改的目录', D004: '驱动伪装成图片之类',
  H001: '安全厂商网址被指向本机', H002: '网址对照表里有可疑条目',
  R001: '杀毒软件把大范围目录排除了', R002: '杀毒软件把木马进程排除了',
  R003: '有木马专用的系统设置项', R004: '开机自启项指向可疑目录',
  R004B: '开机自启项命中已知木马路径', R005: '开机启动目录里有可疑文件',
  F001: '发现伪装成图片的可执行文件', F002: '发现已知木马文件名',
  F003: '发现木马常用的文件组合', X001: '内存里加载了木马模块',
  X002: '内存里加载了伪装的模块', X003: '借正常软件的名义加载了可疑文件',
  N001: '联网很有规律（像定时报到）', N002: '连到了已知的木马服务器',
  N003: '联网规律 + 程序本身已判高风险', N004: '没签名的程序连到木马常用端口',
  N005: '已判高风险的进程正在联网',
};

function ruleTitle(f) {
  if (LANG === 'plain') {
    const p = RULE_PLAIN[f.rule_id];
    if (p) return p;
  }
  return f.title;
}

/* ------------------------------------------------------------ 语言切换 */
/** 填 index.html 里的静态文案：data-t=纯文本，data-th=HTML，data-tph=占位符 */
function applyStaticLang() {
  $$('[data-t]').forEach((el) => { el.textContent = T(el.dataset.t); });
  $$('[data-th]').forEach((el) => { el.innerHTML = T(el.dataset.th); });
  $$('[data-tph]').forEach((el) => { el.placeholder = T(el.dataset.tph); });
  const ah = $('#artHint');
  if (ah) ah.innerHTML = T('art_hint');
  const rh = $('#rulesHint');
  if (rh) {
    const txt = T('rules_hint');
    rh.innerHTML = txt;
    rh.style.display = txt ? '' : 'none';
  }
}

function syncLangToggle() {
  $$('#langSeg button').forEach((b) => b.classList.toggle('on', b.dataset.lang === LANG));
  const btn = $('#langSeg');
  if (btn) btn.title = T('lang_switch');
}

function setLang(l) {
  LANG = LANGS[l] ? l : 'plain';
  try { localStorage.setItem('yinhu-lang', LANG); } catch (e) { /* 隐私模式下忽略 */ }
  rebuildLevels();
  rebuildKinds();
  applyStaticLang();
  syncLangToggle();
  RULES_LOADED = false;          // 规则页的分组标题是前端生成的，要重画
  if (STATE) render();
}


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
  if (!s) return { cls: 'none', mark: '…', txt: T('sig_checking'), cn: '' };
  if (s.kind === 'ok') return { cls: 'ok', mark: '✓', txt: T('sig_ok'), cn: s.cn || s.signer || '' };
  if (s.kind === 'forged') return { cls: 'bad', mark: '⚠', txt: T('sig_forged'), cn: s.cn || '' };
  if (s.kind === 'untrusted') return { cls: 'warn', mark: '⚠', txt: T('sig_untrusted'), cn: s.cn || '' };
  if (s.kind === 'noimage') return { cls: 'none', mark: '·', txt: T('sig_noimage'), cn: T('sig_noimage_tip') };
  if (s.kind === 'packaged') return { cls: 'none', mark: '□', txt: T('sig_packaged'), cn: T('sig_packaged_tip') };
  if (s.kind === 'unsigned') return { cls: 'none', mark: '—', txt: T('sig_unsigned'), cn: '' };
  return { cls: 'none', mark: '?', txt: s.status_zh || T('sig_failed'), cn: s.cn || '' };
}

/* ---------------------------------------------------- 轮询 */
async function poll() {
  try {
    const r = await fetch('/api/state');
    STATE = await r.json();
    render();
  } catch (e) {
    $('#pillStatus').className = 'pill bad';
    $('#pillStatus').innerHTML = `<i class="dot"></i><span>${esc(T('conn_lost'))}</span>`;
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
    pill.innerHTML = `<i class="dot"></i><span>${esc(T('st_changed'))}</span>`;
  } else if (s.scan_count === 0) {
    pill.className = 'pill busy';
    pill.innerHTML = `<i class="dot"></i><span>${esc(T('st_first'))}</span>`;
  } else if (busy) {
    pill.className = 'pill busy';
    pill.innerHTML = `<i class="dot"></i><span>${esc(T('st_scanning'))}</span>`;
  } else if (L.critical > 0) {
    pill.className = 'pill bad';
    pill.innerHTML = `<i class="dot"></i><span>${esc(Tn('st_crit_n', { n: L.critical }))}</span>`;
  } else if (L.high > 0) {
    pill.className = 'pill warn';
    pill.innerHTML = `<i class="dot"></i><span>${esc(Tn('st_high_n', { n: L.high }))}</span>`;
  } else {
    pill.className = 'pill';
    pill.innerHTML = `<i class="dot"></i><span>${esc(T('st_ok'))}</span>`;
  }

  const pa = $('#pillAdmin');
  pa.className = 'pill ' + (s.admin ? '' : 'warn');
  pa.innerHTML = s.admin
    ? `<i class="dot"></i><span>${esc(T('pill_admin_ok'))}</span>`
    : `<i class="dot"></i><span>${esc(T('pill_admin_no'))}</span>`;
  pa.title = s.admin ? T('admin_ok_tip') : T('admin_no_tip');

  $('#pillUptime').innerHTML = `<span>${esc(T('uptime'))} ${fmtUptime(s.uptime)}</span>`;

  /* KPI */
  const netSum = (STATE.net || {}).summary || {};
  const netLv = netSum.levels || {};
  const kpi = [
    ['', s.total, T('kpi_total'), Tn('kpi_total_sub', { ms: s.scan_ms, n: s.scan_count })],
    ['crit', L.critical, T('kpi_crit'), T('kpi_crit_sub')],
    ['high', L.high, T('kpi_high'), T('kpi_high_sub')],
    ['med', L.medium, T('kpi_med'), T('kpi_med_sub')],
    ['', s.artifact_findings, T('kpi_art'),
      Tn('kpi_art_sub', { t: s.tasks, s: s.services, d: s.drivers })],
    ['ok', s.connections, T('kpi_conn'),
      s.sig_pending > 0 ? Tn('kpi_conn_sub_pending', { n: s.sig_pending })
                        : T('kpi_conn_sub_ready')],
  ];
  if (STATE.net) {
    const regN = netSum.regular || 0;
    const badN = (netLv.critical || 0) + (netLv.high || 0);
    kpi.push([badN > 0 ? 'crit' : (regN > 0 ? 'med' : 'ok'), netSum.high_reg || 0,
      T('kpi_reg'),
      badN > 0 ? Tn('kpi_reg_sub_bad', { n: badN }) : Tn('kpi_reg_sub_ok', { n: regN })]);
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

  $('#procInfo').textContent =
    Tn('count_items', { a: list.length, b: STATE.processes.length });

  const rows = list.map((p) => {
    const sv = sigView(p);
    const hits = (p.findings || []).slice(0, 3).map((f) =>
      `<span class="hit ${f.severity}" title="${esc(f.evidence)}">${esc(ruleTitle(f))}</span>`).join('');
    const more = (p.findings || []).length > 3
      ? `<span class="hit">+${p.findings.length - 3}</span>` : '';
    const nc = (p.connections || []).length;
    return `<tr class="${p.level}" data-pid="${p.pid}">
      <td><span class="badge ${p.level}">${LEVEL_ZH[p.level]}</span>
          <span class="score ${p.level}">${p.score}</span></td>
      <td><span class="cname">${esc(p.name)}<small>${esc(p.username || '')}</small></span></td>
      <td class="mono">${p.pid}</td>
      <td><div class="pth" title="${esc(p.exe)}">${esc(p.exe || T('path_unreadable'))}</div></td>
      <td><span class="sig ${sv.cls}">${sv.mark} ${esc(sv.txt)}${sv.cn ? `<small title="${esc(sv.cn)}">${esc(sv.cn)}</small>` : ''}</span></td>
      <td>${nc ? `<span class="netdot"></span> <span class="mono">${nc}</span>` : '<span class="netdot none"></span>'}</td>
      <td><div class="hits">${hits}${more}</div></td>
    </tr>`;
  }).join('');

  $('#procBody').innerHTML = rows ||
    `<tr><td colspan="7" style="text-align:center;padding:34px;color:var(--dim)">
       ${esc(T('no_match'))}</td></tr>`;
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

/** 规律性的"证据来源"是服务端给的中文短语，大白话版换成人话 */
function regSource(s) {
  if (LANG !== 'plain') return s || '';
  if (s === '连接建立间隔') return '每次连上的间隔';
  if (s === '数据突发间隔') return '每次传数据的间隔';
  return s || '';
}

/* 网络页「判断理由」列的文字由服务端（netmon）生成，这里按原句映射成大白话。
   映射不到就原样显示 —— 宁可显示术语，也不能显示空白。 */
const VERDICT_PLAIN = {
  '高度疑似 C2 通道，建议立即处置': '很可能就是木马在跟服务器通信，建议马上处理',
  '疑似 C2 心跳，建议优先核查': '像是木马在定时报到，建议优先确认',
  '存在规律性外联，建议核实': '联网很有规律，建议核实一下',
  '低度可疑，可继续观察': '有点可疑，可以先观察',
  '规律性高但上下文无可疑特征': '联网很规律，但程序本身和目标都正常',
  '未见异常': '没发现问题',
};

function verdictText(v) {
  if (LANG === 'plain' && VERDICT_PLAIN[v]) return VERDICT_PLAIN[v];
  return v || '';
}

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
  return Tn('dur_hint', { p });
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
    $('#netEmptyWhy').textContent = T('net_disabled');
    $('#netProgMeta').textContent = T('net_disabled_short');
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
    ? `<b class="live">${esc(T('net_phase_live'))}</b>`
    : `<b class="fin">${esc(T('net_phase_done'))}</b>`;
  const parts = [
    Tn('net_meta', { e: clockOf(ses.elapsed), d: clockOf(ses.duration), p,
                      c: net.live_conns, f: st.flows || 0, v: st.evaluated || 0 }),
  ];
  if (st.high_reg) parts.push(Tn('net_meta_high', { n: st.high_reg }));
  const badN = (lv.critical || 0) + (lv.high || 0);
  if (badN) parts.push(Tn('net_meta_susp', { n: badN }));
  parts.push(Tn('net_meta_sample', { s: net.sample_interval, ms: net.sample_ms }));
  parts.push(net.estats ? T('net_meta_estats_ok') : T('net_meta_estats_no'));
  $('#netProgMeta').innerHTML =
    `${phaseTxt} · ${esc(parts[0])}` +
    parts.slice(1).map((x) => ` · <b class="hl">${esc(x)}</b>`).join('');

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

  $('#netInfo').textContent =
    Tn('count_items', { a: list.length, b: (net.flows || []).length });
  $('#netEmpty').classList.toggle('show', list.length === 0);
  if (!list.length) {
    $('#netEmptyWhy').textContent = (net.flows || []).length
      ? T('net_no_match') : T('net_no_traffic');
  }

  $('#netBody').innerHTML = list.map((f) => {
    const rc = regClass(f.regularity);
    const chips = (f.findings || []).slice(0, 3).map((x) =>
      `<span class="hit ${x.severity}" title="${esc(x.evidence)}">${esc(ruleTitle(x))}</span>`).join('');
    const tags = [
      `<span class="tag">${esc(f.ip_scope_zh)}</span>`,
      `<span class="tag">${esc((f.proto || '').toUpperCase())}</span>`,
    ];
    if (f.ioc_ip) tags.push(`<span class="tag bad">${esc(T('tag_ioc'))}</span>`);
    if (f.port_class === 'silverfox') tags.push(`<span class="tag bad">${esc(T('tag_sf_port'))}</span>`);
    if (f.proc_untrusted) tags.push(`<span class="tag warn">${esc(T('tag_unsigned'))}</span>`);
    if (f.resolution_limited) tags.push(`<span class="tag dim">${esc(T('tag_reslim'))}</span>`);

    const sub = [];
    if (f.regularity_source) sub.push(esc(regSource(f.regularity_source)));
    if (f.avg_interval != null) sub.push(esc(Tn('sub_period', { v: fmtPeriod(f.avg_interval) })));
    if (f.jitter_pct != null) sub.push(esc(Tn('sub_jitter', { v: f.jitter_pct })));

    return `<tr class="${f.level} netrow${f.regularity != null && f.regularity >= 85 ? ' reg-hi' : ''}"
        data-nkey="${esc(f.key)}">
      <td><span class="badge ${f.level}">${LEVEL_ZH[f.level]}</span>
          <span class="score ${f.level}">${Math.round(f.score)}</span></td>
      <td>
        <div class="regcell ${rc}">
          <div class="regbar"><i style="width:${f.regularity == null ? 0 : f.regularity}%"></i></div>
          <span class="regnum">${regText(f.regularity)}</span>
        </div>
        <div class="regsub">${sub.join(' · ') || (f.note ? esc(f.note) : esc(T('reg_noeval')))}</div>
      </td>
      <td><span class="cname">${esc(f.name)}<small>PID ${f.pid} · ${esc(f.signature_zh)}</small></span></td>
      <td>
        <div class="remote mono">${esc(f.rip)}:${f.rport}</div>
        <div class="rsub">${tags.join('')}</div>
      </td>
      <td>
        <div class="mono bytes">↑${esc(fmtBytes(f.bytes_out))} ↓${esc(fmtBytes(f.bytes_in))}</div>
        <div class="rsub">${esc(Tn('conn_stat', { a: f.live_conns, b: f.conn_events, c: f.byte_events }))}</div>
      </td>
      <td>
        <div class="hits">${chips || `<span class="hit none">${esc(T('no_rule_hit'))}</span>`}</div>
        <div class="verdict">${esc(verdictText(f.verdict))}</div>
      </td>
    </tr>`;
  }).join('');
}

function renderNetNotes(net) {
  const hist = (net.history || [])[0];
  const notes = [T('note_method'), T('note_streams')];
  if (!net.estats) {
    notes.push(Tn('note_estats_off', { why: esc(net.estats_note || '') }));
  }
  if (hist) {
    notes.push(Tn('note_history', {
      t: esc(hist.started_at), d: esc(durLabel(hist.duration)),
      f: hist.flows, r: hist.regular, c: hist.critical, h: hist.high,
    }));
  }
  notes.push(Tn('note_bounds', { s: net.sample_interval }));
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
        <div class="ft"><span class="badge ${f.severity}">${esc(LEVEL_ZH[f.severity] || f.severity_zh)}</span>
          [${esc(f.rule_id)}] ${esc(ruleTitle(f))}</div>
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
      <div class="alarm-rule">[${esc(r.id)}] ${esc(ruleTitle({ rule_id: r.id, title: r.title }))}
        <div class="ev">${esc(r.evidence)}</div>
        ${r.advice ? `<div class="alarm-adv">${esc(r.advice)}</div>` : ''}</div>`).join('');
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
      <h5>${esc(T('wl_title'))}</h5>
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
      }</div>` : '<div class="sub">' + esc(T('wl_none')) + '</div>'}
      <div class="sub" style="margin-top:8px">${T('wl_note')}</div>
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
      <h5>${esc(T('sec_integrity'))}</h5>
      <div class="big">${itIcon} ${esc(it.status_zh || '校验中…')}</div>
      <div class="sub">${Tn('sec_int_sub', {
        n: esc(it.checked || 0), t: esc(it.baseline_time || '—') })}</div>
      <div class="sub" style="margin-top:8px;border-top:1px solid var(--border);padding-top:8px">
        ${Tn('sec_int_self', { pid: esc(sec.self_pid || '—'),
                                n: esc(sec.own_children || 0) })}
      </div>
      ${changed.length ? `<div class="chg">${changed.slice(0, 8).map(esc).join('<br>')}</div>
        <div class="acts"><button class="btn" id="btnAcceptIntegrity">${esc(T('sec_int_btn'))}</button></div>` : ''}
      <div class="sub" style="margin-top:7px">${esc(T('sec_int_note'))}</div>
    </div>

    <div class="seccard info">
      <h5>${esc(T('sec_expose'))}</h5>
      <div class="big">${esc(T('sec_expose_ok'))}</div>
      <div class="sub">${Tn('sec_expose_sub', { a: esc(sec.bind || '—'),
        b: esc(sec.loopback_only ? T('sec_expose_loop') : T('sec_expose_bad')) })}</div>
    </div>

    <div class="seccard">
      <h5>${esc(T('sec_flow'))}</h5>
      <div class="big">${esc(T('sec_flow_ok'))}</div>
      <div class="sub">${Tn('sec_flow_sub', { eg: esc(sec.egress || '') })}</div>
    </div>

    <div class="seccard">
      <h5>${esc(T('sec_write'))}</h5>
      <div class="big">${esc(sec.token_enabled ? T('sec_write_on') : T('sec_write_off'))}</div>
      <div class="sub"><ul>${(sec.post_guards || []).map((g) => `<li>${esc(g)}</li>`).join('')}</ul></div>
      <div class="sub" style="margin-top:7px">${esc(T('sec_write_note'))}</div>
    </div>

    <div class="seccard info">
      <h5>${esc(T('sec_source'))}</h5>
      <div class="big">${esc(Tn('sec_source_big', { n: sec.rule_count || 0,
        v: sec.ioc_version || '' }))}</div>
      <div class="sub">${esc(T('sec_source_sub'))}<ul>${
        (sec.ioc_sources || []).map((s) => `<li>${esc(s)}</li>`).join('')}</ul></div>
    </div>
    ${wlCard}`;

  const b = $('#btnAcceptIntegrity');
  if (b) {
    b.addEventListener('click', async () => {
      const ok = await confirmBox({
        title: T('sec_accept_title'),
        body: T('sec_accept_body'),
        okText: T('sec_accept_ok'),
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
    $('#ruleCount').textContent = Tn('count_items', { a: rr.length, b: rr.length })
      .split(' / ')[0] + ' 条';
    $('#ruleList').innerHTML = rr.map((r) => `
      <div class="rulerow">
        <span class="rid">${esc(r.rule_id)}</span>
        <div>
          <div class="rt"><span class="badge ${r.severity}">${esc(LEVEL_ZH[r.severity] || r.severity_zh)}</span>
            ${esc(ruleTitle({ rule_id: r.rule_id, title: r.title }))}</div>
          <div class="rd">${esc(r.desc)}</div>
        </div>
      </div>`).join('');

    $('#iocVer').textContent = 'v' + ii.version;
    const grp = (key, arr, bad) => arr && arr.length ? `
      <div class="iocgrp"><h4>${esc(T(key))}</h4>
        <div class="items">${arr.map((x) =>
          `<code class="${bad ? 'bad' : ''}">${esc(x)}</code>`).join('')}</div>
      </div>` : '';
    $('#iocBox').innerHTML =
      grp('ioc_domains', ii.domains, true) +
      grp('ioc_ips', ii.ips, true) +
      grp('ioc_ports', ii.ports, true) +
      grp('ioc_filenames', ii.filenames, true) +
      grp('ioc_tasks', ii.task_names, true) +
      grp('ioc_signers', ii.signers, true) +
      grp('ioc_drivers', ii.drivers, true) +
      grp('ioc_hosts', ii.hosts_targets, true) +
      grp('ioc_reg', ii.reg_keys, true) +
      `<div class="iocgrp"><h4>${esc(T('ioc_sources'))}</h4>
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
  $('#dName').textContent = T('d_loading');
  $('#dSub').textContent = '';
  $('#dBody').innerHTML = `<div style="color:var(--dim);padding:22px 0">${esc(T('d_reading'))}</div>`;
  let d;
  try {
    d = await fetch('/api/detail?pid=' + pid).then((r) => r.json());
  } catch (e) {
    $('#dBody').innerHTML = `<div style="color:var(--crit)">${esc(T('d_readfail'))}</div>`;
    return;
  }
  if (d.error) { $('#dName').textContent = d.error; $('#dBody').innerHTML = ''; return; }

  const p = d.process, h = d.hashes || {}, dt = d.detail || {};
  $('#dName').textContent = p.name;
  $('#dSub').textContent = p.exe || T('d_path_unreadable');

  const findHtml = (p.findings || []).map((f) => `
    <div class="dfind ${f.severity}">
      <div class="ft"><span class="badge ${f.severity}">${esc(LEVEL_ZH[f.severity] || f.severity_zh)}</span>
        [${esc(f.rule_id)}] ${esc(ruleTitle(f))}</div>
      <div class="ev">${esc(f.evidence)}</div>
      ${f.advice ? `<div class="ad">${esc(f.advice)}</div>` : ''}
      <div class="facts">
        <button class="btn mini" data-known="${esc(f.rule_id)}" data-pid="${p.pid}">
          ${esc(T('act_known'))}</button>
        <span class="knownhint">${esc(T('known_hint'))}</span>
      </div>
    </div>`).join('') || `<div style="color:var(--ok);font-size:12.5px">${esc(T('no_rule_hit'))}</div>`;

  const chainHtml = (d.chain || []).map((c, i) => `
    ${i ? `<div class="arrow">${esc(T('chain_parent'))}</div>` : ''}
    <div class="node ${i === 0 ? 'cur' : ''}">
      <span class="pid">${c.pid}</span><b>${esc(c.name)}</b>
      <span class="px" title="${esc(c.exe)}">${esc(c.exe)}</span>
    </div>`).join('');

  const conns = (p.connections || []);
  const connHtml = conns.length ? conns.map((c) => `
    <div class="connrow"><span class="st">${esc(c.status || '')}</span>
      <span>${esc(c.laddr || '')} → ${esc(c.raddr || '—')}</span></div>`).join('')
    : `<div style="color:var(--dim);font-size:12px">${esc(T('no_conn'))}</div>`;

  const mods = (dt.modules || []);
  const modHtml = mods.length
    ? mods.slice(0, 60).map((m) => `<div class="modrow">${esc(m.path)}</div>`).join('')
      + (mods.length > 60
          ? `<div class="modrow" style="color:var(--dim)">${esc(Tn('d_more_mods', { n: mods.length - 60 }))}</div>`
          : '')
    : `<div style="color:var(--dim);font-size:12px">${esc(dt.error || T('d_no_mods'))}</div>`;

  const sv = sigView(p);
  const startT = p.create_time ? new Date(p.create_time * 1000).toLocaleString('zh-CN') : '—';

  $('#dBody').innerHTML = `
    <div class="dsec">
      <h4>${esc(Tn('d_sec_rules_n', { n: (p.findings || []).length }))}</h4>
      ${findHtml}
    </div>

    <div class="dsec">
      <h4>${esc(T('d_actions'))}</h4>
      <div class="dact">
        <button class="btn" data-act="open" data-path="${esc(p.exe)}">${esc(T('act_open'))}</button>
        <button class="btn" data-act="copy" data-path="${esc(p.exe)}">${esc(T('act_copy'))}</button>
        ${p.pid > 4 ? `<button class="btn danger" data-act="kill" data-pid="${p.pid}"
          data-name="${esc(p.name)}">${esc(T('act_kill'))}</button>` : ''}
      </div>
    </div>

    <div class="dsec">
      <h4>${esc(T('d_basic'))}</h4>
      <dl class="kv">
        <dt>${esc(T('kv_pid'))}</dt><dd>${p.pid} / ${p.ppid || '—'}</dd>
        <dt>${esc(T('kv_parent'))}</dt><dd>${esc(p.parent_name || '—')}</dd>
        <dt>${esc(T('kv_user'))}</dt><dd>${esc(p.username || '—')}</dd>
        <dt>${esc(T('kv_start'))}</dt><dd>${esc(startT)}</dd>
        <dt>${esc(T('kv_cpu'))}</dt><dd>${p.cpu}% / ${p.rss_mb} MB</dd>
        <dt>${esc(T('kv_threads'))}</dt><dd>${dt.threads || '—'} / ${esc(dt.status || '—')}</dd>
      </dl>
    </div>

    <div class="dsec">
      <h4>${esc(T('d_cmd'))}</h4>
      <div class="modrow" style="white-space:pre-wrap">${
        esc(p.cmdline_str || (p.cmdline_denied
          ? T('d_cmd_denied')
          : (p.cmdline_loaded ? T('d_cmd_unreadable') : T('d_cmd_pending'))))}</div>
    </div>

    <div class="dsec">
      <h4>${esc(T('d_chain'))}</h4>
      <div class="chain">${chainHtml || '<div style="color:var(--dim);font-size:12px">—</div>'}</div>
    </div>

    <div class="dsec">
      <h4>${esc(T('d_sig'))}</h4>
      <dl class="kv">
        <dt>${esc(T('kv_sigresult'))}</dt><dd><span class="sig ${sv.cls}">${sv.mark} ${esc(sv.txt)}</span></dd>
        <dt>${esc(T('kv_signer'))}</dt><dd>${esc(sv.cn || '—')}</dd>
        <dt>${esc(T('kv_cn'))}</dt><dd>${esc((p.signature || {}).signer || '—')}</dd>
        <dt>${esc(T('kv_notafter'))}</dt><dd>${esc((p.signature || {}).notafter || '—')}</dd>
      </dl>
    </div>

    <div class="dsec">
      <h4>${esc(T('d_file'))}</h4>
      <dl class="kv">
        <dt>${esc(T('kv_size'))}</dt><dd>${h.size ? (h.size / 1048576).toFixed(2) + ' MB' : '—'}</dd>
        <dt>${esc(T('kv_mtime'))}</dt><dd>${esc(h.mtime || '—')}</dd>
        <dt>${esc(T('kv_magic'))}</dt><dd>${esc(h.magic || '—')}</dd>
        <dt>MD5</dt><dd>${esc(h.md5 || '—')}</dd>
        <dt>SHA-256</dt><dd>${esc(h.sha256 || '—')}</dd>
      </dl>
    </div>

    <div class="dsec">
      <h4>${esc(Tn('d_sec_net_n', { n: conns.length }))}</h4>
      <div class="connlist">${connHtml}</div>
    </div>

    <div class="dsec">
      <h4>${esc(Tn('d_sec_mods_n', { n: mods.length }))}</h4>
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

  /* 语言初始化：先把静态文案按当前语言填好，再开始渲染 */
  rebuildLevels();
  rebuildKinds();
  applyStaticLang();
  syncLangToggle();
  $$('#langSeg button').forEach((b) => b.addEventListener('click', () => {
    setLang(b.dataset.lang);
  }));

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
