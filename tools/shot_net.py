# -*- coding: utf-8 -*-
"""网络监控界面质检：Playwright 无头浏览器逐屏截图 + 控制台错误捕获 + DOM 断言。"""
from __future__ import annotations

import os
import sys

from playwright.sync_api import sync_playwright

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8891
URL = f"http://127.0.0.1:{PORT}/"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shots_net")
os.makedirs(OUT, exist_ok=True)

PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'OK ' if cond else 'XX '} {name}" + (f"   {extra}" if extra else ""))


with sync_playwright() as p:
    b = p.chromium.launch(headless=True, args=["--no-proxy-server",
                                                "--disable-features=Translate"])
    pg = b.new_page(viewport={"width": 1560, "height": 1000}, device_scale_factor=1.25)
    errs, warns = [], []
    pg.on("console", lambda m: (errs if m.type == "error" else warns).append(m.text))
    pg.on("pageerror", lambda e: errs.append(str(e)))
    pg.goto(URL, wait_until="networkidle")
    pg.wait_for_timeout(3200)

    # ---- 切到网络监控
    pg.click('.tab[data-tab="net"]')
    pg.wait_for_timeout(700)

    check("网络 tab 存在且可切换", pg.is_visible("#pane-net"))
    check("滑块存在", pg.is_visible("#netSlider"))
    n_ticks = pg.eval_on_selector_all("#netTicks span", "els => els.length")
    check("滑块档位数 = 7", n_ticks == 7, f"实际 {n_ticks}")
    check("档位标签正确",
          pg.eval_on_selector("#netTicks", "e => e.textContent").replace(" ", "")
          == "30秒1分钟2分钟3分钟5分钟10分钟15分钟",
          pg.eval_on_selector("#netTicks", "e => e.textContent"))
    dur = pg.inner_text("#netDurVal")
    check("时长显示已同步服务端（5 分钟）", dur == "5 分钟", dur)
    check("时长提示已渲染", "可识别" in pg.inner_text("#netDurHint"))
    check("进度条有宽度", pg.eval_on_selector("#netBar", "e => e.style.width") != "0%",
          pg.eval_on_selector("#netBar", "e => e.style.width"))
    check("进度元信息含采样与 estats",
          "采样" in pg.inner_text("#netProgMeta") and "字节统计" in pg.inner_text("#netProgMeta"),
          pg.inner_text("#netProgMeta")[:90])
    pg.screenshot(path=os.path.join(OUT, "01-网络监控-重点关注.png"))

    # ---- 表格内容
    rows = pg.eval_on_selector_all("#netBody tr", "els => els.length")
    check("重点关注下渲染出流量行", rows >= 4, f"{rows} 行")
    check("存在金色高亮行（规律性 ≥85）",
          pg.eval_on_selector_all("#netBody tr.reg-hi", "els => els.length") >= 2,
          f"{pg.eval_on_selector_all('#netBody tr.reg-hi', 'els => els.length')} 行")
    check("规律性进度条已渲染",
          pg.eval_on_selector_all("#netBody .regbar i", "els => els.length") >= 4)
    check("规律性数字存在", pg.eval_on_selector_all("#netBody .regnum", "els => els.length") >= 4)
    check("IOC 标签存在",
          pg.eval_on_selector_all("#netBody .tag.bad", "els => els.length") >= 2)
    check("未签名标签存在",
          pg.eval_on_selector_all("#netBody .tag.warn", "els => els.length") >= 1)
    check("命中规则芯片存在",
          pg.eval_on_selector_all("#netBody .hit", "els => els.length") >= 4)
    check("判定文字存在", pg.inner_text("#netBody").count("疑似") >= 1)
    check("表头可点击排序标记", pg.eval_on_selector_all("#netTable thead th[data-nsort]", "e => e.length") == 5)

    # ---- 过滤切换
    pg.click('#segNet button[data-nf="regular"]')
    pg.wait_for_timeout(400)
    n_reg = pg.eval_on_selector_all("#netBody tr", "els => els.length")
    check("仅高规律过滤生效", 0 < n_reg < rows, f"{n_reg} / {rows}")
    pg.screenshot(path=os.path.join(OUT, "02-仅高规律.png"))

    pg.click('#segNet button[data-nf="risky"]')
    pg.wait_for_timeout(400)
    n_risk = pg.eval_on_selector_all("#netBody tr", "els => els.length")
    check("仅可疑过滤生效", 0 < n_risk <= rows, f"{n_risk} 行")
    pg.screenshot(path=os.path.join(OUT, "03-仅可疑.png"))

    pg.click('#segNet button[data-nf="all"]')
    pg.wait_for_timeout(400)
    n_all = pg.eval_on_selector_all("#netBody tr", "els => els.length")
    check("全部过滤显示 8 条", n_all == 8, f"{n_all} 行")

    # 搜索
    pg.fill("#netQ", "8.218")
    pg.wait_for_timeout(400)
    n_q = pg.eval_on_selector_all("#netBody tr", "els => els.length")
    check("搜索按远端 IP 过滤", n_q == 1, f"{n_q} 行")
    pg.fill("#netQ", "")
    pg.wait_for_timeout(300)

    pg.click('#segNet button[data-nf="focus"]')
    pg.wait_for_timeout(400)

    # ---- 详情抽屉（银狐场景）
    pg.click('#netBody tr[data-nkey="6312|tcp4|8.218.106.149|443"]')
    pg.wait_for_timeout(1200)
    check("详情抽屉打开", pg.is_visible("#drawer"))
    dname = pg.inner_text("#dName")
    check("抽屉标题正确", "Pl6VgrWG.exe" in dname and "8.218.106.149" in dname, dname)
    check("结论卡渲染", pg.is_visible(".netverdict"))
    check("结论卡含风险分与规律性",
          "风险分" in pg.inner_text(".netverdict") and "规律性" in pg.inner_text(".netverdict"))
    n_svg = pg.eval_on_selector_all("#dBody svg.spark", "els => els.length")
    check("周期性直方图已渲染（2 张）", n_svg >= 3, f"{n_svg} 张 SVG")
    check("间隔序列图含平均虚线",
          pg.eval_on_selector_all("#dBody svg.spark line", "els => els.length") >= 1)
    check("命中规则 3 条", pg.eval_on_selector_all("#dBody .dfind", "els => els.length") == 3,
          f"{pg.eval_on_selector_all('#dBody .dfind', 'els => els.length')} 条")
    dbody = pg.inner_text("#dBody")
    for kw in ("远端端点", "本机进程", "观测统计", "命中 C2 清单", "静默比例"):
        check(f"详情含「{kw}」", kw in dbody)
    pg.screenshot(path=os.path.join(OUT, "04-详情-银狐C2心跳.png"))
    pg.eval_on_selector("#dBody", "e => e.scrollTop = e.scrollHeight")
    pg.wait_for_timeout(300)
    pg.screenshot(path=os.path.join(OUT, "05-详情-下半部.png"))
    pg.click("#dClose")
    pg.wait_for_timeout(400)

    # ---- 详情：良性高规律（验证"规律性≠恶意"的呈现）
    pg.click('#netBody tr[data-nkey="1044|tcp4|4.145.79.82|443"]')
    pg.wait_for_timeout(1100)
    bbody = pg.inner_text("#dBody")
    check("良性场景显示「规律性高但上下文无可疑特征」",
          "规律性高但上下文无可疑特征" in bbody)
    check("良性场景命中规则为 0", pg.eval_on_selector_all("#dBody .dfind", "els => els.length") == 0)
    pg.screenshot(path=os.path.join(OUT, "06-详情-良性高规律.png"))
    pg.click("#dClose")
    pg.wait_for_timeout(300)

    # ---- 详情：不可评估（长连接）
    pg.click('#segNet button[data-nf="all"]')
    pg.wait_for_timeout(400)
    pg.click('#netBody tr[data-nkey="5176|tcp4|180.111.196.240|443"]')
    pg.wait_for_timeout(1100)
    dbody = pg.inner_text("#dBody")
    check("不可评估场景给出明确说明", "无时间结构可分析" in dbody or "样本不足" in dbody)
    check("不可评估时规律性显示为「—」", "—" in pg.inner_text(".nvreg"))
    pg.screenshot(path=os.path.join(OUT, "07-详情-不可评估.png"))
    pg.click("#dClose")
    pg.wait_for_timeout(300)

    # ---- 滑块拖动（真实交互）
    pg.click('#segNet button[data-nf="focus"]')
    pg.wait_for_timeout(300)
    box = pg.eval_on_selector("#netSlider", "e => {const r=e.getBoundingClientRect();return {x:r.x,y:r.y,w:r.width,h:r.height}}")
    pg.mouse.move(box["x"] + 4, box["y"] + box["h"] / 2)
    pg.mouse.down()
    pg.mouse.move(box["x"] + box["w"] * 0.95, box["y"] + box["h"] / 2, steps=12)
    pg.mouse.up()
    pg.wait_for_timeout(1200)
    dur2 = pg.inner_text("#netDurVal")
    check("拖动滑块改变了时长", dur2 == "15 分钟", dur2)
    check("填充变量已更新",
          pg.eval_on_selector("#netSlider", "e => e.style.getPropertyValue('--fill')") != "0%",
          pg.eval_on_selector("#netSlider", "e => e.style.getPropertyValue('--fill')"))
    check("对应档位标签高亮",
          pg.eval_on_selector_all("#netTicks span.on", "els => els.length") == 1)
    pg.screenshot(path=os.path.join(OUT, "08-滑块拖到15分钟.png"))

    # ---- 其它页面未被破坏
    pg.click('.tab[data-tab="proc"]')
    pg.wait_for_timeout(900)
    check("进程页仍正常渲染", pg.eval_on_selector_all("#procBody tr", "els => els.length") > 5)
    pg.screenshot(path=os.path.join(OUT, "09-进程页回归.png"))
    pg.click('.tab[data-tab="rules"]')
    pg.wait_for_timeout(1400)
    check("规则页含 N 系列规则", "N001" in pg.inner_text("#ruleList"),
          "N001" in pg.inner_text("#ruleList") and "N002" in pg.inner_text("#ruleList") and "")
    pg.screenshot(path=os.path.join(OUT, "10-规则页含N系列.png"))

    check("浏览器控制台无错误", not errs, " | ".join(errs[:4]))
    if warns:
        print(f"  （提示：{len(warns)} 条 console warning，前 3 条：{warns[:3]}）")

    b.close()

print()
print("=" * 70)
print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
for f in FAIL:
    print("  x " + f)
print(f"截图目录：{OUT}")
print("=" * 70)
sys.exit(1 if FAIL else 0)
