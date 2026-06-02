#!/usr/bin/env python3
# governance-dashboard.py — 把 dep-policy 白名單的「健康度」彙整成自包含 HTML 儀表板。
#
# 內容：
#   1. 白名單總覽（maven / npm 核可數）
#   2. ⭐ 持續重掃：當初核可、現在才爆 CVE 的套件（OSV batch 查）
#   3. 即將到期 / 已過期的核可（entry 的 expires_at）
#   4. 完整核可清單（含 approved_at / approved_by）
#
# 設計：報告器不是 gate——OSV 查不到就標 N/A，不讓 dashboard 掛掉。
# 用法：python3 scripts/governance-dashboard.py [--out public]

import sys, os, json, html, datetime, urllib.request, urllib.error
import yaml

OUT = "public"
if "--out" in sys.argv:
    OUT = sys.argv[sys.argv.index("--out") + 1]

FILES = {"maven": "maven-approved.yaml", "npm": "npm-approved.yaml"}
OSV_BATCH = "https://api.osv.dev/v1/querybatch"


def load(path):
    if not os.path.exists(path):
        return []
    d = yaml.safe_load(open(path)) or {}
    return d.get("approved", []) or []


def parse_coord(coord, kind):
    if kind == "npm":
        name, _, ver = coord.rpartition("@")
        return name, ver, "npm"
    else:
        parts = coord.split(":")
        if len(parts) >= 3:
            return f"{parts[0]}:{parts[1]}", parts[-1], "Maven"
        return coord, "", "Maven"


def osv_batch(queries):
    body = json.dumps({"queries": [
        {"package": {"name": n, "ecosystem": e}, "version": v} for (n, v, e) in queries
    ]}).encode()
    req = urllib.request.Request(OSV_BATCH, data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            res = json.load(r).get("results", [])
        return [[v.get("id") for v in (item.get("vulns") or [])] for item in res]
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None


def days_until(date_str):
    try:
        d = datetime.date.fromisoformat(str(date_str)[:10])
        return (d - datetime.date.today()).days
    except Exception:
        return None


entries = []
for kind, path in FILES.items():
    for it in load(path):
        coord = it.get("coord")
        if not coord:
            continue
        n, v, eco = parse_coord(coord, kind)
        entries.append({
            "coord": coord, "kind": kind, "eco": eco, "name": n, "ver": v,
            "approved_at": it.get("approved_at", "—"),
            "approved_by": it.get("approved_by", "—"),
            "expires_at": it.get("expires_at"), "vulns": None,
        })

queries = [(e["name"], e["ver"], e["eco"]) for e in entries]
osv_ok = True
for i in range(0, len(queries), 200):
    res = osv_batch(queries[i:i + 200])
    if res is None:
        osv_ok = False
        break
    for j, vulns in enumerate(res):
        entries[i + j]["vulns"] = vulns

n_maven = sum(1 for e in entries if e["kind"] == "maven")
n_npm = sum(1 for e in entries if e["kind"] == "npm")
vulnerable = [e for e in entries if e["vulns"]]
expiring = [e for e in entries if e["expires_at"] is not None and
            (days_until(e["expires_at"]) is not None and days_until(e["expires_at"]) <= 90)]
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
pipeline = os.environ.get("GITHUB_RUN_ID", "local")


def esc(s):
    return html.escape(str(s))


def rows_vuln():
    if not osv_ok:
        return '<tr><td colspan="5" class="warn">OSV 查詢失敗 — 重掃結果暫不可用（N/A）</td></tr>'
    if not vulnerable:
        return '<tr><td colspan="5" class="ok">✅ 目前核可清單內沒有任何已知 CVE</td></tr>'
    out = []
    for e in sorted(vulnerable, key=lambda x: -len(x["vulns"])):
        ids = " ".join(f'<code>{esc(v)}</code>' for v in e["vulns"][:6])
        more = f' +{len(e["vulns"])-6}' if len(e["vulns"]) > 6 else ""
        out.append(f'<tr><td><code>{esc(e["coord"])}</code></td><td>{esc(e["eco"])}</td>'
                   f'<td class="bad">{len(e["vulns"])}</td><td>{ids}{more}</td>'
                   f'<td>{esc(e["approved_at"])} / {esc(e["approved_by"])}</td></tr>')
    return "\n".join(out)


def rows_expiring():
    if not expiring:
        return '<tr><td colspan="3" class="ok">無 90 天內到期的核可</td></tr>'
    out = []
    for e in sorted(expiring, key=lambda x: days_until(x["expires_at"]) or 0):
        d = days_until(e["expires_at"])
        cls = "bad" if d is not None and d < 0 else "warn"
        label = f'已過期 {-d} 天' if d is not None and d < 0 else f'{d} 天後到期'
        out.append(f'<tr><td><code>{esc(e["coord"])}</code></td>'
                   f'<td>{esc(e["expires_at"])}</td><td class="{cls}">{label}</td></tr>')
    return "\n".join(out)


def rows_all():
    out = []
    for e in sorted(entries, key=lambda x: (x["kind"], x["coord"])):
        flag = '<span class="bad">⚠ CVE</span>' if e["vulns"] else (
            '<span class="warn">N/A</span>' if not osv_ok else '<span class="ok">✓</span>')
        out.append(f'<tr><td><code>{esc(e["coord"])}</code></td><td>{esc(e["kind"])}</td>'
                   f'<td>{flag}</td><td>{esc(e["approved_at"])}</td><td>{esc(e["approved_by"])}</td></tr>')
    return "\n".join(out)


os.makedirs(OUT, exist_ok=True)
HTML = f"""<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>依賴治理儀表板 — dep-policy</title>
<style>
 :root{{--ok:#1a7f37;--warn:#9a6700;--bad:#cf222e;--ink:#1f2328;--line:#d0d7de}}
 *{{box-sizing:border-box}}
 body{{font:14px/1.55 -apple-system,Segoe UI,Roboto,"Noto Sans CJK TC",sans-serif;color:var(--ink);margin:0;background:#f6f8fa}}
 .wrap{{max-width:1000px;margin:0 auto;padding:28px 24px}}
 h1{{font-size:21px;margin:0 0 4px}} .sub{{color:#57606a;margin:0 0 20px}}
 h2{{font-size:15px;border-bottom:2px solid var(--line);padding-bottom:5px;margin:28px 0 12px}}
 .cards{{display:flex;gap:14px;flex-wrap:wrap}}
 .card{{flex:1;min-width:150px;background:#fff;border:1px solid var(--line);border-radius:8px;padding:14px}}
 .card .n{{font-size:26px;font-weight:700}} .card .l{{color:#57606a;font-size:12px}}
 table{{border-collapse:collapse;width:100%;background:#fff}}
 th,td{{border:1px solid var(--line);padding:7px 10px;text-align:left;vertical-align:top}}
 th{{background:#f6f8fa}} code{{background:#eff1f3;padding:1px 5px;border-radius:4px;font-size:12px}}
 .ok{{color:var(--ok);font-weight:700}} .warn{{color:var(--warn);font-weight:700}} .bad{{color:var(--bad);font-weight:700}}
 details{{margin-top:8px}} summary{{cursor:pointer;color:#57606a}}
 footer{{color:#57606a;margin-top:32px;font-size:12px;border-top:1px solid var(--line);padding-top:12px}}
</style></head><body><div class="wrap">
<h1>依賴治理儀表板</h1>
<p class="sub">dep-policy 白名單的健康度 · 持續重掃「核可後才爆的 CVE」· 每次 push 更新</p>
<div class="cards">
 <div class="card"><div class="n">{n_maven + n_npm}</div><div class="l">核可套件總數（maven {n_maven} / npm {n_npm}）</div></div>
 <div class="card"><div class="n {'bad' if vulnerable else 'ok'}">{len(vulnerable) if osv_ok else 'N/A'}</div><div class="l">現在有已知 CVE 的核可套件</div></div>
 <div class="card"><div class="n {'warn' if expiring else 'ok'}">{len(expiring)}</div><div class="l">90 天內到期 / 已過期的核可</div></div>
</div>
<h2>⚠️ 持續重掃：核可後才爆 CVE 的套件</h2>
<p class="sub">當初審核時乾淨，OSV 現在查到漏洞——該優先處理 / re-review。</p>
<table><thead><tr><th>coord</th><th>生態</th><th>CVE 數</th><th>CVE</th><th>核可（日期/人）</th></tr></thead>
<tbody>
{rows_vuln()}
</tbody></table>
<h2>⏳ 即將到期 / 已過期的核可</h2>
<table><thead><tr><th>coord</th><th>expires_at</th><th>狀態</th></tr></thead><tbody>
{rows_expiring()}
</tbody></table>
<h2>📋 完整核可清單</h2>
<details><summary>展開 {n_maven + n_npm} 筆</summary>
<table><thead><tr><th>coord</th><th>生態</th><th>狀態</th><th>approved_at</th><th>approved_by</th></tr></thead><tbody>
{rows_all()}
</tbody></table>
</details>
<footer>Generated by <code>scripts/governance-dashboard.py</code> · {now} · run {esc(pipeline)} ·
資料源：OSV.dev + dep-policy allow-list · 自包含單檔</footer>
</div></body></html>"""

open(os.path.join(OUT, "index.html"), "w").write(HTML)
print(f"governance dashboard → {OUT}/index.html "
      f"(approved={n_maven+n_npm}, vulnerable={len(vulnerable) if osv_ok else 'N/A'}, expiring={len(expiring)})")
