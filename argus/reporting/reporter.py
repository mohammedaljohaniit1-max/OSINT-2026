"""
Professional report generation: JSON, Markdown, HTML (self-contained), GEXF graph.

The HTML report is a single dark-themed file: executive summary, risk gauge,
findings grouped by type, evidence tables, and an interactive relationship
graph (vis-network via CDN, with an offline fallback list).
"""
from __future__ import annotations

import html
import json
import time
from pathlib import Path

from ..core.models import EntityType, IntelGraph, RiskLevel

RISK_COLORS = {
    "critical": "#ff3b3b", "high": "#ff8c00", "medium": "#ffd000",
    "low": "#4da3ff", "info": "#8a8f98",
}


def _slug(target: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in target)[:40]


def write_reports(graph: IntelGraph, outdir: str = "reports") -> dict:
    Path(outdir).mkdir(parents=True, exist_ok=True)
    target = graph.run_meta.get("target", "scan")
    stamp = time.strftime("%Y%m%d_%H%M%S")
    base = f"{outdir}/argus_{_slug(target)}_{stamp}"

    paths = {}
    # JSON
    with open(base + ".json", "w") as f:
        json.dump(graph.to_dict(), f, indent=2, default=str)
    paths["json"] = base + ".json"
    # Markdown
    with open(base + ".md", "w") as f:
        f.write(_markdown(graph))
    paths["markdown"] = base + ".md"
    # HTML
    with open(base + ".html", "w") as f:
        f.write(_html(graph))
    paths["html"] = base + ".html"
    # GEXF graph
    with open(base + ".gexf", "w") as f:
        f.write(_gexf(graph))
    paths["gexf"] = base + ".gexf"
    return paths


# --------------------------------------------------------------------------- #
def _sorted_entities(graph):
    return sorted(graph.entities.values(),
                  key=lambda e: (-e.risk.score, -e.confidence))


def _markdown(graph: IntelGraph) -> str:
    m = graph.run_meta
    st = graph.stats()
    out = [f"# Argus OSINT Report — {m.get('target')}", ""]
    out.append(f"- **Target type:** {m.get('target_type')}")
    out.append(f"- **Profile:** {m.get('profile')}")
    out.append(f"- **Duration:** {m.get('duration')}s")
    out.append(f"- **Entities:** {st['total_entities']}  |  "
               f"**Relationships:** {st['total_relationships']}")
    out.append("")
    out.append("## Risk Summary")
    for r in ("critical", "high", "medium", "low", "info"):
        if st["by_risk"].get(r):
            out.append(f"- **{r.upper()}**: {st['by_risk'][r]}")
    out.append("")
    # critical/high first
    out.append("## Key Findings (Critical / High)")
    for e in _sorted_entities(graph):
        if e.risk.score >= RiskLevel.HIGH.score:
            out.append(f"- `[{e.risk.value.upper()}]` **{e.type.value}** "
                       f"`{e.value}` (conf {e.confidence:.0%}, "
                       f"sources: {', '.join(sorted(e.sources))})")
    out.append("")
    out.append("## All Findings by Type")
    for etype in EntityType:
        ents = graph.by_type(etype)
        if not ents:
            continue
        out.append(f"### {etype.value} ({len(ents)})")
        for e in sorted(ents, key=lambda x: -x.confidence)[:200]:
            out.append(f"- `{e.value}` — {e.risk.value}, {e.confidence:.0%}")
        out.append("")
    return "\n".join(out)


def _gexf(graph: IntelGraph) -> str:
    nodes = []
    for e in graph.entities.values():
        nodes.append(
            f'<node id="{e.id}" label="{html.escape(e.value[:40])}">'
            f'<attvalues><attvalue for="0" value="{e.type.value}"/>'
            f'<attvalue for="1" value="{e.risk.value}"/></attvalues></node>')
    edges = []
    for i, r in enumerate(graph.relationships.values()):
        edges.append(f'<edge id="{i}" source="{r.src_id}" target="{r.dst_id}" '
                     f'label="{r.rel_type}"/>')
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<gexf xmlns="http://gexf.net/1.3" version="1.3"><graph defaultedgetype="directed">
<attributes class="node"><attribute id="0" title="type" type="string"/>
<attribute id="1" title="risk" type="string"/></attributes>
<nodes>{''.join(nodes)}</nodes><edges>{''.join(edges)}</edges></graph></gexf>"""


_VERDICT_COLOR = {"confirmed": "#2ecc71", "likely": "#f1c40f",
                  "possible": "#e67e22", "rejected": "#7f8c8d"}


def _persona_section(graph: IntelGraph) -> str:
    """Render the person-investigation block: unified personas, each with its
    ranked accounts, geo verdict, and the explainable reasons per account.
    Returns '' when the scan was not a person search."""
    personas = graph.by_type(EntityType.PERSONA)
    pmeta = graph.run_meta.get("persona")
    if not personas and not pmeta:
        return ""

    ctx = ""
    if pmeta:
        ctx = (f'<div class="pctx">'
               f'<b>{html.escape(str(pmeta.get("name","")))}</b>'
               f' &nbsp;·&nbsp; Country: {html.escape(str(pmeta.get("country") or "—"))}'
               f' &nbsp;·&nbsp; City: <b>{html.escape(str(pmeta.get("city") or "—"))}</b>'
               f' &nbsp;·&nbsp; handles tried: {len(pmeta.get("handles_tried", []))}'
               f'</div>')

    cards = ""
    # sort personas: confirmed first, then by aggregate score
    def _key(p):
        v = p.metadata.get("verdict", "possible")
        order = {"confirmed": 0, "likely": 1, "possible": 2, "rejected": 3}
        return (order.get(v, 4), -p.metadata.get("aggregate_score", 0))

    for p in sorted(personas, key=_key):
        md = p.metadata
        v = md.get("verdict", "possible")
        col = _VERDICT_COLOR.get(v, "#888")
        accts = md.get("accounts", [])
        rows = ""
        for a in accts:
            reasons = "<br>".join("· " + html.escape(str(r)) for r in a.get("reasons", [])[:4])
            rows += (
                f'<tr><td><a href="{html.escape(a["url"])}" target="_blank" '
                f'style="color:#4da3ff">{html.escape(a["platform"])}</a></td>'
                f'<td class="val">{html.escape(a.get("handle",""))}</td>'
                f'<td>{html.escape(a.get("display_name","") or "—")}</td>'
                f'<td>{html.escape(a.get("location","") or "—")}</td>'
                f'<td><b style="color:{_VERDICT_COLOR.get(a.get("verdict"),"#888")}">'
                f'{a.get("score",0)}</b></td>'
                f'<td class="src">{reasons}</td></tr>')
        cards += (
            f'<div class="persona" style="border-color:{col}">'
            f'<div class="ph"><span class="verdict" style="background:{col}">'
            f'{v.upper()}</span> <b>{html.escape(md.get("name",""))}</b>'
            f' <span class="pscore">score {md.get("aggregate_score",0)}</span>'
            f' <span class="pcount">{md.get("account_count",0)} account(s)</span></div>'
            f'<table class="patbl"><thead><tr><th>Platform</th><th>Handle</th>'
            f'<th>Name</th><th>Location</th><th>Score</th><th>Why</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>')

    if not cards:
        cards = '<div class="pctx">No matching accounts confirmed in the target city.</div>'

    return (f'<h2>🧭 Persona Investigation</h2>{ctx}'
            f'<div class="personas">{cards}</div>')


def _html(graph: IntelGraph) -> str:
    m = graph.run_meta
    st = graph.stats()
    # risk cards
    cards = ""
    for r in ("critical", "high", "medium", "low", "info"):
        n = st["by_risk"].get(r, 0)
        cards += (f'<div class="card" style="border-color:{RISK_COLORS[r]}">'
                  f'<div class="num" style="color:{RISK_COLORS[r]}">{n}</div>'
                  f'<div class="lbl">{r.upper()}</div></div>')
    # findings rows
    rows = ""
    for e in _sorted_entities(graph):
        srcs = ", ".join(sorted(e.sources))
        evid = ""
        if e.evidence:
            ev0 = e.evidence[0]
            evid = html.escape((ev0.url or ev0.snippet or "")[:80])
        rows += (f'<tr class="r-{e.risk.value}">'
                 f'<td><span class="pill" style="background:{RISK_COLORS[e.risk.value]}">'
                 f'{e.risk.value.upper()}</span></td>'
                 f'<td>{e.type.value}</td>'
                 f'<td class="val">{html.escape(e.value[:90])}</td>'
                 f'<td>{e.confidence:.0%}</td>'
                 f'<td class="src">{html.escape(srcs[:60])}</td>'
                 f'<td class="src">{evid}</td></tr>')
    # graph data
    gnodes = json.dumps([
        {"id": e.id, "label": e.value[:24], "group": e.type.value,
         "color": RISK_COLORS[e.risk.value]}
        for e in graph.entities.values()][:600])
    gedges = json.dumps([
        {"from": r.src_id, "to": r.dst_id, "label": r.rel_type}
        for r in graph.relationships.values()][:800])

    # by-type breakdown
    bytype = ""
    for t, n in sorted(st["by_type"].items(), key=lambda x: -x[1]):
        bytype += f'<span class="tag">{t}: {n}</span>'

    # ── Persona Hunter section (person investigations) ──────────────────
    persona_html = _persona_section(graph)

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Argus Report — {html.escape(str(m.get('target')))}</title>
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>
*{{box-sizing:border-box}}body{{margin:0;font-family:-apple-system,Segoe UI,Roboto,sans-serif;
background:#0b0e14;color:#e6e6e6}}
header{{padding:24px 32px;background:linear-gradient(120deg,#12161f,#1b2233);
border-bottom:2px solid #2a3550}}
h1{{margin:0;font-size:26px;letter-spacing:.5px}}h1 span{{color:#4da3ff}}
.meta{{color:#8a8f98;margin-top:8px;font-size:14px}}
.wrap{{padding:24px 32px;max-width:1300px;margin:auto}}
.cards{{display:flex;gap:14px;flex-wrap:wrap;margin:20px 0}}
.card{{flex:1;min-width:120px;background:#12161f;border:2px solid;border-radius:12px;
padding:16px;text-align:center}}
.num{{font-size:34px;font-weight:700}}.lbl{{font-size:12px;color:#8a8f98;margin-top:4px}}
.tag{{display:inline-block;background:#1b2233;border:1px solid #2a3550;border-radius:20px;
padding:4px 12px;margin:3px;font-size:12px;color:#a9b4c9}}
table{{width:100%;border-collapse:collapse;margin-top:14px;font-size:13px}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #1b2233}}
th{{color:#8a8f98;text-transform:uppercase;font-size:11px;letter-spacing:.5px}}
.val{{font-family:monospace;color:#cfe3ff;word-break:break-all}}
.src{{color:#8a8f98;font-size:12px}}
.pill{{color:#0b0e14;font-weight:700;padding:2px 8px;border-radius:20px;font-size:11px}}
tr.r-critical td{{background:rgba(255,59,59,.07)}}
tr.r-high td{{background:rgba(255,140,0,.06)}}
h2{{margin-top:36px;border-left:4px solid #4da3ff;padding-left:12px}}
#net{{height:560px;background:#0d1017;border:1px solid #1b2233;border-radius:12px;margin-top:14px}}
.foot{{color:#5a6172;font-size:12px;margin-top:40px;text-align:center}}
.searchbox{{margin:10px 0;padding:8px 12px;width:100%;background:#0d1017;border:1px solid #2a3550;
border-radius:8px;color:#e6e6e6}}
.pctx{{color:#a9b4c9;margin:8px 0 14px;font-size:14px}}
.personas{{display:flex;flex-direction:column;gap:14px}}
.persona{{background:#12161f;border:2px solid;border-radius:12px;padding:14px 16px}}
.ph{{font-size:16px;margin-bottom:10px}}
.verdict{{color:#0b0e14;font-weight:800;padding:3px 10px;border-radius:20px;font-size:12px}}
.pscore{{color:#8a8f98;font-size:13px;margin-left:8px}}
.pcount{{color:#4da3ff;font-size:13px;margin-left:8px}}
.patbl{{width:100%;border-collapse:collapse;margin-top:6px;font-size:13px}}
.patbl th{{color:#8a8f98;font-size:11px;text-transform:uppercase}}
.patbl td,.patbl th{{padding:6px 8px;border-bottom:1px solid #1b2233;vertical-align:top}}
</style></head><body>
<header><h1>ARG<span>US</span> · OSINT Intelligence Report</h1>
<div class="meta">Target: <b>{html.escape(str(m.get('target')))}</b> ({m.get('target_type')})
&nbsp;·&nbsp; Profile: {m.get('profile')} &nbsp;·&nbsp; Duration: {m.get('duration')}s
&nbsp;·&nbsp; {time.strftime('%Y-%m-%d %H:%M')}</div></header>
<div class="wrap">
<div class="cards">{cards}</div>
<div>{bytype}</div>
{persona_html}
<h2>Relationship Graph</h2>
<div id="net"></div>
<h2>Findings ({st['total_entities']})</h2>
<input class="searchbox" id="q" placeholder="filter findings…"
 onkeyup="filt()">
<table id="tbl"><thead><tr><th>Risk</th><th>Type</th><th>Value</th>
<th>Conf</th><th>Sources</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table>
<div class="foot">Generated by Argus — Zero-API OSINT Engine.
For authorized security assessments only.</div>
</div>
<script>
function filt(){{var q=document.getElementById('q').value.toLowerCase();
document.querySelectorAll('#tbl tbody tr').forEach(function(r){{
r.style.display=r.innerText.toLowerCase().includes(q)?'':'none';}});}}
try{{
var nodes=new vis.DataSet({gnodes});
var edges=new vis.DataSet({gedges});
new vis.Network(document.getElementById('net'),{{nodes:nodes,edges:edges}},
{{nodes:{{shape:'dot',size:12,font:{{color:'#cfe3ff',size:11}}}},
edges:{{color:'#33415f',arrows:'to',font:{{color:'#5a6172',size:9}}}},
physics:{{stabilization:true,barnesHut:{{gravitationalConstant:-8000}}}}}});
}}catch(e){{document.getElementById('net').innerHTML=
'<p style=padding:20px;color:#8a8f98>Graph needs internet for vis-network CDN. '+
'Use the .gexf file in Gephi for offline analysis.</p>';}}
</script></body></html>"""
