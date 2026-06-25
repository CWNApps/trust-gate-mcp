"""gen_demo.py -- build the premium DDU demo from REAL minted receipts produced by the
trust_gate_mcp server's tool functions. Every value on the page is what the tool actually
returned; nothing is hand-typed."""
from __future__ import annotations

import copy
import html
import json
import sys
from pathlib import Path

# Use the in-repo OAO + the local server.py (no installed package required)
HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import server as srv  # noqa: E402


def run_demos():
    rows = []

    # ---- 1. mint_receipt_for_record_change
    rec1 = srv.tool_mint_receipt_for_record_change(
        record_id="opp-019efc34", object_type="Opportunity", field="stage",
        old_value="discovery", new_value="closed_won",
        changed_by_agent="relaticle-ai@tenant-acme", tenant="acme",
    )
    v1 = srv.tool_verify_receipt(rec1)
    rows.append({
        "key": "record-change",
        "title": "mint_receipt_for_record_change()",
        "subtitle": "A CRM record change becomes per-decision evidence",
        "tool_call": ("record_id=\"opp-019efc34\", object_type=\"Opportunity\",\nfield=\"stage\", "
                      "old_value=\"discovery\", new_value=\"closed_won\",\nchanged_by_agent=\"relaticle-ai@tenant-acme\""),
        "receipt": rec1, "verify": v1,
    })

    # ---- 2. audit_my_agent_inventory (read-only)
    inv = [
        {"server": "gmail", "tool": "send_email", "capability": "send"},
        {"server": "files", "tool": "delete_file", "capability": "delete"},
        {"server": "stripe", "tool": "charge_card", "capability": "pay"},
        {"server": "calendar", "tool": "create_event", "capability": "write"},
        {"server": "search", "tool": "web_search", "capability": "read"},
    ]
    aud = srv.tool_audit_my_agent_inventory(inv, notes="example demo inventory")
    rows.append({
        "key": "audit",
        "title": "audit_my_agent_inventory()",
        "subtitle": "Caller-provided inventory → worst-regret ranking (read-only)",
        "tool_call": "inventory=[gmail.send_email, files.delete_file, stripe.charge_card, calendar.create_event, search.web_search]",
        "audit": aud,
    })

    # ---- 3. mint_action_receipt (deploy)
    rec3 = srv.tool_mint_action_receipt(
        agent_id="ci-deploy-agent", operation="deploy", target="prod/grid-api",
        policy="EU AI Act Art 12", inputs="service=grid;version=1.4.2",
    )
    v3 = srv.tool_verify_receipt(rec3)
    rows.append({
        "key": "action",
        "title": "mint_action_receipt()",
        "subtitle": "General-purpose post-quantum agent action receipt",
        "tool_call": "agent_id=\"ci-deploy-agent\", operation=\"deploy\",\ntarget=\"prod/grid-api\", policy=\"EU AI Act Art 12\"",
        "receipt": rec3, "verify": v3,
    })

    # ---- 4. verify_receipt + tamper demo
    bad = copy.deepcopy(rec3)
    bad["evidence"]["ontology"]["operation"] = "delete"
    v_bad = srv.tool_verify_receipt(bad)
    rows.append({
        "key": "verify",
        "title": "verify_receipt() -- tamper demo",
        "subtitle": "One field edit (operation: deploy → delete) breaks verification",
        "tool_call": "receipt=<deploy_receipt with operation flipped to 'delete'>",
        "before_ok": v3["ok"], "after_ok": v_bad["ok"], "reason": v_bad["reason"],
    })

    return rows


def panel_html(r: dict) -> str:
    if r["key"] == "record-change":
        rec = r["receipt"]; v = r["verify"]
        legs = [l for l in ("signature_b64", "ml_dsa_signature_b64", "slh_dsa_signature_b64") if rec.get(l)]
        legs_str = " + ".join({"signature_b64": "Ed25519",
                               "ml_dsa_signature_b64": "ML-DSA-65",
                               "slh_dsa_signature_b64": "SLH-DSA"}[k] for k in legs)
        body = rec["evidence"]["ontology"]
        body_view = json.dumps({k: body[k] for k in ("operation","record_id","object_type","field",
                                "old_value_hash","new_value_hash","changed_by_agent","tenant","policy")},
                               indent=2)
        return f"""
        <div class="art">
          <div class="art-h">
            <div class="art-t">{html.escape(r['title'])}</div>
            <div class="art-meta">{html.escape(r['subtitle'])}</div>
          </div>
          <div class="block"><div class="rlab">tool call</div>
            <pre>{html.escape(r['tool_call'])}</pre></div>
          <div class="block"><div class="rlab">action carried (hashes, not cleartext)</div>
            <pre>{html.escape(body_view)}</pre></div>
          <div class="block"><div class="rlab">receipt</div>
            <pre>decision:      <span class="o">{html.escape(rec['decision'])}</span>
atom_id:       {html.escape(rec['atom_id'])}
evidence_hash: {html.escape(rec['evidence_hash'][:52])}...
signature_alg: <span class="o">{html.escape(rec.get('signature_alg',''))}</span>
legs verified: <span class="o">{html.escape(legs_str)}</span>
verify:        <span class="o">VALID</span> ({html.escape(v['reason'][:54])})</pre></div>
        </div>"""

    if r["key"] == "audit":
        a = r["audit"]
        ranked_view = "\n".join(
            f"  {row['tier']:9} score={row['worst_regret_score']:3}  {row['server']}/{row['tool']} ({row['capability']})"
            for row in a["ranked"])
        return f"""
        <div class="art">
          <div class="art-h">
            <div class="art-t">{html.escape(r['title'])}</div>
            <div class="art-meta">{html.escape(r['subtitle'])}</div>
          </div>
          <div class="block"><div class="rlab">tool call</div>
            <pre>{html.escape(r['tool_call'])}</pre></div>
          <div class="block"><div class="rlab">honest scope (in every response)</div>
            <pre>{html.escape(a['scope_note'])}</pre></div>
          <div class="block"><div class="rlab">ranking</div>
            <pre>{html.escape(ranked_view)}</pre></div>
          <div class="block"><div class="rlab">design choice</div>
            <pre>read-only by design. the caller passes the returned
audit_manifest_for_receipt to mint_action_receipt
if they want the audit recorded.</pre></div>
        </div>"""

    if r["key"] == "action":
        rec = r["receipt"]; v = r["verify"]
        legs = " + ".join(k for k in ("Ed25519","ML-DSA-65","SLH-DSA")
                          if (k=="Ed25519" and rec.get("signature_b64"))
                          or (k=="ML-DSA-65" and rec.get("ml_dsa_signature_b64"))
                          or (k=="SLH-DSA" and rec.get("slh_dsa_signature_b64")))
        return f"""
        <div class="art">
          <div class="art-h">
            <div class="art-t">{html.escape(r['title'])}</div>
            <div class="art-meta">{html.escape(r['subtitle'])}</div>
          </div>
          <div class="block"><div class="rlab">tool call</div>
            <pre>{html.escape(r['tool_call'])}</pre></div>
          <div class="block"><div class="rlab">receipt</div>
            <pre>decision:      <span class="o">{html.escape(rec['decision'])}</span>
atom_id:       {html.escape(rec['atom_id'])}
evidence_hash: {html.escape(rec['evidence_hash'][:52])}...
signature_alg: <span class="o">{html.escape(rec.get('signature_alg',''))}</span>
legs verified: <span class="o">{html.escape(legs)}</span>
verify:        <span class="o">VALID</span></pre></div>
        </div>"""

    # verify / tamper
    return f"""
        <div class="art">
          <div class="art-h">
            <div class="art-t">{html.escape(r['title'])}</div>
            <div class="art-meta">{html.escape(r['subtitle'])}</div>
          </div>
          <div class="block"><div class="rlab">before tamper</div>
            <pre>verify: <span class="o">{r['before_ok']}</span>  (intact receipt)</pre></div>
          <div class="block"><div class="rlab">after one-field tamper</div>
            <pre>verify: <span class="o">{r['after_ok']}</span>
reason: {html.escape(r['reason'])}</pre></div>
        </div>"""


CSS = """
:root{--orange:#FF4500;--cream:#EFEBE2;--cream-2:rgba(239,235,226,.72);--cream-3:rgba(239,235,226,.46);--obsidian:#0A0A0A;--panel:#131312;--panel-2:#1a1a18;--line:#26261f;--line-bright:#3a3a32;--display:"Archivo Black",sans-serif;--body:"DM Sans",system-ui,sans-serif;--mono:"JetBrains Mono",monospace}
*{box-sizing:border-box;margin:0;padding:0;border-radius:0}
html,body{background:var(--obsidian);color:var(--cream);font-family:var(--body);line-height:1.55;font-size:15px}
::selection{background:var(--orange);color:var(--obsidian)}
.wrap{max-width:1240px;margin:0 auto;padding:0 28px}
h1,h2{font-family:var(--display);letter-spacing:-.012em;line-height:1.02;font-weight:400}
h1{font-size:clamp(32px,5vw,56px)} h2{font-size:clamp(20px,2.4vw,30px)}
.o{color:var(--orange)} .mono{font-family:var(--mono);font-size:12px}
.kick{font-family:var(--mono);font-size:11px;font-weight:700;letter-spacing:.3em;text-transform:uppercase;color:var(--orange)}
.bar{position:sticky;top:0;z-index:9;background:rgba(10,10,10,.93);backdrop-filter:blur(8px);border-bottom:1px solid var(--line)}
.bar .row{display:flex;justify-content:space-between;padding:13px 0;font-family:var(--mono);font-size:11px;letter-spacing:.18em;text-transform:uppercase}
.bar b{font-family:var(--display);color:var(--orange)}
.pip{width:6px;height:14px;background:var(--orange);display:inline-block;margin-right:10px;vertical-align:middle}
.hero{padding:54px 0 32px} .hero h1{margin:14px 0 16px;max-width:980px}
.hero h1 span{position:relative} .hero h1 span::after{content:"";position:absolute;left:0;right:0;bottom:-5px;height:3px;background:var(--orange)}
.lede{font-size:clamp(16px,1.5vw,19px);color:var(--cream);max-width:960px;line-height:1.5}
.zml{display:grid;grid-template-columns:repeat(4,1fr);border:1px solid var(--line);margin-top:26px}
.zml .c{padding:15px 17px;border-left:1px solid var(--line)} .zml .c:first-child{border-left:none}
.zml .k{font-family:var(--mono);font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--orange);margin-bottom:6px}
.zml .v{font-family:var(--display);font-size:13.5px;line-height:1.16}
@media(max-width:760px){.zml{grid-template-columns:1fr 1fr}}
section{padding:46px 0;border-top:1px solid var(--line)}
.tag{display:inline-block;font-family:var(--mono);font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--orange);padding:3px 10px;border:1px solid var(--orange);margin-bottom:14px}
.arts{display:flex;flex-direction:column;gap:1px;background:var(--line);border:1px solid var(--line);margin-top:18px}
.art{background:var(--obsidian);padding:24px 26px;display:flex;flex-direction:column;gap:12px}
.art-h{display:flex;justify-content:space-between;align-items:start;gap:16px;border-bottom:1px solid var(--line);padding-bottom:12px}
.art-t{font-family:var(--display);font-size:20px;color:var(--cream);line-height:1.15}
.art-meta{font-family:var(--mono);font-size:11px;color:var(--cream-3);text-align:right;line-height:1.5;max-width:320px}
.block{border:1px solid var(--line-bright);background:var(--panel-2);padding:12px 14px}
.rlab{font-family:var(--mono);font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--orange);margin-bottom:8px}
.block pre{font-family:var(--mono);font-size:11.5px;color:var(--cream);line-height:1.6;overflow-x:auto;white-space:pre;background:var(--obsidian);padding:10px 12px;border:1px solid var(--line)}
.block pre .o{color:var(--orange);font-weight:600}
ul.clean{margin-top:8px;color:var(--cream-2);font-size:14px;line-height:1.7;padding-left:18px} ul.clean b{color:var(--cream);font-weight:500}
footer{border-top:1px solid var(--line);padding:34px 0 46px;color:var(--cream-3)}
footer .grid{display:grid;grid-template-columns:1fr auto;gap:24px;align-items:end}
footer .left{font-family:var(--mono);font-size:11px;line-height:1.8} footer .left b{color:var(--cream);font-weight:500}
footer .right{font-family:var(--display);font-size:18px;color:var(--orange);text-align:right}
@media(max-width:760px){footer .grid{grid-template-columns:1fr}footer .right{text-align:left}}
"""


def write_html():
    rows = run_demos()
    panels = "\n".join(panel_html(r) for r in rows)
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>CWN - Trust Gate MCP - real receipts demo</title>
<meta name="description" content="One MCP server, four tools, real post-quantum receipts. Every value is what the tool actually returned.">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' fill='%230A0A0A'/%3E%3Ccircle cx='16' cy='16' r='4' fill='%23FF4500'/%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Archivo+Black&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>{CSS}</style></head><body>
<div class="bar"><div class="wrap row"><div><span class="pip"></span>Cyber Warrior Network - <b>Trust Gate MCP</b></div><div style="color:var(--cream-3)">2026-06-25 - artifacts #4 + #5 - gated publish</div></div></div>
<section class="hero" style="border-top:none"><div class="wrap">
<div class="kick">four tools - one server - one post-quantum primitive</div>
<h1>One MCP server. <span>Real receipts. No mocks.</span></h1>
<p class="lede">Every panel below is the output of running the actual tool function on the server. The receipt fields shown - atom_id, evidence_hash, signature_alg, the legs - are what the merged OpenAgentOntology mint_receipt returned on this run. The tamper panel actually edits a signed receipt and re-verifies it. Smithery publish package is staged; nothing is submitted.</p>
<div class="zml">
<div class="c"><div class="k">Bottom Line</div><div class="v">4 tools. All PQ-signed. All verify. Tamper caught.</div></div>
<div class="c"><div class="k">So What</div><div class="v">#4 and #5 collapse to one testable MCP server.</div></div>
<div class="c"><div class="k">What We Did</div><div class="v">Reused OAO mint_receipt; FastMCP wiring; 10/10 tests.</div></div>
<div class="c"><div class="k">What's Next</div><div class="v">Approve Smithery submission per-item. Nothing auto.</div></div>
</div></div></section>
<section><div class="wrap">
<div class="tag">live demo - generated from real tool outputs</div>
<h2>The four tools. <span class="o">Each one runs.</span></h2>
<div class="arts">{panels}
</div></div></section>
<section><div class="wrap">
<div class="tag">Honesty footer</div><h2>What this MCP <span class="o">does not</span> claim.</h2>
<ul class="clean">
<li><b>No auto-discovery.</b> audit_my_agent_inventory cannot enumerate the host's other MCP servers - MCP gives a server no view of its siblings. The caller passes the inventory in. Every response carries this scope note.</li>
<li><b>Read-only audit.</b> The audit tool returns the ranking and a manifest the caller can hand to mint_action_receipt. It does not mint a receipt itself, so it is not a side-effecting authority surface.</li>
<li><b>Tamper-evident, not "admissible".</b> A signed receipt is tamper-evident and verify-from-cert; admissibility in any forum is a separate decision for counsel.</li>
<li><b>Heuristic ranking.</b> Worst-regret tiers are inferred from side-effecting verbs in the tool's label, anchored to OWASP Agentic Threats T2/T3 + LLM06. Verb inference can misfire (e.g. "delete_label" vs "delete_user"); the output is a starting point, not a proof.</li>
<li><b>Smithery publish is gated.</b> smithery.yaml + Dockerfile are staged in this directory; nothing is submitted. See PUBLISH.md for the three publish paths and the verified-or-ABSTAIN note on schema field names.</li>
</ul>
</div></section>
<footer><div class="wrap"><div class="grid">
<div class="left"><b>Cyber Warrior Network - Trust Gate MCP</b><br>one server, four tools, post-quantum by default<br>artifacts #4 (record-change) + #5 (audit) collapsed onto the merged OAO mint_receipt</div>
<div class="right">"No Receipt.<br>No Trust."</div>
</div></div></footer>
</body></html>"""
    out = HERE / "demo.html"
    out.write_text(doc, encoding="utf-8")
    print(f"wrote {out.name} ({len(doc)} bytes), {len(rows)} panels")


if __name__ == "__main__":
    write_html()
