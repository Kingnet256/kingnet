#!/usr/bin/env python3
"""
Render the KINGNET lessons (Markdown) into a small static HTML site for kasspar.com.

Usage: python3 lessons/build_site.py [output_dir]   (default: lessons/_site)
Self-contained: one stylesheet, a lesson sidebar, a prominent LAB-ONLY banner. No JS.
"""
import os
import re
import sys

import markdown

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "_site")
REPO = "https://github.com/Kingnet256/kingnet"

LESSONS = [
    ("01-what-is-aitm.md", "What AiTM phishing is"),
    ("02-run-the-attack.md", "Run the attack"),
    ("03-why-2fa-fails.md", "Why 2FA doesn't stop it"),
    ("04-detection.md", "Catching the replay"),
    ("05-passkeys-defeat-aitm.md", "Passkeys defeat AiTM"),
    ("06-oauth-consent-phishing.md", "OAuth consent phishing"),
    ("07-banking-aitm.md", "Banking AiTM"),
    ("08-cookie-theft-variants.md", "Cookie theft without a proxy"),
]

CSS = """
:root{--bg:#0b1020;--panel:#121a2e;--ink:#dce5f5;--muted:#8b9bc0;--brand:#38d39f;--line:#223052;--accent:#7aa2ff}
*{box-sizing:border-box} html{scroll-behavior:smooth}
body{margin:0;font:16px/1.65 -apple-system,Segoe UI,Roboto,Arial,sans-serif;color:var(--ink);background:var(--bg)}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
.lab{background:#2a1623;border-bottom:1px solid #5c2740;color:#ffb3c7;font-size:13px;text-align:center;padding:8px 14px}
.wrap{display:flex;max-width:1180px;margin:0 auto;gap:28px;padding:24px 16px}
nav{flex:0 0 240px;position:sticky;top:24px;align-self:flex-start}
nav .brand{font-weight:800;letter-spacing:1px;color:#fff;font-size:18px;margin-bottom:4px}
nav .tag{color:var(--muted);font-size:12px;margin-bottom:16px}
nav ol{list-style:none;margin:0;padding:0;counter-reset:l}
nav li{counter-increment:l;margin:2px 0}
nav li a{display:block;padding:7px 10px;border-radius:8px;color:var(--ink);font-size:14px}
nav li a:hover{background:var(--panel);text-decoration:none}
nav li a.active{background:var(--panel);color:var(--brand);font-weight:600}
nav li a::before{content:counter(l) ". ";color:var(--muted)}
main{flex:1;min-width:0;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:30px 34px;overflow:hidden}
main h1{margin-top:0;font-size:28px;color:#fff}
main h2{margin-top:30px;color:#fff;border-bottom:1px solid var(--line);padding-bottom:6px}
main h3{color:#cfe0ff}
main code{background:#0a0f1e;border:1px solid var(--line);border-radius:5px;padding:1px 5px;font-size:13.5px}
main pre{background:#0a0f1e;border:1px solid var(--line);border-radius:10px;padding:14px 16px;overflow:auto}
main pre code{border:0;padding:0;background:none}
main table{border-collapse:collapse;width:100%;margin:14px 0;font-size:14.5px}
main th,main td{border:1px solid var(--line);padding:8px 10px;text-align:left}
main th{background:#0e1527;color:#fff}
main blockquote{border-left:3px solid var(--brand);margin:14px 0;padding:6px 14px;background:#0e1527;color:var(--muted)}
.foot{color:var(--muted);font-size:13px;border-top:1px solid var(--line);margin-top:28px;padding-top:14px}
.home-hero h1{font-size:34px}
@media(max-width:820px){.wrap{flex-direction:column}nav{position:static;flex-basis:auto}}
"""

md = markdown.Markdown(extensions=["fenced_code", "tables", "toc", "sane_lists"])


def render_body(path):
    md.reset()
    with open(path, encoding="utf-8") as f:
        text = f.read()
    # rewrite inter-lesson .md links to .html
    text = re.sub(r"\((\d\d-[a-z0-9-]+)\.md\)", r"(\1.html)", text)
    return md.convert(text)


def nav_html(active):
    items = []
    for fn, title in LESSONS:
        html = fn.replace(".md", ".html")
        cls = ' class="active"' if html == active else ""
        items.append(f'<li><a href="{html}"{cls}>{title}</a></li>')
    return (f'<nav><div class="brand">KINGNET</div>'
            f'<div class="tag">AiTM / phishing — attack &amp; defense, lab-only</div>'
            f'<ol><li><a href="index.html"{" class=\"active\"" if active=="index.html" else ""}>Overview</a></li>'
            + "".join(items) + f'</ol><div class="tag" style="margin-top:16px">'
            f'<a href="{REPO}">Source on GitHub →</a></div></nav>')


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · KINGNET</title>
<meta name="description" content="KINGNET — a lab-contained range that shows how modern AiTM/phishing attacks really work, then how to defend. Educational, lab-only.">
<style>{css}</style></head><body>
<div class="lab">⚠️ KINGNET is an <b>educational, lab-only</b> cyber range. The techniques are real; the targets are bundled lab services and can never reach a real system.</div>
<div class="wrap">{nav}<main>{body}
<div class="foot">KINGNET · lab-contained AiTM/phishing education · <a href="{repo}">github.com/Kingnet256/kingnet</a></div>
</main></div></body></html>"""


def write(name, title, body):
    with open(os.path.join(OUT, name), "w", encoding="utf-8") as f:
        f.write(PAGE.format(title=title, css=CSS, nav=nav_html(name), body=body, repo=REPO))


def main():
    os.makedirs(OUT, exist_ok=True)
    write("index.html", "Overview", render_body(os.path.join(HERE, "README.md")))
    for fn, title in LESSONS:
        write(fn.replace(".md", ".html"), title, render_body(os.path.join(HERE, fn)))
    print(f"built {len(LESSONS)+1} pages -> {OUT}")


if __name__ == "__main__":
    main()
