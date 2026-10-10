#!/usr/bin/env python3
"""
Render the KINGNET lessons (Markdown) into a small, SEO-optimised static site.

Usage: python3 lessons/build_site.py [output_dir]   (default: lessons/_site)
Emits: one HTML page per lesson + overview, a sitemap.xml, robots.txt and favicon.svg.
Each page carries a unique title + meta description, canonical URL, Open Graph / Twitter
tags and JSON-LD structured data. Self-contained: one inline stylesheet, no JS.
"""
import datetime
import os
import re
import sys

import markdown

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "_site")
BASE = "https://lab.kasspar.com"
REPO = "https://github.com/Kingnet256/kingnet"
TODAY = datetime.date.today().isoformat()

# name -> (nav label, <title>, meta description). Titles/descriptions are unique and
# keyword-targeted for the attack/defense each page teaches.
PAGES = {
    "index.html": (
        "Overview",
        "KINGNET — Hands-On AiTM Phishing Attack & Defense Lab",
        "A free, hands-on cyber range that shows how adversary-in-the-middle (AiTM) "
        "phishing steals a live session and beats SMS/app 2FA — then how passkeys, "
        "detection and device-bound sessions stop it."),
    "01-what-is-aitm.html": (
        "What AiTM phishing is",
        "What Is AiTM Phishing? Adversary-in-the-Middle Explained",
        "Adversary-in-the-middle (AiTM) phishing proxies your login in real time, relays "
        "your 2FA and steals the session cookie. Here is exactly how it works."),
    "02-run-the-attack.html": (
        "Run the attack",
        "Run an AiTM Phishing Attack — Lab Walkthrough",
        "Step-by-step: phish a login through a proxy, relay the one-time code, steal the "
        "post-2FA session cookie and take over the account — safely, in the KINGNET lab."),
    "03-why-2fa-fails.html": (
        "Why 2FA doesn't stop it",
        "Why SMS and App 2FA Don't Stop AiTM Phishing",
        "Two-factor codes protect the login, not the session. See why SMS and "
        "authenticator-app 2FA are relayed and bypassed by adversary-in-the-middle attacks."),
    "04-detection.html": (
        "Catching the replay",
        "Detecting Stolen-Session Replay: New Device & Impossible Travel",
        "Even when 2FA is bypassed, a replayed session cookie looks anomalous. Learn the "
        "detection signals — new device, impossible travel, token reuse — that catch it."),
    "05-passkeys-defeat-aitm.html": (
        "Passkeys defeat AiTM",
        "How Passkeys (WebAuthn/FIDO2) Defeat AiTM Phishing",
        "Passkeys bind the login to the real site's origin, so a phishing proxy cannot "
        "relay them. See why FIDO2/WebAuthn is phishing-resistant, proven in the lab."),
    "06-oauth-consent-phishing.html": (
        "OAuth consent phishing",
        "OAuth Consent Phishing (Illicit Grant) — Explained & Defended",
        "Consent phishing needs no password: the victim grants a malicious app access to "
        "their account. Learn the illicit-grant attack and how to detect, revoke and block it."),
    "07-banking-aitm.html": (
        "Banking AiTM",
        "Banking AiTM: Account Takeover From a Stolen Session",
        "When the session cookie is money, AiTM phishing drains the account. See the "
        "banking attack and the defenses — anomaly detection, step-up and transaction binding."),
    "08-cookie-theft-variants.html": (
        "Cookie theft without a proxy",
        "Session Cookie Theft: XSS vs Infostealer (HttpOnly, DBSC)",
        "Sessions get stolen without any proxy — via XSS or an infostealer. Learn both, why "
        "HttpOnly only stops one, and how device-bound sessions (DBSC) defend the rest."),
}
MD_FILES = {  # html name -> source markdown
    "index.html": "README.md",
    **{k: k.replace(".html", ".md") for k in PAGES if k != "index.html"},
}

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
main h1{margin-top:0;font-size:28px;color:#fff;line-height:1.25}
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
@media(max-width:820px){.wrap{flex-direction:column}nav{position:static;flex-basis:auto}}
"""

FAVICON = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
           '<rect width="32" height="32" rx="7" fill="#0b1020"/>'
           '<path d="M16 5 7 8v7c0 5.3 3.7 9.3 9 11 5.3-1.7 9-5.7 9-11V8l-9-3Z" '
           'fill="none" stroke="#38d39f" stroke-width="2" stroke-linejoin="round"/>'
           '<path d="M12 16l3 3 5-6" fill="none" stroke="#7aa2ff" stroke-width="2" '
           'stroke-linecap="round" stroke-linejoin="round"/></svg>')

md = markdown.Markdown(extensions=["fenced_code", "tables", "toc", "sane_lists"])


def render_body(md_name):
    md.reset()
    with open(os.path.join(HERE, md_name), encoding="utf-8") as f:
        text = f.read()
    text = re.sub(r"\((\d\d-[a-z0-9-]+)\.md\)", r"(\1.html)", text)  # .md links -> .html
    return md.convert(text)


def nav_html(active):
    items = []
    for name, (label, _t, _d) in PAGES.items():
        if name == "index.html":
            continue
        cls = ' class="active"' if name == active else ""
        items.append(f'<li><a href="{name}"{cls}>{label}</a></li>')
    home_cls = ' class="active"' if active == "index.html" else ""
    return (f'<nav><div class="brand">KINGNET</div>'
            f'<div class="tag">AiTM / phishing — attack &amp; defense, lab-only</div>'
            f'<ol><li><a href="index.html"{home_cls}>Overview</a></li>'
            + "".join(items) + f'</ol><div class="tag" style="margin-top:16px">'
            f'<a href="{REPO}" rel="noopener">Source on GitHub →</a></div></nav>')


def jsonld(name, title, desc):
    url = f"{BASE}/" + ("" if name == "index.html" else name)
    org = ('{"@type":"Organization","@id":"%s/#org","name":"KINGNET",'
           '"url":"%s/","parentOrganization":{"@type":"Organization","name":"Kasspar",'
           '"url":"https://kasspar.com/"}}') % (BASE, BASE)
    if name == "index.html":
        parts = ",".join(
            '{"@type":"ListItem","position":%d,"url":"%s/%s","name":"%s"}'
            % (i + 1, BASE, n, PAGES[n][1].replace('"', ""))
            for i, n in enumerate(k for k in PAGES if k != "index.html"))
        graph = (org + ',{"@type":"Course","name":"%s","description":"%s","url":"%s/",'
                 '"provider":{"@id":"%s/#org"},"hasCourseInstance":{"@type":"CourseInstance",'
                 '"courseMode":"online","courseWorkload":"PT2H"}},'
                 '{"@type":"ItemList","itemListElement":[%s]}'
                 % (title.replace('"', ""), desc.replace('"', ""), BASE, BASE, parts))
    else:
        graph = (org + ',{"@type":"LearningResource","name":"%s","description":"%s","url":"%s",'
                 '"inLanguage":"en","learningResourceType":"tutorial",'
                 '"isPartOf":{"@type":"Course","name":"KINGNET AiTM lab","url":"%s/"},'
                 '"provider":{"@id":"%s/#org"},"dateModified":"%s"},'
                 '{"@type":"BreadcrumbList","itemListElement":['
                 '{"@type":"ListItem","position":1,"name":"KINGNET lab","item":"%s/"},'
                 '{"@type":"ListItem","position":2,"name":"%s","item":"%s"}]}'
                 % (title.replace('"', ""), desc.replace('"', ""), url, BASE, BASE, TODAY,
                    BASE, title.replace('"', ""), url))
    return '<script type="application/ld+json">{"@context":"https://schema.org","@graph":[%s]}</script>' % graph


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<meta name="description" content="{desc}">
<link rel="canonical" href="{url}">
<meta name="robots" content="index,follow,max-image-preview:large">
<meta name="author" content="KINGNET · Kasspar">
<meta name="theme-color" content="#0b1020">
<meta property="og:type" content="{ogtype}">
<meta property="og:site_name" content="KINGNET — AiTM phishing lab">
<meta property="og:title" content="{title}">
<meta property="og:description" content="{desc}">
<meta property="og:url" content="{url}">
<meta property="og:locale" content="en">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="{title}">
<meta name="twitter:description" content="{desc}">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
{jsonld}
<style>{css}</style></head><body>
<div class="lab">⚠️ KINGNET is an <b>educational, lab-only</b> cyber range. The techniques are real; the targets are bundled lab services and can never reach a real system.</div>
<div class="wrap">{nav}<main>{body}
<div class="foot">KINGNET · lab-contained AiTM/phishing education, part of <a href="https://kasspar.com/" rel="noopener">Kasspar</a> · <a href="{repo}" rel="noopener">source on GitHub</a></div>
</main></div></body></html>"""


def write(name, body):
    label, title, desc = PAGES[name]
    url = f"{BASE}/" + ("" if name == "index.html" else name)
    html = PAGE.format(title=title, desc=desc, url=url, css=CSS, nav=nav_html(name),
                       body=body, repo=REPO, jsonld=jsonld(name, title, desc),
                       ogtype="website" if name == "index.html" else "article")
    with open(os.path.join(OUT, name), "w", encoding="utf-8") as f:
        f.write(html)


def write_extras():
    with open(os.path.join(OUT, "favicon.svg"), "w", encoding="utf-8") as f:
        f.write(FAVICON)
    with open(os.path.join(OUT, "robots.txt"), "w", encoding="utf-8") as f:
        f.write(f"User-agent: *\nAllow: /\nSitemap: {BASE}/sitemap.xml\n")
    urls = "".join(
        '<url><loc>%s/%s</loc><lastmod>%s</lastmod><changefreq>monthly</changefreq>'
        '<priority>%s</priority></url>'
        % (BASE, "" if n == "index.html" else n, TODAY, "1.0" if n == "index.html" else "0.8")
        for n in PAGES)
    with open(os.path.join(OUT, "sitemap.xml"), "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n'
                '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">%s</urlset>\n' % urls)


def main():
    os.makedirs(OUT, exist_ok=True)
    for name in PAGES:
        write(name, render_body(MD_FILES[name]))
    write_extras()
    print(f"built {len(PAGES)} pages + sitemap.xml + robots.txt + favicon.svg -> {OUT}")


if __name__ == "__main__":
    main()
