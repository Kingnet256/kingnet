// Lab "browser": views a saved inbox page and runs any injected <script>, exactly as a
// victim's browser would. document.cookie is set to the NON-HttpOnly cookies only — the
// HttpOnly session is invisible to page JS, which is the whole point. Image/fetch really
// fire, so the attacker's exfil request actually reaches the drop server.
const fs = require('fs');
const html = fs.readFileSync(process.argv[2], 'utf8');
globalThis.document = { cookie: process.argv[3] || '' };
globalThis.Image = class { set src(u) { fetch(u).catch(() => {}); } };
const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].map(m => m[1]);
(async () => {
  for (const s of scripts) { try { await eval(s); } catch (e) { console.error('run error:', e.message); } }
  await new Promise(r => setTimeout(r, 400));   // let exfil requests flush
  console.log('ran ' + scripts.length + ' injected script block(s)');
})();
