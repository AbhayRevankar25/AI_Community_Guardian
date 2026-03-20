"""Shared HTML templates for multi-page UI."""

SHARED_CSS = """
:root{--bg1:#0b1220;--bg2:#0f1b33;--card:#111a2e;--text:#e8eefc;--muted:#a9b4d0;--border:rgba(255,255,255,.10);
--shadow:0 18px 50px rgba(0,0,0,.35);--brand:#7c5cff;--brand2:#2dd4bf;--danger:#ff4d6d;--warn:#fbbf24;
--ok:#2dd4bf;--low:#60a5fa;}
*{box-sizing:border-box;}
body{margin:0;font-family:ui-sans-serif,system-ui,sans-serif;color:var(--text);
background:radial-gradient(900px 600px at 10% 10%,rgba(124,92,255,.25),transparent),
radial-gradient(700px 500px at 90% 20%,rgba(45,212,191,.18),transparent),
linear-gradient(135deg,var(--bg1),var(--bg2));min-height:100vh;}
.wrap{max-width:900px;margin:0 auto;padding:28px 18px 48px;}
.nav{display:flex;gap:16px;align-items:center;margin-bottom:28px;padding:12px 0;border-bottom:1px solid var(--border);}
.nav a{color:var(--muted);text-decoration:none;font-weight:600;font-size:14px;}
.nav a:hover{color:var(--text);}.nav a.active{color:var(--brand);}
.card{background:linear-gradient(180deg,rgba(255,255,255,.04),rgba(255,255,255,.02));
border:1px solid var(--border);box-shadow:var(--shadow);border-radius:16px;padding:20px;}
.section-title{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:12px;}
.section-title strong{font-size:14px;}
.pill{font-size:12px;color:var(--muted);border:1px solid var(--border);background:rgba(255,255,255,.03);
padding:6px 10px;border-radius:999px;white-space:nowrap;}
textarea{width:100%;min-height:120px;resize:vertical;padding:12px;border-radius:12px;border:1px solid var(--border);
background:rgba(0,0,0,.20);color:var(--text);outline:none;}
textarea:focus{border-color:rgba(124,92,255,.55);box-shadow:0 0 0 3px rgba(124,92,255,.15);}
.row{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-top:12px;}
.row .grow{flex:1;min-width:200px;}
label{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:13px;}
input[type="checkbox"]{width:18px;height:18px;accent-color:var(--brand);}
.btn{border:none;padding:10px 18px;border-radius:12px;background:linear-gradient(90deg,var(--brand),rgba(124,92,255,.35));
color:white;font-weight:600;cursor:pointer;transition:filter .2s;}
.btn:hover{filter:brightness(1.06);}
.btn.secondary{background:rgba(255,255,255,.05);border:1px solid var(--border);color:var(--text);}
.btn:disabled{cursor:not-allowed;opacity:.6;}
.hint{color:var(--muted);font-size:12px;}
.error{background:rgba(255,77,109,.10);border:1px solid rgba(255,77,109,.35);color:#ffd7df;
padding:10px 12px;border-radius:12px;display:none;margin-top:12px;font-size:13px;}
.loading{display:none;margin-left:10px;color:var(--muted);font-size:13px;align-items:center;gap:10px;}
.spinner{width:16px;height:16px;border-radius:50%;border:2px solid rgba(255,255,255,.25);
border-top-color:rgba(124,92,255,.95);animation:spin .9s linear infinite;}
@keyframes spin{to{transform:rotate(360deg);}}
.badges{display:flex;gap:10px;flex-wrap:wrap;}
.badge{display:inline-flex;align-items:center;gap:8px;font-weight:700;font-size:12px;padding:8px 10px;
border-radius:999px;border:1px solid var(--border);background:rgba(255,255,255,.03);}
.badge .dot{width:10px;height:10px;border-radius:50%;}
.badge.danger{border-color:rgba(255,77,109,.5);background:rgba(255,77,109,.10);}.badge.danger .dot{background:var(--danger);}
.badge.warn{border-color:rgba(251,191,36,.45);background:rgba(251,191,36,.12);}.badge.warn .dot{background:var(--warn);}
.badge.ok{border-color:rgba(45,212,191,.45);background:rgba(45,212,191,.10);}.badge.ok .dot{background:var(--ok);}
.badge.low{border-color:rgba(96,165,250,.45);}.badge.low .dot{background:var(--low);}
.progress{height:10px;background:rgba(255,255,255,.08);border:1px solid var(--border);border-radius:999px;overflow:hidden;}
.bar{height:100%;width:0%;background:linear-gradient(90deg,var(--brand),var(--brand2));border-radius:999px;transition:width .25s;}
.kv{display:grid;grid-template-columns:1fr 1fr;gap:10px;}
.box{background:rgba(0,0,0,.18);border:1px solid var(--border);border-radius:14px;padding:12px;}
.kv .k{color:var(--muted);font-size:12px;margin-bottom:6px;}
.kv .v{font-size:16px;font-weight:800;}
ul{margin:8px 0 0 18px;padding:0;}li{margin:6px 0;color:var(--text);}
.muted{color:var(--muted);}
.alerts-list{display:flex;flex-direction:column;gap:10px;}
.alert-item{background:rgba(0,0,0,.18);border:1px solid var(--border);border-radius:14px;padding:12px;}
.alert-item .top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:8px;}
.alert-item .t{font-weight:800;font-size:13px;}
.alert-item .time{color:var(--muted);font-size:12px;}
.alert-item .cat{color:var(--muted);font-size:12px;margin-top:6px;}
.footer-note{margin-top:14px;color:var(--muted);font-size:12px;}
.hero{text-align:center;padding:48px 24px;}
.hero h1{margin:0 0 12px;font-size:28px;}
.hero p{color:var(--muted);font-size:15px;line-height:1.6;max-width:560px;margin:0 auto 24px;}
.hero-links{display:flex;gap:16px;justify-content:center;flex-wrap:wrap;}
.hero-links a{display:inline-block;padding:14px 24px;border-radius:14px;text-decoration:none;font-weight:700;
background:linear-gradient(90deg,var(--brand),rgba(124,92,255,.35));color:white;transition:filter .2s;}
.hero-links a:hover{filter:brightness(1.1);}
.hero-links a.outline{background:transparent;border:2px solid var(--border);color:var(--text);}
input[type="password"],input[type="text"]{width:100%;padding:11px 12px;border-radius:12px;border:1px solid var(--border);
background:rgba(0,0,0,.20);color:var(--text);outline:none;}
"""


def nav_html(current: str) -> str:
    links = [("/", "Home"), ("/analyze-page", "Analyze"), ("/alerts-page", "Alerts"), ("/safe-circle-page", "Safe Circle")]
    items = [f'<a href="{h}" class="{"active" if current == h else ""}">{lbl}</a>' for h, lbl in links]
    return '<nav class="nav">' + "".join(items) + "</nav>"


def page(title: str, current: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{title} - AI Community Guardian</title><style>{SHARED_CSS}</style></head>
<body><div class="wrap">{nav_html(current)}
<a href="/" style="text-decoration:none;color:var(--text);"><h1 style="margin:0 0 8px;">AI Community Guardian</h1></a>
<p class="muted" style="margin:0 0 24px;">Zero Trust Cyber Safety Assistant</p>
{body}</div></body></html>"""
