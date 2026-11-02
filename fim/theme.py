"""Visual theme for the dashboard: a dark forensic-investigation console.

Pure CSS and HTML, with no extra packages and no online fonts. It uses fonts
installed with Windows (Bahnschrift and Consolas), so text displays offline.
"""
from __future__ import annotations

THEME_CSS = """
<style>
:root {
  --cyan: #00e5ff;
  --green: #39ff88;
  --amber: #ffb020;
  --panel: rgba(8, 18, 34, 0.80);
  --line: rgba(0, 229, 255, 0.30);
  --head-font: 'Bahnschrift', 'Segoe UI', 'Arial Narrow', Arial, sans-serif;
  --mono-font: 'Consolas', 'Courier New', monospace;
}

.stApp {
  background:
    radial-gradient(ellipse at top, rgba(0, 229, 255, 0.12), transparent 60%),
    linear-gradient(rgba(0, 229, 255, 0.07) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0, 229, 255, 0.07) 1px, transparent 1px),
    #050a14;
  background-size: auto, 40px 40px, 40px 40px, auto;
  font-family: var(--mono-font);
  color: #c9f7ff;
}

.stApp::after {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  background: linear-gradient(transparent 50%, rgba(0, 229, 255, 0.035) 50%);
  background-size: 100% 4px;
  animation: scan 9s linear infinite;
  z-index: 999;
}
@keyframes scan {
  from { background-position: 0 0; }
  to { background-position: 0 100%; }
}

.stDeployButton { display: none !important; }

h1, h2, h3 {
  font-family: var(--head-font) !important;
  color: var(--cyan) !important;
  letter-spacing: 1px;
}
h2, h3 { text-transform: uppercase; font-size: 1.1rem !important; }

/* Make ordinary text readable on the dark background */
.stMarkdown p, .stCaption, label, .stTextInput label p {
  color: #c9f7ff !important;
  font-family: var(--mono-font);
}
.stCaption p { color: #7fd8e8 !important; }

div[data-testid="stMetric"] {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 14px 16px;
  box-shadow: 0 0 18px rgba(0, 229, 255, 0.12), inset 0 0 20px rgba(0, 229, 255, 0.05);
  transition: transform 0.3s ease, box-shadow 0.3s ease;
}
div[data-testid="stMetric"]:hover {
  transform: perspective(600px) rotateX(8deg) translateY(-4px);
  box-shadow: 0 12px 30px rgba(0, 229, 255, 0.28);
}
div[data-testid="stMetricLabel"] p {
  color: #7fd8e8 !important;
  text-transform: uppercase;
  letter-spacing: 1px;
  font-size: 0.85rem !important;
  font-family: var(--mono-font);
}
div[data-testid="stMetricValue"] {
  color: var(--green) !important;
  font-family: var(--head-font);
  font-size: 2.2rem !important;
  text-shadow: 0 0 10px rgba(57, 255, 136, 0.6);
}

div[data-testid="stAlert"] {
  background: var(--panel) !important;
  border-left: 4px solid var(--cyan);
}
div[data-testid="stAlert"] p {
  color: #e6fbff !important;
  font-family: var(--mono-font);
}

.stButton button, .stDownloadButton button {
  background: transparent !important;
  color: var(--cyan) !important;
  border: 1px solid var(--cyan) !important;
  font-family: var(--mono-font);
  text-transform: uppercase;
  letter-spacing: 1px;
  box-shadow: 0 0 10px rgba(0, 229, 255, 0.3);
}
.stButton button p, .stDownloadButton button p {
  color: var(--cyan) !important;
}
.stButton button:hover, .stDownloadButton button:hover {
  background: rgba(0, 229, 255, 0.15) !important;
  box-shadow: 0 0 22px rgba(0, 229, 255, 0.6);
  color: #ffffff !important;
}

div[data-testid="stDataFrame"], div[data-testid="stTextInput"] input {
  border: 1px solid var(--line) !important;
  border-radius: 6px;
}

.fim-hero {
  display: flex;
  align-items: center;
  gap: 28px;
  padding: 8px 0 18px 0;
}
.fim-scene { width: 130px; height: 130px; perspective: 500px; flex: 0 0 130px; margin-left: 24px; }
.fim-cube {
  width: 110px;
  height: 110px;
  position: relative;
  margin: 10px;
  transform-style: preserve-3d;
  animation: spin 14s linear infinite;
}
.fim-cube .face {
  position: absolute;
  width: 110px;
  height: 110px;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--cyan);
  background: rgba(0, 229, 255, 0.08);
  color: #e6fbff;
  font-family: var(--mono-font);
  font-size: 13px;
  font-weight: bold;
  letter-spacing: 1px;
  box-shadow: inset 0 0 18px rgba(0, 229, 255, 0.25);
}
.fim-cube .front  { transform: translateZ(55px); }
.fim-cube .back   { transform: rotateY(180deg) translateZ(55px); }
.fim-cube .right  { transform: rotateY(90deg) translateZ(55px); }
.fim-cube .left   { transform: rotateY(-90deg) translateZ(55px); }
.fim-cube .top    { transform: rotateX(90deg) translateZ(55px); }
.fim-cube .bottom { transform: rotateX(-90deg) translateZ(55px); }
@keyframes spin {
  from { transform: rotateX(-20deg) rotateY(0deg); }
  to { transform: rotateX(-20deg) rotateY(360deg); }
}
.fim-kicker { color: var(--amber); font-family: var(--mono-font); font-size: 0.9rem; letter-spacing: 2px; }
.fim-title-text {
  font-family: var(--head-font);
  font-size: 2.2rem;
  font-weight: 700;
  color: var(--cyan);
  text-shadow: 0 0 14px rgba(0, 229, 255, 0.8);
}
.fim-sub { color: #7fd8e8; font-family: var(--mono-font); letter-spacing: 2px; }
</style>
"""

HERO_HTML = """<div class="fim-hero">
<div class="fim-scene">
<div class="fim-cube">
<div class="face front">SHA-256</div>
<div class="face back">BASELINE</div>
<div class="face right">DIFF</div>
<div class="face left">AUDIT</div>
<div class="face top">HASH</div>
<div class="face bottom">SEAL</div>
</div>
</div>
<div>
<div class="fim-kicker">// FORENSIC FILE INTEGRITY CONSOLE</div>
<div class="fim-title-text">FILE INTEGRITY MANAGER</div>
<div class="fim-sub">BASELINE &middot; COMPARE &middot; CLASSIFY &middot; SEAL</div>
</div>
</div>
"""
