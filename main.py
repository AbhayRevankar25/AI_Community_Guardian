import hashlib
import json
import os
import random
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from actions import get_actions
from ai_engine import classify as ai_classify
from rules import rule_check
from spam_memory import combined_pattern_score, store_observation
from safe_circle import decrypt_status, encrypt_status, get_history, reset_history, store_shared_status
from user_habits import compute_unusual, update_profile
from zero_trust import combine as zero_trust_combine


app = FastAPI(title="AI Community Guardian")


class AnalyzeRequest(BaseModel):
    text: str
    elderly_mode: bool = False
    location: str | None = None
    user_id: str | None = None


class AlertOut(BaseModel):
    input_hash: str
    location: str
    category: str
    summary: str
    trust_score: int
    severity: str
    actions: list[str]
    created_at: str
    explanation: list[str]


ALERTS: list[AlertOut] = []


class SafeCircleShareRequest(BaseModel):
    status_text: str
    passphrase: str
    location: str | None = None


class SafeCircleReceiveRequest(BaseModel):
    share_code: str
    passphrase: str


def _dump_model(a: AlertOut) -> dict:
    # Pydantic v1 uses `.dict()`, v2 prefers `.model_dump()`.
    if hasattr(a, "model_dump"):
        return a.model_dump()  # type: ignore[attr-defined]
    return a.dict()  # type: ignore[call-arg]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _input_hash(text: str) -> str:
    normalized = (text or "").strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _load_dataset_locations() -> list[str]:
    path = os.path.join(os.path.dirname(__file__), "data.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        locs: list[str] = []
        for item in data if isinstance(data, list) else []:
            loc = str(item.get("location", "")).strip()
            if loc:
                locs.append(loc)
        return locs
    except Exception:
        return ["Bangalore", "Mumbai", "Delhi"]


LOCATIONS = _load_dataset_locations()


def _synthetic_location(override: str | None) -> str:
    if override and override.strip():
        return override.strip()
    return random.choice(LOCATIONS)


def _dedupe_alerts(alerts: list[AlertOut]) -> list[AlertOut]:
    """
    Simple duplicate reduction:
    - same input_hash + category means it is likely the same alert content.
    - keep the newest.
    """
    seen: dict[tuple[str, str], AlertOut] = {}
    for a in sorted(alerts, key=lambda x: x.created_at, reverse=True):
        key = (a.input_hash, a.category)
        if key not in seen:
            seen[key] = a
    return list(seen.values())


from templates import page as _page


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    body = """
    <div class="hero">
      <h1>AI Community Guardian</h1>
      <p>Zero Trust cyber safety assistant. Classify threats, view filtered alerts, and share encrypted updates with trusted guardians.</p>
      <div class="hero-links">
        <a href="/analyze-page">Analyze a Message</a>
        <a href="/alerts-page" class="outline">View Alerts</a>
        <a href="/safe-circle-page" class="outline">Safe Circle</a>
      </div>
    </div>
    """
    return _page("Home", "/", body)


_ANALYZE_SCRIPT = """
      const userIdKey = 'client_user_id';
      let clientUserId = localStorage.getItem(userIdKey);
      if (!clientUserId){
        clientUserId = (window.crypto && crypto.randomUUID) ? crypto.randomUUID() : ('u_'+Date.now());
        localStorage.setItem(userIdKey, clientUserId);
      }
      const textEl = document.getElementById('text');
      const elderlyEl = document.getElementById('elderly');
      const analyzeBtn = document.getElementById('analyzeBtn');
      const loadingEl = document.getElementById('loading');
      const errorBox = document.getElementById('errorBox');
      const charCount = document.getElementById('charCount');
      if (textEl) textEl.addEventListener('input', () => { charCount.textContent = textEl.value.length + ' chars'; });
      function setError(msg){ if (!msg){ errorBox.style.display='none'; return; } errorBox.style.display='block'; errorBox.textContent=msg; }
      function setLoading(b){ analyzeBtn.disabled=b; loadingEl.style.display=b?'flex':'none'; }
      function badgeClassForThreat(t){ t=(t||'').toLowerCase(); if(t==='phishing')return 'danger'; if(t==='scam')return 'warn'; if(t==='malware')return 'danger'; if(t==='safe')return 'ok'; return 'low'; }
      function badgeClassForSeverity(s){ s=(s||'').toUpperCase(); if(s==='HIGH')return 'danger'; if(s==='MEDIUM')return 'warn'; return 'low'; }
      function parseTrustScore(ts){ if(ts==null||ts===undefined)return 0; if(typeof ts==='number')return Math.max(0,Math.min(100,Math.round(ts))); const n=parseFloat(String(ts).replace('%','')); return Number.isNaN(n)?0:Math.max(0,Math.min(100,Math.round(n))); }
      function renderList(ul,items,emptyEl){ ul.innerHTML=''; if(!items||!items.length){ emptyEl.style.display='block'; return; } emptyEl.style.display='none'; items.forEach(i=>{ const li=document.createElement('li'); li.textContent=i; ul.appendChild(li); }); }
      function clearResult(){ const s=document.getElementById('summary'); const e=document.getElementById('elderlyOut'); const tb=document.getElementById('threatBadge'); const sb=document.getElementById('severityBadge'); const tr=document.getElementById('trustBar'); const tp=document.getElementById('trustPill'); const ex=document.getElementById('explanation'); const ac=document.getElementById('actions'); const ee=document.getElementById('explanationEmpty'); const ae=document.getElementById('actionsEmpty'); if(s)s.textContent='Waiting...'; if(e)e.innerHTML='<span class=\\"muted\\">--</span>'; if(tb){ tb.className='badge low'; tb.querySelector('span:last-child').textContent='Threat: --'; } if(sb){ sb.className='badge low'; sb.querySelector('span:last-child').textContent='Severity: --'; } if(tr)tr.style.width='0%'; if(tp)tp.textContent='Trust: --%'; if(ex)ex.innerHTML=''; if(ac)ac.innerHTML=''; if(ee)ee.style.display='none'; if(ae)ae.style.display='none'; }
      function clearAll(){ textEl.value=''; elderlyEl.checked=false; setError(null); clearResult(); charCount.textContent='0 chars'; }
      async function analyze(){ const text=textEl.value||''; setError(null); if(!text.trim()){ setError('Please paste some message text.'); return; } setLoading(true); try{ const r=await fetch('/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text,elderly_mode:elderlyEl.checked,user_id:clientUserId})}); const d=await r.json(); if(!r.ok){ setError(d.detail||'Request failed'); return; } const threat=d['Threat']||'--'; const severity=d['Severity']||'--'; const trust=parseTrustScore(d['Trust Score']); const tb=document.getElementById('threatBadge'); const sb=document.getElementById('severityBadge'); if(tb){ tb.className='badge '+badgeClassForThreat(threat); tb.querySelector('span:last-child').textContent='Threat: '+threat; } if(sb){ sb.className='badge '+badgeClassForSeverity(severity); sb.querySelector('span:last-child').textContent='Severity: '+severity; } document.getElementById('trustBar').style.width=trust+'%'; document.getElementById('trustPill').textContent='Trust: '+trust+'%'; document.getElementById('summary').textContent=d['Summary']||'—'; const eo=document.getElementById('elderlyOut'); eo.innerHTML=d['Elderly Friendly']?d['Elderly Friendly']:'<span class=\\"muted\\">--</span>'; renderList(document.getElementById('explanation'),d['Explanation']||[],document.getElementById('explanationEmpty')); renderList(document.getElementById('actions'),d['Actions']||[],document.getElementById('actionsEmpty')); } finally{ setLoading(false); } }
      clearResult();
"""
@app.get("/analyze-page", response_class=HTMLResponse)
def analyze_page() -> str:
    body = '''
    <div class="card">
      <div class="section-title"><strong>Analyze a message</strong><span class="pill" id="charCount">0 chars</span></div>
      <div class="hint">Tip: include keywords like "click here", "urgent action required", or "enable macros".</div>
      <div style="margin-top:10px;"><textarea id="text" placeholder="Paste phishing/scam/malware text here..."></textarea></div>
      <div class="row">
        <div class="grow"><label><input type="checkbox" id="elderly"/> Elderly-friendly mode</label></div>
        <button class="btn secondary" onclick="clearAll()">Clear</button>
        <button class="btn" id="analyzeBtn" onclick="analyze()">Analyze</button>
        <div class="loading" id="loading"><span class="spinner"></span><span>Analyzing...</span></div>
      </div>
      <div class="error" id="errorBox"></div>
      <div style="margin-top:20px;">
        <div class="section-title"><strong>Result</strong><span class="pill" id="trustPill">Trust: --%</span></div>
        <div class="badges" style="margin-bottom:12px">
          <div class="badge low" id="threatBadge"><span class="dot"></span><span>Threat: --</span></div>
          <div class="badge low" id="severityBadge"><span class="dot"></span><span>Severity: --</span></div>
        </div>
        <div class="progress"><div class="bar" id="trustBar"></div></div>
        <div class="kv" style="margin-top:12px">
          <div class="box"><div class="k">Summary</div><div class="v" id="summary">Waiting...</div></div>
          <div class="box"><div class="k">Elderly Friendly</div><div class="v" id="elderlyOut"><span class="muted">--</span></div></div>
        </div>
        <div class="box" style="margin-top:12px"><div style="font-weight:700;margin-bottom:6px">Explanation</div><ul id="explanation"></ul><div class="muted" id="explanationEmpty" style="display:none">No explanation.</div></div>
        <div class="box" style="margin-top:12px"><div style="font-weight:700;margin-bottom:6px">Recommended Actions</div><ul id="actions"></ul><div class="muted" id="actionsEmpty" style="display:none">No actions.</div></div>
      </div>
      <p class="footer-note"><a href="/alerts-page" style="color:var(--brand)">View recent alerts</a></p>
    </div>
    ''' + "<script>" + _ANALYZE_SCRIPT + "</script>"
    return _page("Analyze", "/analyze-page", body)


@app.get("/alerts-page", response_class=HTMLResponse)
def alerts_page() -> str:
    body = '''
    <div class="card">
      <div class="section-title"><strong>Recent important alerts</strong><span class="pill">Filtered (HIGH/MEDIUM)</span><button class="btn secondary" onclick="loadAlerts()" id="refreshBtn">Refresh</button></div>
      <div class="alerts-list" id="alertsList"><div class="muted">Loading...</div></div>
      <p class="footer-note">Alerts are filtered to reduce alert fatigue. <a href="/analyze-page" style="color:var(--brand)">Analyze a message</a></p>
    </div>
    <script>
      async function loadAlerts(){
        const list = document.getElementById("alertsList");
        const btn = document.getElementById("refreshBtn");
        list.innerHTML = "<div class=\\"muted\\">Loading...</div>";
        btn.disabled = true;
        try {
          const r = await fetch("/alerts?limit=10&t=" + Date.now(), { cache: "no-store" });
          const d = await r.json();
          if (!d.alerts || !d.alerts.length){ list.innerHTML = "<div class=\\"muted\\">No recent HIGH/MEDIUM alerts. Analyze a message to create one.</div>"; return; }
          list.innerHTML = d.alerts.map(a => `<div class="alert-item"><div class="top"><div class="t">${a.category}</div><div class="time">${new Date(a.created_at).toLocaleString()}</div></div><div class="cat">${a.summary||""}</div><div class="cat"><span class="muted">Severity:</span> ${a.severity}</div></div>`).join("");
        } finally { btn.disabled = false; }
      }
      loadAlerts();
    </script>
    '''
    return _page("Alerts", "/alerts-page", body)


@app.get("/safe-circle-page", response_class=HTMLResponse)
def safe_circle_page() -> str:
    body = '''
    <div class="card">
      <div class="section-title"><strong>Safe Circle (Simulated)</strong><span class="pill">Privacy-first encryption</span></div>
      <div class="hint">Two independent sections: encrypt a status message above, or decrypt a share code below.</div>

      <div class="section-title" style="margin-top:24px"><strong>1. Encrypt</strong><span class="pill">Create share code</span></div>
      <div style="margin-top:12px;">
        <div class="k" style="margin-bottom:6px">Status message</div>
        <textarea id="safeStatus" placeholder="Example: Please verify my account activity. I suspect a phishing attempt." style="min-height:80px"></textarea>
      </div>
      <div class="row" style="margin-top:12px">
        <div class="grow"><div class="k" style="margin-bottom:6px">Trusted passphrase</div><input id="safePassphrase" type="password" placeholder="Create a passphrase (>=4 chars)"/></div>
        <div style="align-self:flex-end"><button class="btn" onclick="createSafeShare()">Create Encrypted Update</button></div>
      </div>
      <div style="margin-top:12px"><div class="k" style="margin-bottom:6px">Encrypted share code (copy & share)</div><textarea id="safeShareCode" readonly placeholder="Share code will appear here..." style="min-height:60px"></textarea></div>

      <div class="section-title" style="margin-top:28px"><strong>2. Decrypt</strong><span class="pill">Guardian decode</span></div>
      <div style="margin-top:12px;">
        <div class="k" style="margin-bottom:6px">Paste share code</div>
        <textarea id="decryptShareCode" placeholder="Paste the encrypted share code from the sender..." style="min-height:60px"></textarea>
      </div>
      <div class="row" style="margin-top:12px">
        <div class="grow"><div class="k" style="margin-bottom:6px">Passphrase</div><input id="guardianPassphrase" type="password" placeholder="Enter passphrase shared by sender"/></div>
        <div style="align-self:flex-end"><button class="btn secondary" onclick="decodeSafeShare()">Decode Update</button></div>
      </div>
      <div class="box" style="margin-top:12px"><div class="k">Decoded status</div><div id="decodedSafe" class="muted">Waiting for decode...</div></div>

      <p class="footer-note"><a href="/analyze-page" style="color:var(--brand)">Back to Analyze</a></p>
    </div>
    <script>
      const userIdKey="client_user_id"; let clientUserId=localStorage.getItem(userIdKey); if(!clientUserId){ clientUserId=(window.crypto&&crypto.randomUUID?crypto.randomUUID():("u_"+Date.now())); localStorage.setItem(userIdKey,clientUserId); }
      async function createSafeShare(){
        const t=document.getElementById("safeStatus").value, p=document.getElementById("safePassphrase").value, el=document.getElementById("safeShareCode");
        if(!t.trim()){ alert("Enter a status message."); return; } if(!p||p.length<4){ alert("Passphrase >= 4 chars."); return; }
        el.value="Creating..."; const r=await fetch("/safe-circle/share",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({status_text:t,passphrase:p})}); const d=await r.json();
        if(!r.ok){ el.value=""; alert(d.detail||"Failed"); return; } el.value=d.share_code;
      }
      async function decodeSafeShare(){
        const c=document.getElementById("decryptShareCode").value, p=document.getElementById("guardianPassphrase").value, el=document.getElementById("decodedSafe");
        if(!c.trim()){ alert("Paste a share code."); return; } if(!p){ alert("Enter passphrase."); return; }
        el.textContent="Decoding..."; const r=await fetch("/safe-circle/receive",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({share_code:c,passphrase:p})}); const d=await r.json();
        if(!r.ok){ el.textContent="Decode failed."; return; } el.textContent=(d.status_text||"")+"\\n\\nLocation: "+(d.location||"--")+"\\nSeverity: "+(d.severity||"--");
      }
    </script>
    '''
    return _page("Safe Circle", "/safe-circle-page", body)


@app.post("/analyze")
def analyze(req: AnalyzeRequest) -> dict:
    if not req.text or not req.text.strip():
        raise HTTPException(status_code=400, detail="`text` must not be empty")

    location = _synthetic_location(req.location)
    input_hash = _input_hash(req.text)
    now = datetime.now(timezone.utc)
    user_id = (req.user_id or "demo-user").strip() or "demo-user"
    created_at = now.isoformat()

    ai_result = ai_classify(req.text)
    # Rule-based fallback always available (deterministic).
    rule_category, rule_conf, rule_reasons = rule_check(req.text)
    rule_result = {"category": rule_category, "confidence": rule_conf, "reasons": rule_reasons}

    # If Gemini is unavailable, we still provide explanation from rules.
    if ai_result is None:
        summary = "Verification-based analysis detected suspicious indicators. Review carefully."
        # Mask vendor/tooling wording in user-facing output.
        ai_result = {
            "category": rule_category,
            "confidence": rule_conf,
            "reason": "AI analysis unavailable; using verification rules only.",
        }
    else:
        summary = str(ai_result.get("summary") or "Threat indicators detected.")

    zt = zero_trust_combine(ai_result=ai_result, rule_result=rule_result)

    # --- Self-learning spam memory (privacy-first) ---
    # Learned similarity against previously detected suspicious messages.
    pattern = combined_pattern_score(req.text)
    pattern_score = int(pattern.get("pattern_score", 0))
    pattern_category = str(pattern.get("match_category", "unknown")).lower().strip()
    signature_found = pattern.get("signature_found") or []

    # Dynamic trust scoring (base):
    # combine Zero Trust confidence with spam-memory evidence.
    # (Keep it explainable and demo-friendly.)
    base_trust = int(round(zt.trust_score * 0.75 + pattern_score * 0.25))
    base_trust = max(0, min(100, base_trust))

    # Contextual relevance (privacy-first):
    # compute a lightweight per-user "unusual activity" score from aggregated behavior.
    habit = compute_unusual(user_id=user_id, location=location, at=now)
    habit_score = int(habit.get("score", 0))
    habit_score = max(0, min(100, habit_score))

    # Integrate habit evidence into Trust Score only.
    # If we don't have enough history (demo "cold start"), avoid penalizing the
    # base trust. This prevents early MEDIUM outcomes when AI/rules are already strong.
    habit_explanations = habit.get("explanations") or []
    cold_start = any("Not enough data for behavior analysis" in str(x) for x in habit_explanations)
    if habit_score == 0 and cold_start:
        final_trust = base_trust
    else:
        final_trust = int(round(base_trust * 0.7 + habit_score * 0.3))
    final_trust = max(0, min(100, final_trust))

    # If the spam-memory/signature is confident, it can override the category.
    final_category = zt.category
    if base_trust >= 65 and pattern_category in {"phishing", "scam", "malware"}:
        final_category = pattern_category

    # Recompute severity from final trust (and keep LOW/MEDIUM/HIGH consistent).
    if final_category == "safe":
        final_severity = "LOW"
    else:
        if final_trust >= 80:
            final_severity = "HIGH"
        elif final_trust >= 60:
            final_severity = "MEDIUM"
        else:
            final_severity = "LOW"

    # Explain why we changed/confirmed decision.
    explanation = list(zt.explanation)
    if pattern_score >= 60:
        explanation.append(f"Matches prior suspicious message patterns (spam memory). Score: {pattern_score}/100.")
    if signature_found:
        explanation.append(f"Threat signature matched keywords: {', '.join(signature_found[:5])}.")
    if habit_score > 0:
        explanation.extend(habit.get("explanations") or [])

    actions = get_actions(final_category)

    elderly_output = "SAFE" if final_category == "safe" else "NOT SAFE"

    alert = AlertOut(
        input_hash=input_hash,
        location=location,
        category=final_category,
        summary=summary,
        trust_score=final_trust,
        severity=final_severity,
        actions=actions,
        created_at=created_at,
        explanation=explanation,
    )
    ALERTS.append(alert)

    # Update privacy-first contextual signals AFTER producing the alert.
    update_profile(user_id=user_id, location=location, severity=alert.severity, at=now)

    # Update spam memory AFTER producing the alert.
    # Privacy-first: we store token fingerprints, not raw text.
    # Important: store spam-memory observations based on the *base* trust signal,
    # so the learned pattern layer still gets fed even when habit-scoring
    # changes the final alert severity in early demo interactions.
    if alert.category == "safe":
        memory_severity = "LOW"
    else:
        if base_trust >= 80:
            memory_severity = "HIGH"
        elif base_trust >= 60:
            memory_severity = "MEDIUM"
        else:
            memory_severity = "LOW"

    store_observation(req.text, category=alert.category, severity=memory_severity)

    return {
        "Threat": alert.category,
        "Severity": alert.severity,
        "Trust Score": f"{alert.trust_score}%",
        "Summary": summary,
        "Explanation": alert.explanation,
        "Actions": actions,
        "Elderly Friendly": elderly_output if req.elderly_mode else None,
    }


@app.get("/alerts")
def get_alerts(limit: int = 10) -> dict:
    total = len(ALERTS)
    deduped = _dedupe_alerts(ALERTS)

    # Alert fatigue reduction: only return important items.
    important = [a for a in deduped if a.severity in ("HIGH", "MEDIUM")]
    important = sorted(important, key=lambda x: x.created_at, reverse=True)[: max(1, limit)]

    return {
        "message": f"Showing {len(important)} important alerts (filtered from {total})",
        "alerts": [_dump_model(a) for a in important],
    }


@app.post("/safe-circle/share")
def safe_circle_share(req: SafeCircleShareRequest) -> dict:
    text = (req.status_text or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="`status_text` must not be empty")
    if not (req.passphrase or "").strip() or len(req.passphrase.strip()) < 4:
        raise HTTPException(status_code=400, detail="`passphrase` must be at least 4 characters")

    location = _synthetic_location(req.location)
    # For demo: severity derived from the text's classification intent (rules only).
    cat, conf, _ = rule_check(text)
    severity = "HIGH" if conf >= 70 and cat in ("phishing", "scam", "malware") else "MEDIUM"

    share_code = encrypt_status(text, passphrase=req.passphrase, location=location, severity=severity)
    store_shared_status(share_code=share_code, location=location, severity=severity)

    return {"share_code": share_code, "location": location, "severity": severity}


@app.post("/safe-circle/receive")
def safe_circle_receive(req: SafeCircleReceiveRequest) -> dict:
    try:
        payload = decrypt_status(req.share_code, passphrase=req.passphrase)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {
        "status_text": payload.get("status_text", ""),
        "location": payload.get("location", ""),
        "severity": payload.get("severity", ""),
        "created_at": payload.get("created_at", ""),
    }


@app.get("/safe-circle/history")
def safe_circle_history(limit: int = 5) -> dict:
    items = get_history(limit=limit)
    return {"alerts": [{"created_at": i.created_at, "location": i.location, "severity": i.severity} for i in items]}


if __name__ == "__main__":
    # Allows: `python main.py` quick start (still best to use uvicorn in practice).
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
