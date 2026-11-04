import re
import json
import hashlib
import secrets
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from workers import asgi

app = FastAPI(title="AMR ID")

# -- Crypto core: 160-bit entropy, Base58, checksum, version byte --
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
VERSION = "A"  # version byte

def b58encode(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    out = ""
    while num > 0:
        num, r = divmod(num, 58)
        out = BASE58[r] + out
    # leading zero bytes
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + out

def generate_id() -> str:
    raw = secrets.token_bytes(20)  # 160 bits
    payload = VERSION.encode() + raw
    checksum = hashlib.sha256(payload).digest()[:4]
    full = payload + checksum
    return b58encode(full)

OTP_RE = re.compile(r"\b(\d{4,8})\b")
RESERVED = {"admin", "root", "system", "amr", "support", "help", "test", "null", "undefined"}

async def tg_send(env, chat_id: str, text: str):
    import js
    url = f"https://api.telegram.org/bot{env.TELEGRAM_BOT_TOKEN}/sendMessage"
    body = json.dumps({"chat_id": chat_id, "text": text, "parse_mode": "HTML"})
    await js.fetch(url, to_js({"method": "POST", "headers": {"Content-Type": "application/json"}, "body": body}))

# -- Routes --

@app.get("/", response_class=HTMLResponse)
async def home():
    return HTMLResponse(INDEX_HTML)

@app.get("/id", response_class=HTMLResponse)
async def id_page():
    return HTMLResponse(ID_HTML)

@app.get("/talking", response_class=HTMLResponse)
async def talking_page():
    return HTMLResponse("<h1>AMR Talking</h1><p>Coming soon.</p>")

@app.post("/api/register")
async def register(request: Request):
    env = request.scope["env"]
    data = await request.json()
    nick = data.get("nick", "").strip().lower()
    password = data.get("password", "")
    if not nick or len(nick) < 3 or len(nick) > 24:
        raise HTTPException(400, "nick 3-24 chars")
    if not re.fullmatch(r"[a-z0-9._-]+", nick):
        raise HTTPException(400, "invalid chars")
    if nick in RESERVED:
        raise HTTPException(400, "reserved")
    if len(password) < 8:
        raise HTTPException(400, "password min 8")
    existing = await env.AMR_KV.get(f"nick:{nick}")
    if existing:
        raise HTTPException(409, "nick taken")
    amr_id = generate_id()
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    rec = json.dumps({"id": amr_id, "pw": pw_hash})
    await env.AMR_KV.put(f"nick:{nick}", rec)
    await env.AMR_KV.put(f"id:{amr_id}", json.dumps({"nick": nick}))
    return {"ok": True, "amr_id": amr_id, "nick": nick}

@app.post("/api/login")
async def login(request: Request):
    env = request.scope["env"]
    data = await request.json()
    nick = data.get("nick", "").strip().lower()
    password = data.get("password", "")
    rec = await env.AMR_KV.get(f"nick:{nick}")
    if not rec:
        raise HTTPException(404, "not found")
    rec = json.loads(rec)
    if hashlib.sha256(password.encode()).hexdigest() != rec["pw"]:
        raise HTTPException(401, "wrong password")
    return {"ok": True, "amr_id": rec["id"], "nick": nick}

@app.post("/api/resolve/{nick}")
async def resolve(nick: str, request: Request):
    env = request.scope["env"]
    rec = await env.AMR_KV.get(f"nick:{nick.lower()}")
    if not rec:
        raise HTTPException(404, "not found")
    return json.loads(rec)

@app.post("/webhook/sms")
async def sms_webhook(request: Request):
    env = request.scope["env"]
    body = await request.json()
    try:
        event = body["data"]
        if event.get("event_type") != "message.received":
            return {"ok": True}
        payload = event["payload"]
        to_number = payload["to"][0]["phone_number"]
        text = payload.get("text", "")
        from_number = payload["from"]["phone_number"]
    except Exception:
        raise HTTPException(400, "bad payload")
    mapping = await env.AMR_KV.get(f"num:{to_number}")
    if not mapping:
        return {"ok": True, "note": "unknown number"}
    mapping = json.loads(mapping)
    chat_id = mapping["chat_id"]
    codes = OTP_RE.findall(text)
    code = codes[0] if codes else text[:100]
    msg = f"<b>OTP</b> for {to_number}<br>From: {from_number}<br>Code: <code>{code}</code>"
    await tg_send(env, chat_id, msg)
    await env.AMR_KV.put(f"otp:{to_number}", json.dumps({"code": code, "text": text}), {"expirationTtl": 600})
    return {"ok": True}

@app.get("/otp/{number}")
async def get_otp(number: str, request: Request):
    env = request.scope["env"]
    data = await env.AMR_KV.get(f"otp:{number}")
    if not data:
        raise HTTPException(404, "no otp")
    return json.loads(data)

@app.post("/api/bind-number")
async def bind_number(request: Request):
    """Bind a temporary number to a chat_id for OTP delivery."""
    env = request.scope["env"]
    data = await request.json()
    await env.AMR_KV.put(f"num:{data['number']}", json.dumps({"chat_id": data["chat_id"]}))
    return {"ok": True}

Default = asgi.entrypoint(app)

# -- HTML --
INDEX_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AMR ID</title>
<style>
  :root{--bg:#0B0E11;--fg:#E8EAED;--accent:#00D4FF;--steel:#8A9199}
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px}
  h1{font-size:2rem;letter-spacing:.5px;margin-bottom:8px}
  .sub{color:var(--steel);margin-bottom:40px;font-size:.95rem}
  nav{display:flex;gap:24px;flex-wrap:wrap;justify-content:center}
  nav a{color:var(--accent);text-decoration:none;font-size:1.1rem;padding:12px 20px;border:1px solid var(--accent);border-radius:8px;transition:background .2s}
  nav a:hover{background:rgba(0,212,255,.1)}
  .tag{color:var(--steel);font-size:.75rem;margin-top:60px;letter-spacing:2px;text-transform:uppercase}
</style></head><body>
<h1>AMR ID</h1>
<p class="sub">Your identity. Not your number.</p>
<nav>
  <a href="/id">AMR ID</a>
  <a href="/talking">AMR Talking</a>
</nav>
<p class="tag">Craft meets intelligence</p>
</body></html>"""

ID_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AMR ID — Create</title>
<style>
  :root{--bg:#0B0E11;--fg:#E8EAED;--accent:#00D4FF;--steel:#8A9199;--err:#FF5C5C}
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
  .card{width:100%;max-width:400px}
  h1{font-size:1.5rem;margin-bottom:4px}
  .sub{color:var(--steel);font-size:.85rem;margin-bottom:28px}
  label{display:block;color:var(--steel);font-size:.8rem;margin-bottom:6px;letter-spacing:1px;text-transform:uppercase}
  input{width:100%;background:#141820;border:1px solid #2A2F36;color:var(--fg);padding:14px;border-radius:8px;font-size:1rem;margin-bottom:18px;outline:none}
  input:focus{border-color:var(--accent)}
  button{width:100%;background:var(--accent);color:#0B0E11;border:none;padding:14px;border-radius:8px;font-size:1rem;font-weight:600;cursor:pointer}
  button:hover{opacity:.9}
  .err{color:var(--err);font-size:.85rem;margin-bottom:12px;min-height:20px}
  .result{margin-top:24px;padding:16px;background:#141820;border-radius:8px;border:1px solid #2A2F36;word-break:break-all}
  .result .lbl{color:var(--steel);font-size:.75rem;text-transform:uppercase;letter-spacing:1px}
  .result .val{font-size:1.1rem;margin-top:4px;font-family:monospace}
  a.back{color:var(--steel);text-decoration:none;font-size:.85rem;display:inline-block;margin-bottom:20px}
  a.back:hover{color:var(--accent)}
  .tabs{display:flex;gap:8px;margin-bottom:24px}
  .tabs button{background:transparent;color:var(--steel);border:1px solid #2A2F36}
  .tabs button.active{background:var(--accent);color:#0B0E11;border-color:var(--accent)}
</style></head><body>
<div class="card">
  <a class="back" href="/">&#8592; AMR ID</a>
  <h1>Your AMR ID</h1>
  <p class="sub">One nick. Every platform.</p>
  <div class="tabs">
    <button class="active" onclick="show('reg')">Create</button>
    <button onclick="show('login')">Sign In</button>
  </div>
  <div id="reg">
    <label>Nick</label><input id="rn" placeholder="your.nick" autocomplete="off">
    <label>Password</label><input id="rp" type="password" placeholder="min 8 chars">
    <div class="err" id="re"></div>
    <button onclick="doReg()">Create ID</button>
  </div>
  <div id="login" style="display:none">
    <label>Nick</label><input id="ln" placeholder="your.nick" autocomplete="off">
    <label>Password</label><input id="lp" type="password">
    <div class="err" id="le"></div>
    <button onclick="doLogin()">Sign In</button>
  </div>
  <div class="result" id="res" style="display:none"><div class="lbl">Your AMR ID</div><div class="val" id="rid"></div></div>
</div>
<script>
function show(t){document.getElementById('reg').style.display=t==='reg'?'block':'none';document.getElementById('login').style.display=t==='login'?'block':'none';document.querySelectorAll('.tabs button').forEach((b,i)=>b.classList.toggle('active',(t==='reg'&&i===0)||(t==='login'&&i===1)));}
async function doReg(){const n=document.getElementById('rn').value,p=document.getElementById('rp').value;document.getElementById('re').textContent='';try{const r=await fetch('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({nick:n,password:p})});const d=await r.json();if(!r.ok)throw new Error(d.detail||'error');document.getElementById('rid').textContent=d.amr_id;document.getElementById('res').style.display='block';}catch(e){document.getElementById('re').textContent=e.message;}}
async function doLogin(){const n=document.getElementById('ln').value,p=document.getElementById('lp').value;document.getElementById('le').textContent='';try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({nick:n,password:p})});const d=await r.json();if(!r.ok)throw new Error(d.detail||'error');document.getElementById('rid').textContent=d.amr_id;document.getElementById('res').style.display='block';}catch(e){document.getElementById('le').textContent=e.message;}}
</script></body></html>"""
