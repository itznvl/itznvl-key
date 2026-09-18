"""
ITZNVL KEY SYSTEM — Flask + Turso (libSQL)
Deploy Render free tier.
"""
import os, time, secrets, hmac, hashlib, sqlite3, threading
from functools import wraps
from flask import (Flask, request, jsonify, render_template_string,
                   redirect, session)
from datetime import datetime

# ============================================================
# CONFIG
# ============================================================
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "itznvl2026")
SECRET_KEY     = os.environ.get("SECRET_KEY", secrets.token_hex(32))
HMAC_SECRET    = os.environ.get("HMAC_SECRET", "itznvl-hmac-change-me")
KEY_DAYS       = int(os.environ.get("KEY_DAYS", "1"))
TURSO_URL      = os.environ.get("TURSO_URL", "")
TURSO_TOKEN    = os.environ.get("TURSO_TOKEN", "")
DB_PATH        = os.environ.get("DB_PATH", "keys.db")
RATE_LIMIT_MAX = int(os.environ.get("RATE_LIMIT_MAX", "5"))
RATE_LIMIT_WIN = int(os.environ.get("RATE_LIMIT_WIN", "3600"))

app = Flask(__name__)
app.secret_key = SECRET_KEY

# ============================================================
# DB LAYER — Turso hoặc SQLite fallback
# ============================================================
db_lock = threading.Lock()
USE_TURSO = bool(TURSO_URL and TURSO_TOKEN)

if USE_TURSO:
    try:
        import libsql_experimental as libsql
        print("[+] Using Turso (libSQL)")
    except ImportError:
        print("[!] libsql_experimental not installed — falling back to SQLite")
        USE_TURSO = False

def db():
    if USE_TURSO:
        conn = libsql.connect(TURSO_URL, auth_token=TURSO_TOKEN)
        return conn
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def q(sql, params=(), fetch=None, commit=False):
    """Helper: chạy query, trả về kết quả hoặc None.
    fetch: 'one' | 'all' | None"""
    with db_lock:
        conn = db()
        try:
            cur = conn.cursor() if USE_TURSO else conn
            cur.execute(sql, params)
            result = None
            if fetch == "one":
                row = cur.fetchone()
                if row is not None:
                    if not USE_TURSO and hasattr(row, "keys"):
                        result = dict(row)
                    else:
                        cols = [d[0] for d in cur.description]
                        result = dict(zip(cols, row))
            elif fetch == "all":
                rows = cur.fetchall()
                if not USE_TURSO and rows and hasattr(rows[0], "keys"):
                    result = [dict(r) for r in rows]
                else:
                    cols = [d[0] for d in cur.description]
                    result = [dict(zip(cols, r)) for r in rows]
            if commit:
                conn.commit()
            return result
        finally:
            try: conn.close()
            except Exception: pass

def init_db():
    q("""CREATE TABLE IF NOT EXISTS keys (
        key         TEXT PRIMARY KEY,
        hwid        TEXT,
        fingerprint TEXT,
        activated   INTEGER DEFAULT 0,
        expiry      INTEGER DEFAULT 0,
        claimed_at  INTEGER DEFAULT 0,
        note        TEXT,
        ip          TEXT
    )""", commit=True)
    q("""CREATE TABLE IF NOT EXISTS rate (
        ident  TEXT,
        ts     INTEGER
    )""", commit=True)

# ============================================================
# UTIL
# ============================================================
def gen_key(prefix="ITZ"):
    return prefix + "-" + secrets.token_hex(8).upper()

def sign_payload(data: dict) -> str:
    msg = "|".join(f"{k}={data[k]}" for k in sorted(data.keys()))
    return hmac.new(HMAC_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()

def fingerprint(hwid, ua, ip):
    ip_class = ".".join(ip.split(".")[:2]) if "." in ip else ip
    raw = f"{hwid}|{ua}|{ip_class}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

def rate_check(ident):
    now = int(time.time())
    q("DELETE FROM rate WHERE ts < ?", (now - RATE_LIMIT_WIN,), commit=True)
    r = q("SELECT COUNT(*) AS c FROM rate WHERE ident=?", (ident,), fetch="one")
    cnt = r["c"] if r else 0
    if cnt >= RATE_LIMIT_MAX:
        return True
    q("INSERT INTO rate (ident, ts) VALUES (?, ?)", (ident, now), commit=True)
    return False

def add_keys(n, note=""):
    created = []
    for _ in range(n):
        k = gen_key()
        try:
            q("INSERT INTO keys (key, note) VALUES (?, ?)", (k, note), commit=True)
            created.append(k)
        except Exception:
            continue
    return created

def client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff: return xff.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"

# ============================================================
# HTML — LANDING
# ============================================================
LANDING = """<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ITZNVL MENU — GET KEY</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  background:#05070d;color:#e6f6ff;min-height:100vh;overflow-x:hidden;
  -webkit-font-smoothing:antialiased}
.bg{position:fixed;inset:0;z-index:0;overflow:hidden;
  background:radial-gradient(circle at 20% 10%,rgba(0,180,255,.18),transparent 45%),
             radial-gradient(circle at 85% 80%,rgba(120,0,255,.15),transparent 45%),
             radial-gradient(circle at 50% 50%,rgba(0,80,140,.08),transparent 65%),#05070d}
.bg::before{content:"";position:absolute;inset:-50%;
  background:conic-gradient(from 0deg,transparent,rgba(0,200,255,.06),transparent 30%);
  animation:spin 30s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.wrap{position:relative;z-index:1;max-width:720px;margin:0 auto;padding:60px 24px 80px}
.logo{display:inline-flex;align-items:center;gap:10px;padding:8px 16px;border-radius:100px;
  background:rgba(0,180,255,.08);border:1px solid rgba(0,180,255,.3);
  font-size:13px;font-weight:600;letter-spacing:2px;color:#00d9ff;margin-bottom:32px}
.logo .dot{width:8px;height:8px;border-radius:50%;background:#00ff88;
  box-shadow:0 0 12px #00ff88;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(.8)}}
h1{font-size:clamp(38px,8vw,64px);font-weight:900;line-height:1.05;
  letter-spacing:-2px;margin-bottom:20px;
  background:linear-gradient(135deg,#fff 0%,#00d9ff 60%,#7b5cff 100%);
  -webkit-background-clip:text;background-clip:text;color:transparent}
.sub{font-size:17px;color:#8ba3b8;line-height:1.6;margin-bottom:40px;max-width:520px}
.card{background:linear-gradient(160deg,rgba(10,20,35,.9),rgba(5,10,20,.95));
  border:1px solid rgba(0,180,255,.18);border-radius:20px;padding:32px;
  box-shadow:0 24px 80px rgba(0,120,255,.08),inset 0 1px 0 rgba(255,255,255,.05);
  backdrop-filter:blur(12px);margin-bottom:24px;
  opacity:0;transform:translateY(30px);
  animation:rise .6s cubic-bezier(.2,.8,.3,1) forwards}
.card:nth-of-type(1){animation-delay:.1s}
.card:nth-of-type(2){animation-delay:.2s}
.card:nth-of-type(3){animation-delay:.3s}
@keyframes rise{to{opacity:1;transform:translateY(0)}}
.label{font-size:12px;letter-spacing:2px;color:#00d9ff;font-weight:700;
  margin-bottom:12px;text-transform:uppercase}
.hwid{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;color:#8ba3b8;
  background:rgba(0,0,0,.4);padding:10px 14px;border-radius:8px;
  border:1px solid rgba(255,255,255,.06);word-break:break-all;line-height:1.5}
.btn{display:flex;align-items:center;justify-content:center;gap:10px;width:100%;
  padding:20px;border:none;border-radius:14px;font-size:17px;font-weight:800;
  letter-spacing:.5px;cursor:pointer;
  background:linear-gradient(135deg,#00a8ff,#0066ff);color:#fff;
  box-shadow:0 12px 40px rgba(0,120,255,.4),inset 0 1px 0 rgba(255,255,255,.2);
  transition:all .25s cubic-bezier(.2,.8,.3,1);position:relative;overflow:hidden}
.btn::after{content:"";position:absolute;inset:0;
  background:linear-gradient(120deg,transparent,rgba(255,255,255,.25),transparent);
  transform:translateX(-100%)}
.btn:hover::after{transform:translateX(100%);transition:transform .8s}
.btn:hover{transform:translateY(-2px);box-shadow:0 16px 50px rgba(0,120,255,.55)}
.btn:active{transform:translateY(0)}
.btn.pulse{animation:btnPulse 2.2s infinite}
@keyframes btnPulse{0%,100%{box-shadow:0 12px 40px rgba(0,120,255,.4)}
  50%{box-shadow:0 12px 55px rgba(0,200,255,.7),0 0 0 8px rgba(0,180,255,.06)}}
.key-box{background:linear-gradient(135deg,rgba(0,255,136,.08),rgba(0,180,255,.08));
  border:2px solid #00ff88;border-radius:16px;padding:26px 20px;text-align:center;
  margin:20px 0;box-shadow:0 0 40px rgba(0,255,136,.15),inset 0 1px 0 rgba(255,255,255,.05);
  animation:rise .5s cubic-bezier(.2,.8,.3,1) forwards}
.key-val{font-family:ui-monospace,Menlo,Consolas,monospace;
  font-size:clamp(20px,5vw,28px);font-weight:800;color:#00ff88;letter-spacing:2px;
  word-break:break-all;text-shadow:0 0 20px rgba(0,255,136,.5)}
.copy-row{display:flex;gap:8px;margin-top:16px}
.copy-btn{flex:1;padding:14px;border-radius:10px;border:1px solid rgba(0,255,136,.4);
  background:rgba(0,255,136,.08);color:#00ff88;font-size:14px;font-weight:700;
  cursor:pointer;transition:all .2s}
.copy-btn:hover{background:rgba(0,255,136,.18)}
.copy-btn.done{background:#00ff88;color:#05070d}
.meta{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:20px}
.meta-item{background:rgba(0,0,0,.3);border-radius:10px;padding:14px;
  border:1px solid rgba(255,255,255,.05)}
.meta-item .k{font-size:11px;color:#4a5f75;letter-spacing:1.5px;
  text-transform:uppercase;margin-bottom:6px}
.meta-item .v{font-size:15px;color:#e6f6ff;font-weight:700}
.steps{counter-reset:s;list-style:none}
.steps li{counter-increment:s;padding:14px 0 14px 44px;position:relative;
  border-bottom:1px solid rgba(255,255,255,.05);color:#a8bdd0;font-size:15px}
.steps li:last-child{border:none}
.steps li::before{content:counter(s);position:absolute;left:0;top:12px;
  width:28px;height:28px;border-radius:50%;
  background:rgba(0,180,255,.12);border:1px solid rgba(0,180,255,.4);
  color:#00d9ff;font-weight:800;font-size:13px;
  display:flex;align-items:center;justify-content:center}
.footer{text-align:center;color:#3a4a5c;font-size:12px;margin-top:40px;letter-spacing:1px}
.err{background:rgba(255,60,60,.08);border:1px solid rgba(255,60,60,.3);
  color:#ff8b8b;padding:16px;border-radius:10px;font-size:14px;text-align:center}
.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%) translateY(100px);
  background:#00ff88;color:#05070d;padding:14px 28px;border-radius:100px;
  font-weight:800;font-size:14px;box-shadow:0 12px 40px rgba(0,255,136,.4);
  transition:transform .4s cubic-bezier(.2,.8,.3,1);z-index:99}
.toast.show{transform:translateX(-50%) translateY(0)}
</style>
</head>
<body>
<div class="bg"></div>
<div class="wrap">
  <div class="logo"><span class="dot"></span> ITZNVL MENU</div>
  <h1>Get your key.<br>Vào trận ngay.</h1>
  <p class="sub">Hệ thống cấp key tự động. Mỗi key bị khoá cứng vào 1 thiết bị duy nhất.</p>

  <div class="card">
    <div class="label">Device HWID</div>
    <div class="hwid">{{ hwid or "Không tìm thấy — mở link từ menu ITZNVL" }}</div>
  </div>

  {% if error %}
    <div class="card"><div class="err">{{ error }}</div></div>
  {% endif %}

  {% if key %}
  <div class="card">
    <div class="label">Your Key</div>
    <div class="key-box">
      <div class="key-val" id="keyval">{{ key }}</div>
    </div>
    <div class="copy-row">
      <button class="copy-btn" onclick="copyKey()">📋 SAO CHÉP KEY</button>
    </div>
    <div class="meta">
      <div class="meta-item"><div class="k">Hạn dùng</div><div class="v">{{ days }} ngày</div></div>
      <div class="meta-item"><div class="k">Hết hạn</div><div class="v">{{ expiry_str }}</div></div>
    </div>
  </div>
  {% else %}
  <div class="card">
    <form method="POST">
      <input type="hidden" name="hwid" value="{{ hwid }}">
      <button class="btn pulse" type="submit">🔑 GET KEY</button>
    </form>
  </div>
  {% endif %}

  <div class="card">
    <div class="label">Hướng dẫn</div>
    <ol class="steps">
      {% if not key %}
      <li>Nhấn <b>GET KEY</b> để nhận key</li>
      {% else %}
      <li>Sao chép key ở trên</li>
      {% endif %}
      <li>Quay lại game ITZNVL MENU</li>
      <li>Dán key vào ô kích hoạt</li>
      <li>Bấm KÍCH HOẠT — vào trận</li>
    </ol>
  </div>

  <div class="footer">ITZNVL © 2026 · Anti-bypass protected</div>
</div>
<div class="toast" id="toast">✓ Đã sao chép</div>
<script>
function copyKey(){
  const k = document.getElementById('keyval').textContent.trim();
  navigator.clipboard.writeText(k).then(()=>{
    const t = document.getElementById('toast');
    t.classList.add('show');
    setTimeout(()=>t.classList.remove('show'), 1800);
    const b = document.querySelector('.copy-btn');
    b.classList.add('done');
    b.textContent = '✓ ĐÃ SAO CHÉP';
  });
}
</script>
</body>
</html>
"""

# ============================================================
# HTML — ADMIN
# ============================================================
ADMIN = """<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ITZNVL Admin</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#05070d;
  color:#e6f6ff;min-height:100vh}
.bg{position:fixed;inset:0;z-index:0;
  background:radial-gradient(circle at 15% 5%,rgba(0,180,255,.15),transparent 40%),
             radial-gradient(circle at 85% 95%,rgba(120,0,255,.12),transparent 40%),#05070d}
.wrap{position:relative;z-index:1;max-width:1200px;margin:0 auto;padding:32px 24px 80px}
h1{font-size:32px;font-weight:900;letter-spacing:-1px;margin-bottom:6px;
   background:linear-gradient(135deg,#fff,#00d9ff);-webkit-background-clip:text;
   background-clip:text;color:transparent}
.sub{color:#4a5f75;font-size:14px;margin-bottom:24px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
  gap:14px;margin-bottom:24px}
.stat{background:linear-gradient(160deg,rgba(10,20,35,.9),rgba(5,10,20,.95));
  border:1px solid rgba(0,180,255,.18);border-radius:14px;padding:20px;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.05)}
.stat .n{font-size:32px;font-weight:900;color:#00d9ff}
.stat .l{font-size:12px;color:#4a5f75;letter-spacing:1.5px;text-transform:uppercase;margin-top:4px}
.card{background:linear-gradient(160deg,rgba(10,20,35,.9),rgba(5,10,20,.95));
  border:1px solid rgba(0,180,255,.18);border-radius:16px;padding:24px;
  box-shadow:0 24px 80px rgba(0,120,255,.06),inset 0 1px 0 rgba(255,255,255,.05);
  margin-bottom:24px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
input,select{padding:12px 16px;background:rgba(0,0,0,.4);border:1px solid rgba(0,180,255,.2);
  color:#e6f6ff;border-radius:10px;font-size:14px;font-family:inherit}
input:focus,select:focus{outline:none;border-color:#00d9ff;box-shadow:0 0 0 3px rgba(0,217,255,.12)}
.btn{padding:12px 24px;border:none;border-radius:10px;font-size:14px;font-weight:800;
  letter-spacing:.5px;cursor:pointer;transition:all .2s;color:#fff;
  background:linear-gradient(135deg,#00a8ff,#0066ff);
  box-shadow:0 8px 24px rgba(0,120,255,.3)}
.btn:hover{transform:translateY(-1px);box-shadow:0 12px 32px rgba(0,120,255,.5)}
.btn.danger{background:linear-gradient(135deg,#ff4040,#c01010)}
.btn.green{background:linear-gradient(135deg,#00d966,#009944)}
table{width:100%;border-collapse:collapse;font-size:13px;
  font-family:ui-monospace,Menlo,monospace}
th{text-align:left;padding:12px 10px;background:rgba(0,0,0,.3);color:#00d9ff;
  font-size:11px;letter-spacing:1.5px;text-transform:uppercase;font-weight:800;
  border-bottom:1px solid rgba(0,180,255,.2)}
td{padding:11px 10px;border-bottom:1px solid rgba(255,255,255,.04);color:#a8bdd0}
tr:hover td{background:rgba(0,180,255,.03)}
.badge{display:inline-block;padding:3px 10px;border-radius:100px;font-size:10px;
  font-weight:800;letter-spacing:1px;text-transform:uppercase}
.badge.free{background:rgba(0,255,136,.15);color:#00ff88;border:1px solid rgba(0,255,136,.3)}
.badge.used{background:rgba(0,180,255,.15);color:#00d9ff;border:1px solid rgba(0,180,255,.3)}
.badge.exp{background:rgba(255,60,60,.15);color:#ff6b6b;border:1px solid rgba(255,60,60,.3)}
.mini{padding:5px 10px;font-size:11px;border-radius:6px;border:none;cursor:pointer;
  background:rgba(255,60,60,.15);color:#ff8b8b;font-weight:700}
.mini:hover{background:rgba(255,60,60,.3)}
.scroll{overflow-x:auto;border-radius:12px;border:1px solid rgba(0,180,255,.1)}
.login-box{max-width:380px;margin:80px auto;text-align:center}
.login-box h1{margin-bottom:24px}
.login-box input{width:100%;margin-bottom:14px;text-align:center;font-size:16px}
.login-box .btn{width:100%;padding:16px}
.toast{position:fixed;bottom:30px;right:30px;background:#00ff88;color:#05070d;
  padding:14px 24px;border-radius:12px;font-weight:800;font-size:13px;
  box-shadow:0 12px 40px rgba(0,255,136,.4);opacity:0;
  transform:translateY(20px);transition:all .35s cubic-bezier(.2,.8,.3,1)}
.toast.show{opacity:1;transform:translateY(0)}
</style>
</head>
<body>
<div class="bg"></div>
{% if not authed %}
<div class="wrap login-box">
  <h1>ITZNVL Admin</h1>
  <form method="POST" action="/admin">
    <input type="password" name="pw" placeholder="Admin password" autofocus>
    <button class="btn" type="submit">ĐĂNG NHẬP</button>
  </form>
  {% if err %}<p style="color:#ff6b6b;margin-top:16px">{{ err }}</p>{% endif %}
</div>
{% else %}
<div class="wrap">
  <h1>ITZNVL Admin</h1>
  <p class="sub">Quản lý key · Real-time</p>

  <div class="stats">
    <div class="stat"><div class="n">{{ total }}</div><div class="l">Tổng key</div></div>
    <div class="stat"><div class="n" style="color:#00ff88">{{ free }}</div><div class="l">Chưa dùng</div></div>
    <div class="stat"><div class="n">{{ used }}</div><div class="l">Đang dùng</div></div>
    <div class="stat"><div class="n" style="color:#ff6b6b">{{ expired }}</div><div class="l">Hết hạn</div></div>
  </div>

  <div class="card">
    <div class="row">
      <input type="number" id="numKeys" value="100" min="1" max="1000" style="width:100px">
      <input type="text" id="note" placeholder="Ghi chú (tùy chọn)" style="flex:1;min-width:180px">
      <button class="btn green" onclick="addKeys()">+ THÊM KEY</button>
      <button class="btn danger" onclick="clearFree()">🗑 XÓA KEY TRỐNG</button>
    </div>
  </div>

  <div class="card" style="padding:0">
    <div class="scroll">
      <table>
        <thead><tr>
          <th>Key</th><th>HWID</th><th>Trạng thái</th>
          <th>Hết hạn</th><th>IP</th><th>Note</th><th></th>
        </tr></thead>
        <tbody>
        {% for k in keys %}
          <tr>
            <td><b style="color:#00d9ff">{{ k.key }}</b></td>
            <td>{{ k.hwid[:20] if k.hwid else '—' }}</td>
            <td><span class="badge {{ k.cls }}">{{ k.status }}</span></td>
            <td>{{ k.expiry_str }}</td>
            <td>{{ k.ip or '—' }}</td>
            <td>{{ k.note or '' }}</td>
            <td><button class="mini" onclick="delKey('{{ k.key }}')">XÓA</button></td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>
<script>
async function api(path, body){
  const r = await fetch(path, {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(body || {})
  });
  return await r.json();
}
function show(msg, ok=true){
  const t = document.getElementById('toast');
  t.textContent = (ok?'✓ ':'✗ ') + msg;
  t.style.background = ok ? '#00ff88' : '#ff6b6b';
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), 2000);
}
async function addKeys(){
  const n = parseInt(document.getElementById('numKeys').value) || 100;
  const note = document.getElementById('note').value;
  const r = await api('/admin/add', {n, note});
  if (r.ok){ show(`Đã thêm ${r.created} key`); setTimeout(()=>location.reload(), 800); }
  else show(r.error || 'Lỗi', false);
}
async function delKey(k){
  if (!confirm('Xóa key ' + k + '?')) return;
  const r = await api('/admin/del', {key: k});
  if (r.ok){ show('Đã xóa'); setTimeout(()=>location.reload(), 600); }
  else show(r.error || 'Lỗi', false);
}
async function clearFree(){
  if (!confirm('Xóa TẤT CẢ key chưa dùng?')) return;
  const r = await api('/admin/clear', {});
  if (r.ok){ show(`Đã xóa ${r.deleted} key`); setTimeout(()=>location.reload(), 800); }
  else show(r.error || 'Lỗi', false);
}
</script>
{% endif %}
</body>
</html>
"""

# ============================================================
# ROUTES
# ============================================================
@app.route("/", methods=["GET"])
def home():
    return redirect("/getkey")

@app.route("/getkey", methods=["GET", "POST"])
def getkey():
    hwid = request.values.get("hwid", "").strip()
    if not hwid:
        return render_template_string(LANDING,
            hwid="", key=None, days=KEY_DAYS, expiry_str="",
            error="Thiếu HWID. Mở link này từ trong menu ITZNVL.")

    ua = request.headers.get("User-Agent", "")
    ip = client_ip()
    fp = fingerprint(hwid, ua, ip)

    if rate_check(f"getkey:{ip}"):
        return render_template_string(LANDING,
            hwid=hwid, key=None, days=KEY_DAYS, expiry_str="",
            error="Bạn đã thử quá nhiều lần. Vui lòng đợi 1 giờ.")

    # 1. HWID đã có key?
    row = q("SELECT key, expiry FROM keys WHERE hwid=? ORDER BY claimed_at DESC LIMIT 1",
            (hwid,), fetch="one")
    if row:
        exp_str = datetime.fromtimestamp(row["expiry"]).strftime("%d/%m/%Y %H:%M") if row["expiry"] else "-"
        return render_template_string(LANDING,
            hwid=hwid, key=row["key"], days=KEY_DAYS, expiry_str=exp_str, error=None)

    # 2. POST → claim
    if request.method == "POST":
        row = q("SELECT key FROM keys WHERE hwid IS NULL OR hwid='' ORDER BY rowid ASC LIMIT 1",
                fetch="one")
        if not row:
            return render_template_string(LANDING,
                hwid=hwid, key=None, days=KEY_DAYS, expiry_str="",
                error="Đã hết key. Vui lòng quay lại sau.")
        key = row["key"]
        now = int(time.time())
        expiry = now + KEY_DAYS * 86400
        q("UPDATE keys SET hwid=?, fingerprint=?, activated=?, expiry=?, claimed_at=?, ip=? WHERE key=?",
          (hwid, fp, now, expiry, now, ip, key), commit=True)
        exp_str = datetime.fromtimestamp(expiry).strftime("%d/%m/%Y %H:%M")
        return render_template_string(LANDING,
            hwid=hwid, key=key, days=KEY_DAYS, expiry_str=exp_str, error=None)

    return render_template_string(LANDING,
        hwid=hwid, key=None, days=KEY_DAYS, expiry_str="", error=None)

@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(silent=True) or {}
    key  = data.get("key", "").strip()
    hwid = data.get("hwid", "").strip()
    ua   = request.headers.get("User-Agent", "")
    ip   = client_ip()

    if not key or not hwid:
        return jsonify(valid=False, reason="missing")

    row = q("SELECT hwid, fingerprint, activated, expiry FROM keys WHERE key=?",
            (key,), fetch="one")
    if not row:
        return jsonify(valid=False, reason="not_found")

    saved_hwid = row["hwid"] or ""
    activated  = row["activated"] or 0
    expiry     = row["expiry"] or 0
    now        = int(time.time())
    cur_fp     = fingerprint(hwid, ua, ip)

    if saved_hwid and saved_hwid != hwid:
        return jsonify(valid=False, reason="hwid_mismatch")

    if not activated:
        expiry = now + KEY_DAYS * 86400
        q("UPDATE keys SET hwid=?, fingerprint=?, activated=?, expiry=?, ip=? WHERE key=?",
          (hwid, cur_fp, now, expiry, ip, key), commit=True)

    if now > expiry:
        return jsonify(valid=False, reason="expired")

    resp = {
        "valid": True,
        "expiry": expiry,
        "days_left": (expiry - now) // 86400,
        "server_time": now
    }
    resp["sig"] = sign_payload({"valid": "1", "expiry": str(expiry), "hwid": hwid})
    return jsonify(resp)

# ---------- ADMIN ----------
def admin_authed():
    return session.get("admin") is True

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        pw = request.form.get("pw", "")
        if pw == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect("/admin")
        return render_template_string(ADMIN, authed=False, err="Sai mật khẩu")

    if not admin_authed():
        return render_template_string(ADMIN, authed=False, err=None)

    rows = q("SELECT key, hwid, activated, expiry, note, ip FROM keys "
             "ORDER BY claimed_at DESC, key ASC", fetch="all") or []

    now = int(time.time())
    keys_out = []
    free = used = expired = 0
    for r in rows:
        if not r["activated"]:
            status, cls = "free", "free"; free += 1; exp_str = "—"
        elif now > r["expiry"]:
            status, cls = "expired", "exp"; expired += 1
            exp_str = datetime.fromtimestamp(r["expiry"]).strftime("%d/%m %H:%M")
        else:
            status, cls = "used", "used"; used += 1
            exp_str = datetime.fromtimestamp(r["expiry"]).strftime("%d/%m %H:%M")
        keys_out.append({
            "key": r["key"], "hwid": r["hwid"] or "",
            "status": status, "cls": cls, "expiry_str": exp_str,
            "note": r["note"] or "", "ip": r["ip"] or ""
        })

    return render_template_string(ADMIN, authed=True,
        total=len(rows), free=free, used=used, expired=expired, keys=keys_out)

@app.route("/admin/add", methods=["POST"])
def admin_add():
    if not admin_authed(): return jsonify(ok=False, error="unauth"), 401
    data = request.get_json(silent=True) or {}
    n = max(1, min(1000, int(data.get("n", 100))))
    note = data.get("note", "")[:100]
    created = add_keys(n, note=note)
    return jsonify(ok=True, created=len(created))

@app.route("/admin/del", methods=["POST"])
def admin_del():
    if not admin_authed(): return jsonify(ok=False, error="unauth"), 401
    data = request.get_json(silent=True) or {}
    k = data.get("key", "")
    q("DELETE FROM keys WHERE key=?", (k,), commit=True)
    return jsonify(ok=True)

@app.route("/admin/clear", methods=["POST"])
def admin_clear():
    if not admin_authed(): return jsonify(ok=False, error="unauth"), 401
    # Đếm trước khi xóa
    r = q("SELECT COUNT(*) AS c FROM keys WHERE activated=0", fetch="one")
    n = r["c"] if r else 0
    q("DELETE FROM keys WHERE activated=0", commit=True)
    return jsonify(ok=True, deleted=n)

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect("/admin")

@app.route("/healthz")
def healthz():
    return "ok", 200

# ============================================================
# BOOT
# ============================================================
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
