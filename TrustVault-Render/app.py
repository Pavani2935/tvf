import os, sqlite3, hashlib, hmac, json, base64, io, secrets
from pathlib import Path
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, session, redirect, url_for, flash, abort, send_file, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet, InvalidToken
ROOT=Path(os.environ.get('TRUSTVAULT_DATA','instance')); ROOT.mkdir(parents=True,exist_ok=True)
FILES=ROOT/'encrypted_files'; FILES.mkdir(exist_ok=True); DB=ROOT/'trustvault.sqlite3'; LIMIT=int(os.environ.get('MAX_UPLOAD_MB','20'))
app=Flask(__name__); app.secret_key=os.environ.get('APP_SECRET','dev-only-change-me'); app.config['MAX_CONTENT_LENGTH']=LIMIT*1024*1024
def now(): return datetime.now(timezone.utc).isoformat(timespec='seconds')
def key(n): return base64.urlsafe_b64encode(hashlib.sha256(os.environ.get(n,'local-'+n).encode()).digest())
cipher=Fernet(key('FILE_MASTER_KEY')); AUDIT=os.environ.get('AUDIT_HMAC_KEY','local-audit-key').encode()
def db():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); return c
def init():
 with db() as c:
  c.executescript('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,password_hash TEXT,role TEXT,active INTEGER DEFAULT 1,created TEXT); CREATE TABLE IF NOT EXISTS docs(id INTEGER PRIMARY KEY,title TEXT,filename TEXT,category TEXT,owner INTEGER,stored TEXT,sha TEXT,size INTEGER,created TEXT); CREATE TABLE IF NOT EXISTS perms(doc INTEGER,user INTEGER,access TEXT,granted_by INTEGER,at TEXT,PRIMARY KEY(doc,user)); CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,at TEXT,actor TEXT,action TEXT,doc INTEGER,target TEXT,outcome TEXT,details TEXT,prev TEXT,digest TEXT);')
  if not c.execute('SELECT id FROM users LIMIT 1').fetchone():
   pw=os.environ.get('BOOTSTRAP_ADMIN_PASSWORD') or secrets.token_urlsafe(18); print('Initial TrustVault admin password (save now):',pw)
   c.execute('INSERT INTO users(username,password_hash,role,created) VALUES(?,?,?,?)',(os.environ.get('BOOTSTRAP_ADMIN_USER','admin'),generate_password_hash(pw),'admin',now()))
def current():
 if not session.get('uid'): return None
 with db() as c:r=c.execute('SELECT * FROM users WHERE id=? AND active=1',(session['uid'],)).fetchone()
 return dict(r) if r else None
def audit(action,doc=None,target='',outcome='success',details=None,actor=None):
 u=current() if actor is None else actor; name=u['username'] if u else (target or 'anonymous')
 with db() as c:
  last=c.execute('SELECT digest FROM audit ORDER BY id DESC LIMIT 1').fetchone(); prev=last['digest'] if last else 'GENESIS'; at=now(); det=json.dumps(details or {},sort_keys=True,separators=(',',':'))
  payload='|'.join([at,name,action,str(doc or ''),target,outcome,det,prev]); digest=hmac.new(AUDIT,payload.encode(),hashlib.sha256).hexdigest()
  c.execute('INSERT INTO audit(at,actor,action,doc,target,outcome,details,prev,digest) VALUES(?,?,?,?,?,?,?,?,?)',(at,name,action,doc,target,outcome,det,prev,digest))
def login_required(fn):
 @wraps(fn)
 def w(*a,**k):
  if not current(): return redirect('/login')
  return fn(*a,**k)
 return w
def roles(*allowed):
 def deco(fn):
  @login_required
  @wraps(fn)
  def w(*a,**k):
   u=current()
   if u['role'] not in allowed: audit('role_access',outcome='denied',details={'path':request.path}); abort(403)
   return fn(*a,**k)
  return w
 return deco
def doccheck(i,level='read'):
 u=current()
 with db() as c:
  d=c.execute('SELECT d.*,u.username owner_name FROM docs d JOIN users u ON u.id=d.owner WHERE d.id=?',(i,)).fetchone(); p=c.execute('SELECT access FROM perms WHERE doc=? AND user=?',(i,u['id'])).fetchone()
 if not d or not (u['role']=='admin' or d['owner']==u['id'] or (p and (level=='read' or p['access']=='edit'))): audit('document_access',i,outcome='denied',details={'required':level}); abort(404)
 return d
def page(body):
 template='''<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>TrustVault</title><style>body{font:16px system-ui;max-width:1050px;margin:30px auto;padding:0 15px;background:#f5f7fb;color:#182230}nav,.card{background:white;padding:18px;border-radius:12px;margin:14px 0}nav{display:flex;gap:18px;flex-wrap:wrap}input,select,button{padding:9px;margin:4px}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:8px;border-bottom:1px solid #ddd}.muted{color:#667085}</style></head><body><h1>🔐 TrustVault</h1>{% if u %}<p class="muted">Signed in as {{u.username}} · {{u.role}}</p><nav><a href="/">Documents</a><a href="/upload">Upload</a><a href="/audit">Audit trail</a>{% if u.role=='admin' %}<a href="/users">Users</a>{% endif %}<a href="/logout">Sign out</a></nav>{% endif %}{% for m in get_flashed_messages() %}<p>{{m}}</p>{% endfor %}BODY</body></html>'''
 return render_template_string(template.replace('BODY',body),u=current())
@app.route('/')
@login_required
def home():
 u=current(); q=request.args.get('q',''); cat=request.args.get('category',''); owner=request.args.get('owner',''); date_from=request.args.get('from',''); date_to=request.args.get('to','')
 with db() as c: docs=c.execute("SELECT DISTINCT d.*,u.username owner_name FROM docs d JOIN users u ON u.id=d.owner LEFT JOIN perms p ON p.doc=d.id AND p.user=? WHERE (?='admin' OR d.owner=? OR p.user IS NOT NULL) AND (d.title LIKE ? OR d.filename LIKE ?) AND d.category LIKE ? AND u.username LIKE ? AND (?='' OR date(d.created)>=date(?)) AND (?='' OR date(d.created)<=date(?)) ORDER BY d.id DESC",(u['id'],u['role'],u['id'],'%'+q+'%','%'+q+'%','%'+cat+'%','%'+owner+'%',date_from,date_from,date_to,date_to)).fetchall()
 rows=''.join(f'<tr><td><a href="/docs/{d["id"]}">{d["title"]}</a></td><td>{d["filename"]}</td><td>{d["owner_name"]}</td><td>{d["category"]}</td><td>{d["created"]}</td></tr>' for d in docs)
 return page(f'<div class="card"><h2>Documents</h2><form><input name="q" placeholder="Search name" value="{q}"><input name="category" placeholder="Category" value="{cat}"><input name="owner" placeholder="Owner" value="{owner}"><label>From <input type="date" name="from" value="{date_from}"></label><label>To <input type="date" name="to" value="{date_to}"></label><button>Search</button></form><table><tr><th>Title</th><th>Filename</th><th>Owner</th><th>Category</th><th>Uploaded</th></tr>{rows}</table></div>')
@app.route('/login',methods=['GET','POST'])
def signin():
 if request.method=='POST':
  name=request.form.get('username','').strip()
  with db() as c:r=c.execute('SELECT * FROM users WHERE username=? AND active=1',(name,)).fetchone()
  if r and check_password_hash(r['password_hash'],request.form.get('password','')): session.clear(); session['uid']=r['id']; audit('login'); return redirect('/')
  audit('login',outcome='denied',target=name,details={'reason':'bad_credentials'},actor=None); flash('Invalid credentials')
 return page('<div class="card"><h2>Sign in</h2><form method="post"><input name="username" placeholder="Username" required><br><input name="password" type="password" placeholder="Password" required><br><button>Sign in</button></form></div>')
@app.route('/logout')
@login_required
def logout(): audit('logout'); session.clear(); return redirect('/login')
@app.route('/upload',methods=['GET','POST'])
@roles('admin','owner')
def upload():
 if request.method=='POST':
  f=request.files.get('file'); title=request.form.get('title','').strip(); cat=request.form.get('category','General').strip()[:80]; fn=secure_filename(f.filename if f else '')
  if not f or not fn or not title or Path(fn).suffix.lower() not in {'.pdf','.txt','.csv','.docx','.xlsx','.png','.jpg','.jpeg'}: audit('upload',outcome='denied',details={'reason':'invalid_file'}); flash('Title and supported file required.'); return redirect('/upload')
  raw=f.read()
  if not raw or len(raw)>LIMIT*1024*1024: flash('File empty or too large.'); return redirect('/upload')
  sha=hashlib.sha256(raw).hexdigest(); u=current()
  with db() as c: c.execute('INSERT INTO docs(title,filename,category,owner,stored,sha,size,created) VALUES(?,?,?,?,?,?,?,?)',(title,fn,cat or 'General',u['id'],'pending',sha,len(raw),now())); i=c.execute('SELECT last_insert_rowid()').fetchone()[0]
  path=FILES/f'{i}.bin'; path.write_bytes(cipher.encrypt(raw))
  with db() as c:c.execute('UPDATE docs SET stored=? WHERE id=?',(str(path),i))
  audit('upload',i,details={'sha256':sha,'size':len(raw)}); flash('Uploaded and encrypted.'); return redirect(f'/docs/{i}')
 return page(f'<div class="card"><h2>Upload</h2><form method="post" enctype="multipart/form-data"><input name="title" placeholder="Document title" required><br><input name="category" placeholder="Category" value="General"><br><input type="file" name="file" required><br><button>Upload</button></form><p>Allowed PDF, TXT, CSV, DOCX, XLSX, PNG, JPG. Max {LIMIT} MB.</p></div>')
@app.route('/docs/<int:i>')
@login_required
def detail(i):
 d=doccheck(i); u=current()
 with db() as c:
  ps=c.execute('SELECT p.user,p.access,u.username FROM perms p JOIN users u ON u.id=p.user WHERE p.doc=?',(i,)).fetchall(); people=c.execute('SELECT id,username,role FROM users WHERE active=1 AND id<>? ORDER BY username',(d['owner'],)).fetchall() if u['role']=='admin' or u['id']==d['owner'] else []; p=c.execute('SELECT access FROM perms WHERE doc=? AND user=?',(i,u['id'])).fetchone()
 editable=u['role']=='admin' or u['id']==d['owner'] or (p and p['access']=='edit'); controls=''
 if editable: controls+=f'<form method="post" action="/docs/{i}/edit"><input name="title" value="{d["title"]}" required><input name="category" value="{d["category"]}" required><button>Save metadata</button></form><form method="post" action="/docs/{i}/delete"><button>Delete document</button></form>'
 if people:
  opts=''.join(f'<option value="{x["id"]}">{x["username"]} ({x["role"]})</option>' for x in people); plist=''.join(f'<li>{x["username"]}: {x["access"]} <form style="display:inline" method="post" action="/docs/{i}/revoke"><input type="hidden" name="user_id" value="{x["user"]}"><button>Revoke</button></form></li>' for x in ps)
  controls+=f'<h3>Grant access</h3><form method="post" action="/docs/{i}/grant"><select name="user_id">{opts}</select><select name="access"><option>read</option><option>edit</option></select><button>Grant</button></form><ul>{plist}</ul>'
 return page(f'<div class="card"><h2>{d["title"]}</h2><p>File: {d["filename"]} · Owner: {d["owner_name"]} · Category: {d["category"]}</p><p>SHA-256: <code>{d["sha"]}</code></p><a href="/docs/{i}/download">Download</a>{controls}</div>')
@app.route('/docs/<int:i>/download')
@login_required
def download(i):
 d=doccheck(i)
 try: raw=cipher.decrypt(Path(d['stored']).read_bytes())
 except (OSError,InvalidToken): audit('download',i,outcome='error'); abort(500)
 if hashlib.sha256(raw).hexdigest()!=d['sha']: audit('download',i,outcome='error',details={'reason':'integrity'}); abort(500)
 audit('download',i,details={'sha256':d['sha']}); return send_file(io.BytesIO(raw),download_name=d['filename'],as_attachment=True)
@app.route('/docs/<int:i>/edit',methods=['POST'])
@login_required
def edit(i):
 d=doccheck(i,'edit'); title=request.form.get('title','').strip(); cat=request.form.get('category','').strip()
 if not title or not cat: abort(400)
 with db() as c:c.execute('UPDATE docs SET title=?,category=? WHERE id=?',(title,cat,i))
 audit('metadata_change',i,details={'title':title,'category':cat}); return redirect(f'/docs/{i}')
@app.route('/docs/<int:i>/grant',methods=['POST'])
@login_required
def grant(i):
 d=doccheck(i,'edit'); u=current()
 if u['id']!=d['owner'] and u['role']!='admin': audit('permission_grant',i,outcome='denied'); abort(403)
 try: target=int(request.form['user_id'])
 except (ValueError,KeyError): abort(400)
 access=request.form.get('access','read')
 if access not in ('read','edit'): abort(400)
 with db() as c:
  t=c.execute('SELECT username FROM users WHERE id=? AND active=1',(target,)).fetchone()
  if not t: abort(400)
  c.execute('INSERT INTO perms(doc,user,access,granted_by,at) VALUES(?,?,?,?,?) ON CONFLICT(doc,user) DO UPDATE SET access=excluded.access,granted_by=excluded.granted_by,at=excluded.at',(i,target,access,u['id'],now()))
 audit('permission_grant',i,target=t['username'],details={'access':access}); return redirect(f'/docs/{i}')
@app.route('/docs/<int:i>/revoke',methods=['POST'])
@login_required
def revoke(i):
 d=doccheck(i,'edit'); u=current()
 if u['id']!=d['owner'] and u['role']!='admin': audit('permission_revoke',i,outcome='denied'); abort(403)
 target=request.form.get('user_id','')
 with db() as c: t=c.execute('SELECT username FROM users WHERE id=?',(target,)).fetchone(); c.execute('DELETE FROM perms WHERE doc=? AND user=?',(i,target))
 audit('permission_revoke',i,target=t['username'] if t else target); flash('Access revoked for future requests.'); return redirect(f'/docs/{i}')
@app.route('/docs/<int:i>/delete',methods=['POST'])
@login_required
def delete(i):
 d=doccheck(i,'edit'); u=current()
 if u['id']!=d['owner'] and u['role']!='admin': audit('delete',i,outcome='denied'); abort(403)
 audit('delete',i,details={'sha256':d['sha']}); Path(d['stored']).unlink(missing_ok=True)
 with db() as c:c.execute('DELETE FROM docs WHERE id=?',(i,))
 return redirect('/')
@app.route('/users',methods=['GET','POST'])
@roles('admin')
def users():
 if request.method=='POST':
  name=request.form.get('username','').strip(); pw=request.form.get('password',''); role=request.form.get('role','viewer')
  if len(name)<3 or len(pw)<12 or role not in ('admin','owner','viewer'): flash('Username 3+ chars and password 12+ chars required.'); return redirect('/users')
  try:
   with db() as c:c.execute('INSERT INTO users(username,password_hash,role,created) VALUES(?,?,?,?)',(name,generate_password_hash(pw),role,now()))
   audit('user_create',target=name,details={'role':role}); flash('User created.')
  except sqlite3.IntegrityError: flash('Username already exists.')
  return redirect('/users')
 with db() as c: rows=c.execute('SELECT username,role,active,created FROM users ORDER BY id').fetchall()
 trs=''.join(f'<tr><td>{x["username"]}</td><td>{x["role"]}</td><td>{x["active"]}</td><td>{x["created"]}</td></tr>' for x in rows)
 return page(f'<div class="card"><h2>Users</h2><form method="post"><input name="username" placeholder="Username" required><input name="password" type="password" placeholder="Password (12+ chars)" required><select name="role"><option>viewer</option><option>owner</option><option>admin</option></select><button>Create</button></form><table><tr><th>User</th><th>Role</th><th>Active</th><th>Created</th></tr>{trs}</table></div>')
@app.route('/audit')
@roles('admin')
def audit_page():
 with db() as c: rows=c.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 500').fetchall()
 trs=''.join(f'<tr><td>{x["id"]}</td><td>{x["at"]}</td><td>{x["actor"]}</td><td>{x["action"]}</td><td>{x["doc"] or ""}</td><td>{x["outcome"]}</td><td><code>{x["digest"][:18]}…</code></td></tr>' for x in rows)
 return page('<div class="card"><h2>Audit trail · latest 500</h2><p>HMAC-SHA256 chained entries. Keep AUDIT_HMAC_KEY separate and store checkpoints externally.</p><table><tr><th>ID</th><th>UTC</th><th>Actor</th><th>Action</th><th>Doc</th><th>Outcome</th><th>Hash</th></tr>'+trs+'</table></div>')
@app.errorhandler(403)
def forbidden(e): return page('<div class="card"><h2>Access denied</h2></div>'),403
@app.errorhandler(404)
def missing(e): return page('<div class="card"><h2>Not found or no access</h2></div>'),404
@app.errorhandler(413)
def too_big(e): return page('<div class="card"><h2>File too large</h2></div>'),413
init()
if __name__=='__main__': app.run(host='0.0.0.0',port=int(os.environ.get('PORT','5000')))
