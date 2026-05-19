from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
import hashlib, os, pickle, re, json, time, io, csv, random, string

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'phishnet-dev-secret-2024')
db_url = os.environ.get('DATABASE_URL', 'sqlite:///phishnet.db')
if db_url.startswith('postgres://'): db_url = db_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_pre_ping': True, 'pool_recycle': 300}
db = SQLAlchemy(app)

# Rate limiting
request_counts = defaultdict(list)
def rate_limit(max_req=10, window=60):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            ip = request.remote_addr; now = time.time()
            request_counts[ip] = [t for t in request_counts[ip] if now - t < window]
            if len(request_counts[ip]) >= max_req:
                return jsonify({'error': 'Too many requests. Please slow down.'}), 429
            request_counts[ip].append(now)
            return f(*args, **kwargs)
        return decorated
    return decorator

# Models
class User(db.Model):
    id=db.Column(db.Integer,primary_key=True); username=db.Column(db.String(80),unique=True,nullable=False)
    email=db.Column(db.String(120),unique=True,nullable=False); password=db.Column(db.String(64),nullable=False)
    role=db.Column(db.String(10),default='user'); otp_code=db.Column(db.String(6),nullable=True)
    otp_expiry=db.Column(db.DateTime,nullable=True); api_key=db.Column(db.String(64),unique=True,nullable=True)
    created=db.Column(db.DateTime,default=datetime.utcnow)
    scans=db.relationship('ScanHistory',backref='user',lazy=True)

class ScanHistory(db.Model):
    id=db.Column(db.Integer,primary_key=True); user_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)
    email_text=db.Column(db.Text,nullable=False); verdict=db.Column(db.String(20),nullable=False)
    score=db.Column(db.Float,nullable=False); flags=db.Column(db.Text,default='')
    feedback=db.Column(db.String(20),nullable=True); timestamp=db.Column(db.DateTime,default=datetime.utcnow)

def hash_pw(p): return hashlib.sha256(p.encode()).hexdigest()
def gen_otp(): return ''.join(random.choices(string.digits, k=6))
def gen_api(): return hashlib.sha256(os.urandom(32)).hexdigest()

def login_required(f):
    @wraps(f)
    def d(*a,**k):
        api_key=request.headers.get('X-API-Key')
        if api_key:
            u=User.query.filter_by(api_key=api_key).first()
            if u: session['user_id']=u.id; session['username']=u.username; return f(*a,**k)
        if 'user_id' not in session: return jsonify({'error':'Unauthorized'}),401
        return f(*a,**k)
    return d

def admin_required(f):
    @wraps(f)
    def d(*a,**k):
        if 'user_id' not in session: return jsonify({'error':'Unauthorized'}),401
        u=User.query.get(session['user_id'])
        if not u or u.role!='admin': return jsonify({'error':'Admin access required'}),403
        return f(*a,**k)
    return d

def load_model():
    path=os.path.join('model','phishnet_model.pkl')
    if os.path.exists(path):
        with open(path,'rb') as f: return pickle.load(f)
    return None

def classify_email(text):
    md=load_model()
    if md:
        feats=md['vectorizer'].transform([text]); prob=md['classifier'].predict_proba(feats)[0]
        score=round(float(prob[1])*100,1); confidence=round(max(prob)*100,1)
    else:
        score=_heuristic(text); confidence=round(min(95,abs(score-50)+55),1)
    flags=_flags(text); keywords=_keywords(text); headers=_headers(text)
    verdict='PHISHING' if score>=60 else ('SUSPICIOUS' if score>=30 else 'SAFE')
    return {'verdict':verdict,'score':score,'confidence':confidence,'flags':flags,'keywords':keywords,'headers':headers}

def _heuristic(text):
    lower=text.lower(); score=0
    for k in ['suspended','verify immediately','click here','urgent','permanently deleted','ssn','credit card','password','login now','verify your','security alert','restore access','suspicious activity','confirm your account','limited time','act now','account locked','unusual activity','prize','winner']:
        if k in lower: score+=12
    for k in ['meeting','agenda','team','schedule','project update','conference room','onboarding','weekly sync','reminder','best regards','kind regards']:
        if k in lower: score-=8
    if re.search(r'bit\.ly|tinyurl|goo\.gl',text,re.I): score+=20
    if re.search(r'[a-z]+\d+[a-z]*\.(ru|xyz|tk|pw|cc)',text,re.I): score+=25
    if re.search(r'urgent|immediate|24 hour|expire',lower): score+=15
    if re.search(r'ssn|credit card|social security',lower): score+=30
    if re.search(r'dear (customer|user|valued)',lower): score+=10
    return max(2.0,min(100.0,float(score)))

def _flags(text):
    lower=text.lower()
    checks={'Urgency language detected':bool(re.search(r'urgent|immediate|24 hour|expire|act now',lower)),
            'Requests sensitive data':bool(re.search(r'ssn|password|credit card|pin',lower)),
            'Shortened URL found':bool(re.search(r'bit\.ly|tinyurl|goo\.gl',text,re.I)),
            'Suspicious domain':bool(re.search(r'[a-z]+\d+[a-z]*\.(ru|xyz|tk|pw)',text,re.I)),
            'Threatening language':bool(re.search(r'deleted|suspended|banned|blocked',lower)),
            'Impersonation attempt':bool(re.search(r'paypa1|amaz0n|micros0ft|g00gle',text,re.I)),
            'Generic greeting':bool(re.search(r'dear (customer|user|valued member)',lower)),
            'Prize/reward language':bool(re.search(r'winner|prize|reward|congratulations|selected',lower))}
    return [f for f,t in checks.items() if t]

def _keywords(text):
    kws=['urgent','suspended','verify','click here','password','ssn','credit card','free','winner','prize','account locked','security alert','restore','confirm','expire','limited']
    lower=text.lower()
    return [k for k in kws if k in lower][:8]

def _headers(text):
    r={}
    fm=re.search(r'from:\s*(.+)',text,re.I); sm=re.search(r'subject:\s*(.+)',text,re.I); tm=re.search(r'to:\s*(.+)',text,re.I)
    r['from']=fm.group(1).strip() if fm else 'Not found'
    r['subject']=sm.group(1).strip() if sm else 'Not found'
    r['to']=tm.group(1).strip() if tm else 'Not found'
    dm=re.search(r'@([\w\.-]+)',r['from'])
    if dm:
        d=dm.group(1); r['domain']=d
        r['suspicious_domain']=any(d.endswith(t) for t in ['.ru','.xyz','.tk','.pw','.cc','.biz'])
        r['has_numbers']=bool(re.search(r'\d',d))
    else:
        r['domain']='Unknown'; r['suspicious_domain']=False; r['has_numbers']=False
    return r

@app.route('/')
def index(): return redirect(url_for('login_page') if 'user_id' not in session else url_for('dashboard'))
@app.route('/login')
def login_page(): return render_template('login.html')
@app.route('/register')
def register_page(): return render_template('register.html')
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('login_page'))
    return render_template('dashboard.html')
@app.route('/admin')
def admin_page():
    if 'user_id' not in session: return redirect(url_for('login_page'))
    u=User.query.get(session['user_id'])
    if not u or u.role!='admin': return redirect(url_for('dashboard'))
    return render_template('admin.html')

@app.route('/api/register',methods=['POST'])
@rate_limit(5,60)
def register():
    d=request.get_json(); username=d.get('username','').strip(); email=d.get('email','').strip(); password=d.get('password','')
    if not username or not email or not password: return jsonify({'error':'All fields required'}),400
    if len(password)<6: return jsonify({'error':'Password min 6 chars'}),400
    if User.query.filter_by(username=username).first(): return jsonify({'error':'Username exists'}),409
    if User.query.filter_by(email=email).first(): return jsonify({'error':'Email registered'}),409
    role='admin' if User.query.count()==0 else 'user'
    u=User(username=username,email=email,password=hash_pw(password),role=role,api_key=gen_api())
    db.session.add(u); db.session.commit()
    session['user_id']=u.id; session['username']=u.username; session['role']=u.role
    return jsonify({'message':'Registered','username':username,'role':role}),201

@app.route('/api/login',methods=['POST'])
@rate_limit(10,60)
def login():
    d=request.get_json(); username=d.get('username','').strip(); password=d.get('password','')
    u=User.query.filter_by(username=username,password=hash_pw(password)).first()
    if not u: return jsonify({'error':'Invalid credentials'}),401
    otp=gen_otp(); u.otp_code=otp; u.otp_expiry=datetime.utcnow()+timedelta(minutes=5)
    db.session.commit()
    return jsonify({'message':'OTP sent','otp':otp,'require_otp':True,'user_id':u.id})

@app.route('/api/verify-otp',methods=['POST'])
def verify_otp():
    d=request.get_json(); user_id=d.get('user_id'); otp=d.get('otp','').strip()
    u=User.query.get(user_id)
    if not u: return jsonify({'error':'Invalid request'}),400
    if u.otp_code!=otp or datetime.utcnow()>u.otp_expiry: return jsonify({'error':'Invalid or expired OTP'}),401
    u.otp_code=None; db.session.commit()
    session['user_id']=u.id; session['username']=u.username; session['role']=u.role
    return jsonify({'message':'Login successful','username':u.username,'role':u.role})

@app.route('/api/logout',methods=['POST'])
def logout(): session.clear(); return jsonify({'message':'Logged out'})

@app.route('/api/analyze',methods=['POST'])
@login_required
@rate_limit(30,60)
def analyze():
    d=request.get_json(); text=d.get('email_text','').strip()
    if not text: return jsonify({'error':'Email text required'}),400
    result=classify_email(text)
    rec=ScanHistory(user_id=session['user_id'],email_text=text[:2000],verdict=result['verdict'],score=result['score'],flags=', '.join(result['flags']))
    db.session.add(rec); db.session.commit(); result['scan_id']=rec.id
    return jsonify(result)

@app.route('/api/feedback',methods=['POST'])
@login_required
def feedback():
    d=request.get_json(); scan_id=d.get('scan_id'); fb=d.get('feedback')
    rec=ScanHistory.query.filter_by(id=scan_id,user_id=session['user_id']).first()
    if not rec: return jsonify({'error':'Scan not found'}),404
    rec.feedback=fb; db.session.commit()
    return jsonify({'message':'Feedback saved!'})

@app.route('/api/history',methods=['GET'])
@login_required
def history():
    recs=ScanHistory.query.filter_by(user_id=session['user_id']).order_by(ScanHistory.timestamp.desc()).limit(50).all()
    return jsonify([{'id':r.id,'verdict':r.verdict,'score':r.score,'flags':r.flags,'feedback':r.feedback,'timestamp':r.timestamp.strftime('%Y-%m-%d %H:%M'),'preview':r.email_text[:80]+('...' if len(r.email_text)>80 else '')} for r in recs])

@app.route('/api/dashboard-stats',methods=['GET'])
@login_required
def dashboard_stats():
    uid=session['user_id']
    total=ScanHistory.query.filter_by(user_id=uid).count()
    safe=ScanHistory.query.filter_by(user_id=uid,verdict='SAFE').count()
    sus=ScanHistory.query.filter_by(user_id=uid,verdict='SUSPICIOUS').count()
    phish=ScanHistory.query.filter_by(user_id=uid,verdict='PHISHING').count()
    trend=[]
    for i in range(6,-1,-1):
        day=datetime.utcnow()-timedelta(days=i)
        cnt=ScanHistory.query.filter(ScanHistory.user_id==uid,ScanHistory.timestamp>=day.replace(hour=0,minute=0,second=0),ScanHistory.timestamp<day.replace(hour=23,minute=59,second=59)).count()
        trend.append({'day':day.strftime('%a'),'count':cnt})
    return jsonify({'total':total,'safe':safe,'suspicious':sus,'phishing':phish,'trend':trend,'username':session.get('username'),'role':session.get('role','user')})

@app.route('/api/my-api-key',methods=['GET'])
@login_required
def get_api_key():
    u=User.query.get(session['user_id']); return jsonify({'api_key':u.api_key})

@app.route('/api/regenerate-api-key',methods=['POST'])
@login_required
def regen_api_key():
    u=User.query.get(session['user_id']); u.api_key=gen_api(); db.session.commit()
    return jsonify({'api_key':u.api_key})

@app.route('/api/export/csv',methods=['GET'])
@login_required
def export_csv():
    recs=ScanHistory.query.filter_by(user_id=session['user_id']).order_by(ScanHistory.timestamp.desc()).all()
    out=io.StringIO(); w=csv.writer(out)
    w.writerow(['ID','Verdict','Score','Flags','Feedback','Timestamp','Preview'])
    for r in recs: w.writerow([r.id,r.verdict,r.score,r.flags,r.feedback or '',r.timestamp.strftime('%Y-%m-%d %H:%M'),r.email_text[:100]])
    out.seek(0)
    return send_file(io.BytesIO(out.getvalue().encode()),mimetype='text/csv',as_attachment=True,download_name=f'phishnet_{datetime.utcnow().strftime("%Y%m%d")}.csv')

@app.route('/api/export/pdf',methods=['GET'])
@login_required
def export_pdf():
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate,Table,TableStyle,Paragraph,Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        recs=ScanHistory.query.filter_by(user_id=session['user_id']).order_by(ScanHistory.timestamp.desc()).limit(20).all()
        uid=session['user_id']
        total=ScanHistory.query.filter_by(user_id=uid).count()
        safe=ScanHistory.query.filter_by(user_id=uid,verdict='SAFE').count()
        phish=ScanHistory.query.filter_by(user_id=uid,verdict='PHISHING').count()
        buf=io.BytesIO(); doc=SimpleDocTemplate(buf,pagesize=letter); styles=getSampleStyleSheet(); story=[]
        story.append(Paragraph('PhishNet AI — Scan Report',styles['Title']))
        story.append(Paragraph(f'Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M")} UTC | User: {session.get("username")}',styles['Normal']))
        story.append(Spacer(1,12))
        story.append(Paragraph(f'Total: {total} | Safe: {safe} | Phishing: {phish}',styles['Normal']))
        story.append(Spacer(1,16))
        data=[['#','Verdict','Score','Date','Preview']]
        for r in recs: data.append([r.id,r.verdict,f'{r.score}%',r.timestamp.strftime('%Y-%m-%d'),r.email_text[:50]+'...'])
        t=Table(data,colWidths=[30,80,50,90,260])
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#005f7f')),('TEXTCOLOR',(0,0),(-1,0),colors.white),('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('FONTSIZE',(0,0),(-1,-1),8),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f0f0f0')]),('GRID',(0,0),(-1,-1),0.5,colors.grey),('PADDING',(0,0),(-1,-1),4)]))
        story.append(t); doc.build(story); buf.seek(0)
        return send_file(buf,mimetype='application/pdf',as_attachment=True,download_name=f'phishnet_{datetime.utcnow().strftime("%Y%m%d")}.pdf')
    except ImportError:
        return jsonify({'error':'Run: pip install reportlab'}),500

@app.route('/api/admin/users',methods=['GET'])
@admin_required
def admin_users():
    users=User.query.order_by(User.created.desc()).all()
    return jsonify([{'id':u.id,'username':u.username,'email':u.email,'role':u.role,'scans':len(u.scans),'created':u.created.strftime('%Y-%m-%d')} for u in users])

@app.route('/api/admin/stats',methods=['GET'])
@admin_required
def admin_stats():
    return jsonify({'total_users':User.query.count(),'total_scans':ScanHistory.query.count(),'total_phish':ScanHistory.query.filter_by(verdict='PHISHING').count(),'total_safe':ScanHistory.query.filter_by(verdict='SAFE').count(),'total_sus':ScanHistory.query.filter_by(verdict='SUSPICIOUS').count()})

@app.route('/health')
def health(): return jsonify({'status':'ok'}),200

with app.app_context():
    db.create_all()

if __name__=='__main__':
    app.run(debug=False)
