const samples = {
  phish: `Subject: URGENT: Your Account Has Been Suspended!\nFrom: security-alert@paypa1-secure.ru\nTo: user@company.com\n\nDear Valued Customer,\nYour account has been TEMPORARILY SUSPENDED. Restore access NOW:\nhttp://bit.ly/acc-restore-929341\nYou must verify within 24 hours or account will be PERMANENTLY DELETED.\nEnter: Username, Password, SSN, Credit Card Number\nPayPal Security Team`,
  safe: `Subject: Weekly Team Meeting - Thursday 3PM\nFrom: manager@company.com\nTo: team@company.com\n\nHi team,\nReminder about our weekly sync this Thursday at 3:00 PM in Conference Room B.\nAgenda: Q3 updates, onboarding review, Q&A.\nBest regards, Sarah`
};
let currentScanId = null;

document.addEventListener('DOMContentLoaded', () => {
  loadStats(); loadRecentScans();
  const inp = document.getElementById('emailInput');
  if (inp) inp.addEventListener('input', () => { document.getElementById('charCount').textContent = inp.value.length + ' chars'; });
});

function showSection(name) {
  ['dashboard','analyze','history','threats','apikey','admin'].forEach(s => { const el=document.getElementById('sec-'+s); if(el) el.style.display=s===name?'':'none'; });
  document.querySelectorAll('.nav-item').forEach(el=>el.classList.remove('active'));
  if(event&&event.currentTarget) event.currentTarget.classList.add('active');
  if(name==='history') loadHistory();
  if(name==='dashboard'){loadStats();loadRecentScans();}
  if(name==='apikey') loadApiKey();
  if(name==='admin') loadAdminData();
}

async function loadStats() {
  try {
    const res=await fetch('/api/dashboard-stats');
    if(res.status===401){window.location.href='/login';return;}
    const d=await res.json();
    setText('statTotal',d.total); setText('statSafe',d.safe); setText('statSus',d.suspicious); setText('statPhish',d.phishing); setText('userChip',d.username||'analyst');
    if(d.total>0){setText('statSafePct',pct(d.safe,d.total)+'% of total');setText('statSusPct',pct(d.suspicious,d.total)+'% of total');setText('statPhishPct',pct(d.phishing,d.total)+'% of total');}
    if(d.role==='admin'){const a=document.getElementById('adminNav');if(a)a.style.display='';}
    if(d.trend) drawChart(d.trend);
  } catch(e){console.error(e);}
}

function drawChart(trend) {
  const canvas=document.getElementById('trendChart'); if(!canvas) return;
  const ctx=canvas.getContext('2d'),W=canvas.width,H=canvas.height,max=Math.max(...trend.map(t=>t.count),1),pad=30,barW=(W-pad*2)/trend.length;
  ctx.clearRect(0,0,W,H);
  ctx.strokeStyle='rgba(0,229,255,0.08)'; ctx.lineWidth=1;
  for(let i=0;i<=4;i++){const y=pad+(H-pad*2)*(i/4);ctx.beginPath();ctx.moveTo(pad,y);ctx.lineTo(W-pad,y);ctx.stroke();}
  trend.forEach((t,i)=>{
    const barH=((t.count/max)*(H-pad*2))||2,x=pad+i*barW+barW*0.15,y=H-pad-barH,bw=barW*0.7;
    const g=ctx.createLinearGradient(0,y,0,H-pad);g.addColorStop(0,'rgba(0,229,255,0.8)');g.addColorStop(1,'rgba(0,229,255,0.1)');
    ctx.fillStyle=g;ctx.beginPath();ctx.rect(x,y,bw,barH);ctx.fill();
    ctx.fillStyle='rgba(58,106,136,1)';ctx.font='10px monospace';ctx.textAlign='center';ctx.fillText(t.day,x+bw/2,H-8);
    if(t.count>0){ctx.fillStyle='rgba(0,229,255,0.9)';ctx.fillText(t.count,x+bw/2,y-4);}
  });
}

async function loadRecentScans() {
  try {
    const res=await fetch('/api/history'); if(!res.ok) return;
    const records=await res.json(); const el=document.getElementById('recentScans');
    if(!records.length){el.innerHTML='<div class="empty-state">No scans yet. Analyze an email to start.</div>';return;}
    el.innerHTML=records.slice(0,6).map(r=>`<div class="table-row"><div class="preview-text">${escHtml(r.preview)}</div><div><span class="badge badge-${r.verdict.toLowerCase()}">${r.verdict}</span></div><div class="score-col score-${r.verdict.toLowerCase()}">${r.score}%</div><div class="time-col">${r.timestamp}</div></div>`).join('');
  } catch(e){console.error(e);}
}

async function loadHistory() {
  try {
    const res=await fetch('/api/history'); if(!res.ok) return;
    const records=await res.json(); const el=document.getElementById('historyList');
    if(!records.length){el.innerHTML='<div class="empty-state">No history yet.</div>';return;}
    el.innerHTML=records.map(r=>`<div class="table-row"><div class="preview-text">${escHtml(r.preview)}</div><div><span class="badge badge-${r.verdict.toLowerCase()}">${r.verdict}</span></div><div class="score-col score-${r.verdict.toLowerCase()}">${r.score}%</div><div class="preview-text" style="font-size:11px;color:var(--muted);">${escHtml(r.flags||'—')}</div><div class="time-col">${r.timestamp}${r.feedback?`<br><span class="badge badge-${r.feedback==='correct'?'safe':'phishing'}">${r.feedback==='correct'?'✓':'✗'}</span>`:`<br><span class="fb-btn fb-correct" onclick="sendFeedback(${r.id},'correct',this)">✓</span> <span class="fb-btn fb-wrong" onclick="sendFeedback(${r.id},'wrong',this)">✗</span>`}</div></div>`).join('');
  } catch(e){console.error(e);}
}

async function sendFeedback(scanId,feedback,el) {
  try {
    await fetch('/api/feedback',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scan_id:scanId,feedback})});
    if(el){const p=el.parentElement;if(p)p.innerHTML=`<span class="badge badge-${feedback==='correct'?'safe':'phishing'}">${feedback==='correct'?'✓':'✗'}</span>`;}
  } catch(e){console.error(e);}
}

function loadSample(type){const inp=document.getElementById('emailInput');inp.value=samples[type];document.getElementById('charCount').textContent=inp.value.length+' chars';clearResult();}
function clearAnalyze(){document.getElementById('emailInput').value='';document.getElementById('charCount').textContent='0 chars';clearResult();}
function clearResult(){document.getElementById('resultBox').className='result-box';currentScanId=null;}

async function analyzeEmail() {
  const text=document.getElementById('emailInput').value.trim(); if(!text){document.getElementById('emailInput').focus();return;}
  document.getElementById('scanOverlay').classList.add('active'); clearResult();
  try {
    const res=await fetch('/api/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email_text:text})});
    if(res.status===401){window.location.href='/login';return;}
    if(res.status===429){alert('Too many requests. Please wait.');document.getElementById('scanOverlay').classList.remove('active');return;}
    const data=await res.json(); document.getElementById('scanOverlay').classList.remove('active');
    showResult(data); currentScanId=data.scan_id; loadStats();
  } catch(e){document.getElementById('scanOverlay').classList.remove('active');alert('Error: Is Flask running?');}
}

function showResult({verdict,score,confidence,flags,keywords,headers,scan_id}) {
  const cls='result-'+verdict.toLowerCase(); const box=document.getElementById('resultBox'); box.className='result-box visible '+cls;
  const emojis={PHISHING:'🚨',SUSPICIOUS:'⚠️',SAFE:'✅'};
  const subs={PHISHING:'HIGH RISK — Do not interact',SUSPICIOUS:'MEDIUM RISK — Review carefully',SAFE:'LOW RISK — Appears legitimate'};
  setText('resultEmoji',emojis[verdict]||'🔍'); setText('resultVerdict',verdict); setText('resultSub',subs[verdict]||''); setText('riskScore',score+'%'); setText('confidenceVal',(confidence||'—')+'% confidence');
  const bar=document.getElementById('riskBar'); bar.style.width='0%'; setTimeout(()=>{bar.style.width=score+'%';},50);
  const fl=document.getElementById('flagsList'); fl.innerHTML=flags&&flags.length?flags.map(f=>`<div class="flag-item flag-danger">⚑ ${escHtml(f)}</div>`).join(''):'<div class="flag-item flag-ok">✓ No suspicious patterns</div>';
  const kw=document.getElementById('keywordsList'); if(kw) kw.innerHTML=keywords&&keywords.length?keywords.map(k=>`<span class="kw-tag">${escHtml(k)}</span>`).join(''):'<span style="color:var(--muted);font-size:12px;">None</span>';
  const hEl=document.getElementById('headerInfo'); if(hEl&&headers) hEl.innerHTML=`<div class="header-row"><span class="h-label">FROM</span><span class="h-val ${headers.suspicious_domain?'danger':''}">${escHtml(headers.from)}</span></div><div class="header-row"><span class="h-label">SUBJECT</span><span class="h-val">${escHtml(headers.subject)}</span></div><div class="header-row"><span class="h-label">DOMAIN</span><span class="h-val ${headers.suspicious_domain?'danger':''}">${escHtml(headers.domain)} ${headers.suspicious_domain?'⚠️':''}</span></div>`;
  const fbEl=document.getElementById('feedbackArea'); if(fbEl) fbEl.innerHTML=`<div class="fb-prompt">Was this verdict correct?</div><div style="display:flex;gap:8px;margin-top:6px;"><button class="fb-btn fb-correct" onclick="sendFeedbackResult('correct')">✓ Correct</button><button class="fb-btn fb-wrong" onclick="sendFeedbackResult('wrong')">✗ Wrong</button></div>`;
  box.scrollIntoView({behavior:'smooth',block:'nearest'});
}

async function sendFeedbackResult(feedback) {
  if(!currentScanId) return;
  await fetch('/api/feedback',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scan_id:currentScanId,feedback})});
  const fbEl=document.getElementById('feedbackArea'); if(fbEl) fbEl.innerHTML=`<div style="color:var(--safe);font-family:'Share Tech Mono',monospace;font-size:12px;margin-top:8px;">✓ Feedback saved!</div>`;
}

function exportCSV(){window.location.href='/api/export/csv';}
function exportPDF(){window.location.href='/api/export/pdf';}

async function loadApiKey(){const res=await fetch('/api/my-api-key');const d=await res.json();setText('apiKeyVal',d.api_key||'Error');}
async function regenApiKey(){if(!confirm('Regenerate? Old key stops working.'))return;const res=await fetch('/api/regenerate-api-key',{method:'POST'});const d=await res.json();setText('apiKeyVal',d.api_key);}
function copyApiKey(){navigator.clipboard.writeText(document.getElementById('apiKeyVal').textContent).then(()=>alert('Copied!'));}

async function loadAdminData() {
  try {
    const [sr,ur]=await Promise.all([fetch('/api/admin/stats'),fetch('/api/admin/users')]);
    const stats=await sr.json(); const users=await ur.json();
    setText('adminTotalUsers',stats.total_users); setText('adminTotalScans',stats.total_scans); setText('adminTotalPhish',stats.total_phish);
    const el=document.getElementById('adminUsersList');
    if(el) el.innerHTML=users.map(u=>`<div class="table-row"><div class="preview-text">${escHtml(u.username)}</div><div class="preview-text" style="font-size:11px;">${escHtml(u.email)}</div><div><span class="badge badge-${u.role==='admin'?'phishing':'safe'}">${u.role.toUpperCase()}</span></div><div class="score-col" style="color:var(--accent);">${u.scans}</div><div class="time-col">${u.created}</div></div>`).join('');
  } catch(e){console.error(e);}
}

async function logout(){await fetch('/api/logout',{method:'POST'});window.location.href='/login';}
function pct(v,t){return t===0?0:Math.round((v/t)*100);}
function setText(id,val){const el=document.getElementById(id);if(el)el.textContent=val;}
function escHtml(str){return String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
