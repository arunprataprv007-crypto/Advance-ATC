// TalentTrack backend (single file): login, AI proxy with free providers + automatic fallback, CV text extraction.
// Secrets live only in Vercel environment variables. Nothing sensitive is ever logged or returned.
const crypto=require('crypto');
const clean=v=>(v||'').trim().replace(/^["']|["']$/g,'');
const PW=()=>clean(process.env.APP_PASSWORD);
const hmac=p=>crypto.createHmac('sha256',PW()).update(p).digest('base64url');
const sha=s=>crypto.createHash('sha256').update(String(s)).digest();
const sign=()=>{const p=Buffer.from(JSON.stringify({exp:Date.now()+7*864e5})).toString('base64url');return p+'.'+hmac(p)};
function authed(req){
  const m=(req.headers.cookie||'').match(/(?:^|; )tt=([^;]+)/);if(!m||!PW())return false;
  const [p,s]=m[1].split('.');if(!p||!s)return false;const e=hmac(p);
  if(s.length!==e.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(e)))return false;
  try{return JSON.parse(Buffer.from(p,'base64url')).exp>Date.now()}catch{return false}
}
const raw=req=>new Promise((ok,no)=>{const c=[];let n=0;req.on('data',d=>{n+=d.length;if(n>4e6){no(new Error('File over 4MB'));req.destroy()}else c.push(d)});req.on('end',()=>ok(Buffer.concat(c)));req.on('error',no)});
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const RULES='You are a recruitment assistant. Use ONLY facts in the provided context. Never invent employers, skills, dates, visas, clearance, salary or qualifications; write "Not provided" when missing. "Not mentioned" does not mean "does not have". For visa/compliance questions give informational guidance only, not legal advice.';

// ---- login throttle (best effort per server instance) ----
const fails=new Map();
const ip=req=>String(req.headers['x-forwarded-for']||'').split(',')[0].trim()||'x';
const locked=req=>{const f=fails.get(ip(req));return f&&f.n>=5&&Date.now()-f.t<9e5};

// ---- AI providers ----
const keyType=k=>k.startsWith('AIza')?'AIza standard key':k.startsWith('AQ.')?'AQ. auth key':'unknown key format';
async function gemini(prompt){
  const key=clean(process.env.GEMINI_API_KEY);if(!key)throw new Error('GEMINI_API_KEY is not set');
  const models=[...new Set([clean(process.env.GEMINI_MODEL),'gemini-3.8-flash','gemini-3.6-flash','gemini-3.5-flash','gemini-3.5-flash-lite','gemini-2.5-flash'].filter(Boolean))];
  const body=JSON.stringify({systemInstruction:{parts:[{text:RULES}]},contents:[{parts:[{text:prompt}]}]});
  const t0=Date.now();let last='request failed';
  for(const m of models){
    for(let a=0;a<2;a++){
      if(Date.now()-t0>20000)throw new Error(last);
      const base=`https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent`;
      const h={'Content-Type':'application/json'};
      let r=await fetch(base,{method:'POST',headers:{...h,'x-goog-api-key':key},body});
      if(r.status===401)r=await fetch(base+'?key='+encodeURIComponent(key),{method:'POST',headers:h,body});
      const d=await r.json().catch(()=>({}));
      if(r.ok){const t=d.candidates?.[0]?.content?.parts?.map(x=>x.text||'').join('');if(t)return t;last='empty response';break}
      last=d.error?.message||'request failed';
      if(r.status===401||r.status===403)throw new Error(`Gemini rejected the key (${keyType(key)}). Google is known to reject some newer AQ. keys; use the Groq free key instead.`);
      if(r.status===503&&a===0){await sleep(1000);continue}
      break;
    }
  }
  throw new Error('Gemini is busy or rate-limited: '+last);
}
async function groq(prompt){
  const key=clean(process.env.GROQ_API_KEY);if(!key)throw new Error('GROQ_API_KEY is not set');
  let last='request failed';
  for(const m of [clean(process.env.GROQ_MODEL),'llama-3.3-70b-versatile','llama-3.1-8b-instant'].filter(Boolean)){
    const r=await fetch('https://api.groq.com/openai/v1/chat/completions',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+key},body:JSON.stringify({model:m,temperature:0.3,messages:[{role:'system',content:RULES},{role:'user',content:prompt}]})});
    const d=await r.json().catch(()=>({}));
    if(r.ok&&d.choices?.[0]?.message?.content)return d.choices[0].message.content;
    last=d.error?.message||'request failed';
    if(r.status===401)throw new Error('Groq rejected the key (check GROQ_API_KEY)');
  }
  throw new Error('Groq is busy or rate-limited: '+last);
}
const PROVIDERS={gemini,groq};
const configured=()=>Object.keys(PROVIDERS).filter(p=>clean(process.env[p.toUpperCase()+'_API_KEY']));

const routes={
  async login(req,res){
    if(req.method!=='POST')return res.status(405).end();
    if(PW().length<8)return res.status(500).json({error:'Server is not configured: APP_PASSWORD must be set and at least 8 characters.'});
    if(locked(req))return res.status(429).json({error:'Too many attempts. Try again in 15 minutes.'});
    if(!crypto.timingSafeEqual(sha(clean(req.body?.password)),sha(PW()))){
      const f=fails.get(ip(req))||{n:0,t:0};fails.set(ip(req),{n:Date.now()-f.t>9e5?1:f.n+1,t:Date.now()});
      return res.status(401).json({error:'Incorrect password'});
    }
    fails.delete(ip(req));
    res.setHeader('Set-Cookie',`tt=${sign()}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800`);res.json({ok:true});
  },
  async me(req,res){authed(req)?res.json({ok:true}):res.status(401).json({error:'Unauthorized'})},
  async health(req,res){
    if(!authed(req))return res.status(401).json({error:'Unauthorized'});
    const g=clean(process.env.GEMINI_API_KEY);
    res.json({configured:configured(),gemini:g?keyType(g):'not set',preferred:clean(process.env.AI_PROVIDER)||'gemini'});
  },
  async ai(req,res){
    if(req.method!=='POST')return res.status(405).end();if(!authed(req))return res.status(401).json({error:'Unauthorized'});
    const prompt=String(req.body?.prompt||'').slice(0,40000);if(!prompt)return res.status(400).json({error:'Prompt required'});
    const have=configured();
    if(!have.length)return res.status(500).json({error:'AI provider is not configured. Add GROQ_API_KEY and/or GEMINI_API_KEY in Vercel, then redeploy.'});
    const pref=clean(process.env.AI_PROVIDER).toLowerCase();
    const order=[...new Set([pref,...have])].filter(p=>have.includes(p));
    const errs=[];
    for(const p of order){
      try{return res.json({text:await PROVIDERS[p](prompt),provider:p})}
      catch(e){errs.push(e.message)}
    }
    res.status(502).json({error:errs.join(' | ')+' Please try again in a minute.'});
  },
  async parse(req,res){
    if(req.method!=='POST')return res.status(405).end();if(!authed(req))return res.status(401).json({error:'Unauthorized'});
    try{
      const name=decodeURIComponent(req.headers['x-filename']||'').toLowerCase();
      const buf=Buffer.isBuffer(req.body)?req.body:await raw(req);
      if(!buf||!buf.length)return res.status(400).json({error:'Empty file'});
      if(buf.length>4e6)return res.status(413).json({error:'File over 4MB'});
      let t;
      if(name.endsWith('.pdf'))t=(await require('pdf-parse/lib/pdf-parse.js')(buf)).text;
      else if(name.endsWith('.docx'))t=(await require('mammoth').extractRawText({buffer:buf})).value;
      else if(name.endsWith('.txt'))t=buf.toString('utf8');
      else return res.status(415).json({error:'File type not supported (PDF, DOCX, TXT)'});
      t=(t||'').trim();if(t.length<50)return res.status(422).json({error:'Unable to parse this file (no readable text)'});
      res.json({text:t.slice(0,30000)});
    }catch(e){res.status(500).json({error:'Unable to parse this file'})}
  }
};
module.exports=async(req,res)=>{
  res.setHeader('Cache-Control','no-store');
  try{
    const route=req.query?.route||(req.url||'').split('?')[0].split('/').pop();
    const h=Object.hasOwn(routes,route)?routes[route]:null;return h?await h(req,res):res.status(404).json({error:'Not found'});
  }catch(e){if(!res.headersSent)res.status(500).json({error:'Something went wrong. Please try again.'})}
};
