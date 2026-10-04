// Single backend file: login, AI proxy (Gemini, free tier) and CV text extraction.
// Keys live only in Vercel environment variables, never in the browser.
const crypto=require('crypto');
const PW=()=>process.env.APP_PASSWORD||'';
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
const RULES='You are a recruitment assistant. Use ONLY facts in the provided context. Never invent employers, skills, dates, visas, clearance, salary or qualifications; write "Not provided" when missing. "Not mentioned" does not mean "does not have". For visa/compliance questions give informational guidance only, not legal advice.';

const routes={
  async login(req,res){
    if(req.method!=='POST')return res.status(405).end();
    if(!PW())return res.status(500).json({error:'Server is not configured: APP_PASSWORD is missing.'});
    if(!crypto.timingSafeEqual(sha(req.body?.password),sha(PW())))return res.status(401).json({error:'Incorrect password'});
    res.setHeader('Set-Cookie',`tt=${sign()}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`);res.json({ok:true});
  },
  async me(req,res){authed(req)?res.json({ok:true}):res.status(401).json({error:'Unauthorized'})},
  async ai(req,res){
    if(req.method!=='POST')return res.status(405).end();if(!authed(req))return res.status(401).json({error:'Unauthorized'});
    const key=(process.env.GEMINI_API_KEY||'').trim().replace(/^["']|["']$/g,'');if(!key)return res.status(500).json({error:'AI provider is not configured: GEMINI_API_KEY is missing.'});
    const prompt=String(req.body?.prompt||'').slice(0,40000);if(!prompt)return res.status(400).json({error:'Prompt required'});
    // Tries each model in turn. Skips to the next on: retired model (404), overloaded (503),
    // rate limit (429). Retries once on overload. GEMINI_MODEL (optional) is tried first.
    const models=[...new Set([process.env.GEMINI_MODEL,'gemini-3.8-flash','gemini-3.5-flash','gemini-2.5-flash','gemini-3.5-flash-lite','gemini-2.5-flash-lite'].filter(Boolean))];
    const body=JSON.stringify({systemInstruction:{parts:[{text:RULES}]},contents:[{parts:[{text:prompt}]}]});
    const sleep=ms=>new Promise(r=>setTimeout(r,ms));
    const t0=Date.now();let lastErr='request failed';
    for(const m of models){
      for(let attempt=0;attempt<2;attempt++){
        if(Date.now()-t0>22000)break;
        try{
          const r=await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent?key=${encodeURIComponent(key)}`,{method:'POST',headers:{'Content-Type':'application/json'},body});
          const d=await r.json().catch(()=>({}));
          if(r.ok){const text=d.candidates?.[0]?.content?.parts?.map(x=>x.text||'').join('');if(text)return res.json({text});lastErr='Empty response from the model';break}
          lastErr=d.error?.message||'request failed';
          if(r.status===400||r.status===401||r.status===403)return res.status(502).json({error:'Gemini rejected the request: '+lastErr+' Create a new key at aistudio.google.com/apikey, paste it in Vercel as GEMINI_API_KEY with no quotes or spaces, then redeploy.'});
          if(r.status===503&&attempt===0){await sleep(1200);continue}
          break;
        }catch(e){lastErr=e.message;break}
      }
    }
    res.status(502).json({error:'Gemini is busy or rate-limited right now: '+lastErr+' Please try again in a minute.'});
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
  const route=req.query?.route||(req.url||'').split('?')[0].split('/').pop();
  const h=routes[route];return h?h(req,res):res.status(404).json({error:'Not found'});
};
