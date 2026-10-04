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
    const key=process.env.GEMINI_API_KEY;if(!key)return res.status(500).json({error:'AI provider is not configured: GEMINI_API_KEY is missing.'});
    const prompt=String(req.body?.prompt||'').slice(0,40000);if(!prompt)return res.status(400).json({error:'Prompt required'});
    try{
      const r=await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${key}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({systemInstruction:{parts:[{text:RULES}]},contents:[{parts:[{text:prompt}]}]})});
      const d=await r.json();if(!r.ok)throw new Error(d.error?.message||'request failed');
      res.json({text:d.candidates[0].content.parts[0].text});
    }catch(e){res.status(502).json({error:'Gemini failed: '+e.message+' (check your key, or wait a minute if you hit the free limit)'})}
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
