"use strict";
const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const app = express();
const IS_PROD = process.env.NODE_ENV === "production" || !!process.env.VERCEL;
const SESSION_DAYS = Math.max(1, Math.min(30, Number(process.env.SESSION_DAYS || 1)));
if (!process.env.DATABASE_URL) console.warn("DATABASE_URL is missing. Connect Neon/Postgres before using the API.");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : undefined,
  max: Number(process.env.DB_POOL_MAX || 5),
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 10000
});

app.disable("x-powered-by");
app.set("trust proxy", Number(process.env.TRUST_PROXY || 1));
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  if (IS_PROD) res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  if (req.path.startsWith("/api/")) res.setHeader("Cache-Control", "no-store");
  next();
});
app.use(express.json({ limit: "250kb" }));
app.use(express.urlencoded({ extended: false, limit: "50kb" }));

let schemaPromise;
async function ensureSchema() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is not configured");
  if (!schemaPromise) schemaPromise = pool.query(`
CREATE TABLE IF NOT EXISTS admins (
 id BIGSERIAL PRIMARY KEY,
 email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'admin',
 is_active BOOLEAN NOT NULL DEFAULT TRUE,
 failed_attempts INTEGER NOT NULL DEFAULT 0,
 locked_until BIGINT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS sessions (
 id BIGSERIAL PRIMARY KEY,
 token_hash TEXT NOT NULL UNIQUE,
 admin_id BIGINT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
 csrf_token TEXT NOT NULL,
 expires_at BIGINT NOT NULL,
 created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS mediators (
 id BIGSERIAL PRIMARY KEY,
 name TEXT NOT NULL,
 email TEXT,
 phone TEXT,
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','inactive','suspended')),
 verification TEXT NOT NULL DEFAULT 'unverified' CHECK(verification IN ('unverified','identity','full')),
 rating DOUBLE PRECISION NOT NULL DEFAULT 0,
 completed_count INTEGER NOT NULL DEFAULT 0,
 fee_percent DOUBLE PRECISION,
 payment_methods JSONB NOT NULL DEFAULT '[]'::jsonb,
 notes TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mediators_status ON mediators(status);
CREATE TABLE IF NOT EXISTS operations (
 id BIGSERIAL PRIMARY KEY,
 code TEXT NOT NULL UNIQUE,
 client_name TEXT,
 client_email TEXT,
 mediator_id BIGINT REFERENCES mediators(id) ON DELETE SET NULL,
 amount DOUBLE PRECISION NOT NULL DEFAULT 0,
 category TEXT NOT NULL DEFAULT 'service',
 payment_method TEXT,
 description TEXT,
 status TEXT NOT NULL DEFAULT 'created' CHECK(status IN ('created','accepted','payment_pending','payment_confirmed','in_progress','client_confirmation','completed','cancelled','disputed')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_operations_status ON operations(status);
CREATE INDEX IF NOT EXISTS idx_operations_mediator ON operations(mediator_id);
CREATE TABLE IF NOT EXISTS disputes (
 id BIGSERIAL PRIMARY KEY,
 operation_id BIGINT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
 opened_by TEXT NOT NULL,
 reason TEXT NOT NULL,
 details TEXT,
 status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','under_review','resolved_client','resolved_mediator','closed')),
 resolution_note TEXT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_disputes_status ON disputes(status);
CREATE TABLE IF NOT EXISTS audit_logs (
 id BIGSERIAL PRIMARY KEY,
 admin_id BIGINT REFERENCES admins(id) ON DELETE SET NULL,
 action TEXT NOT NULL,
 entity_type TEXT,
 entity_id TEXT,
 ip TEXT,
 metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
`).then(seedAdmin).then(() => true).catch(e => { schemaPromise = null; throw e; });
  return schemaPromise;
}

async function seedAdmin() {
  const email = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  const password = String(process.env.ADMIN_PASSWORD || "");
  if (!email || !password) return;
  const { rows } = await pool.query("SELECT COUNT(*)::int AS n FROM admins");
  if (rows[0].n > 0) return;
  if (password.length < 12) { console.warn("ADMIN_PASSWORD must be at least 12 characters. Admin was not created."); return; }
  await pool.query("INSERT INTO admins(email,password_hash) VALUES($1,$2) ON CONFLICT (email) DO NOTHING", [email, await hashPassword(password)]);
  console.log("First admin created from environment variables.");
}

const nowSec = () => Math.floor(Date.now() / 1000);
const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString("base64url");
const sha256 = v => crypto.createHash("sha256").update(v).digest("hex");
const safeJson = (v, fallback) => { try { return typeof v === "string" ? JSON.parse(v) : (v ?? fallback); } catch { return fallback; } };
const clientIp = req => String(req.ip || req.socket.remoteAddress || "").slice(0, 100);

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16);
    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, derived) => {
      if (err) reject(err); else resolve(`scrypt$${salt.toString("base64url")}$${derived.toString("base64url")}`);
    });
  });
}
function verifyPassword(password, stored) {
  return new Promise((resolve, reject) => {
    const [scheme, saltB64, hashB64] = String(stored).split("$");
    if (scheme !== "scrypt" || !saltB64 || !hashB64) return resolve(false);
    const salt = Buffer.from(saltB64, "base64url");
    const expected = Buffer.from(hashB64, "base64url");
    crypto.scrypt(password, salt, expected.length, { N: 16384, r: 8, p: 1 }, (err, derived) => {
      if (err) reject(err); else resolve(crypto.timingSafeEqual(expected, derived));
    });
  });
}
function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  for (const part of raw.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}
function setSessionCookie(res, token) {
  const p = [`wasit_session=${encodeURIComponent(token)}`, "Path=/", "HttpOnly", "SameSite=Strict", `Max-Age=${SESSION_DAYS * 86400}`];
  if (IS_PROD) p.push("Secure");
  res.setHeader("Set-Cookie", p.join("; "));
}
function clearSessionCookie(res) {
  const p = ["wasit_session=", "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=0"];
  if (IS_PROD) p.push("Secure");
  res.setHeader("Set-Cookie", p.join("; "));
}

async function audit(adminId, action, entityType, entityId, req, metadata = {}) {
  await pool.query(`INSERT INTO audit_logs(admin_id,action,entity_type,entity_id,ip,metadata) VALUES($1,$2,$3,$4,$5,$6::jsonb)`, [adminId || null, action, entityType || null, entityId == null ? null : String(entityId), clientIp(req), JSON.stringify(metadata)]);
}
async function getSession(req) {
  const token = getCookie(req, "wasit_session");
  if (!token) return null;
  const { rows } = await pool.query(`SELECT s.*,a.email,a.role,a.is_active FROM sessions s JOIN admins a ON a.id=s.admin_id WHERE s.token_hash=$1 AND s.expires_at>$2 AND a.is_active=TRUE`, [sha256(token), nowSec()]);
  return rows[0] || null;
}
async function requireAuth(req,res,next) {
  try { await ensureSchema(); const session=await getSession(req); if(!session) return res.status(401).json({error:"غير مصرح"}); req.session=session; next(); }
  catch(e){ next(e); }
}
async function requireCsrf(req,res,next) {
  if (!["POST","PUT","PATCH","DELETE"].includes(req.method)) return next();
  if (!req.get("X-CSRF-Token") || req.get("X-CSRF-Token") !== req.session.csrf_token) return res.status(403).json({error:"CSRF token غير صالح"});
  next();
}
const loginAttempts = new Map();
function loginLimiter(key) {
  const now=Date.now(); const arr=(loginAttempts.get(key)||[]).filter(t=>now-t<15*60*1000);
  if(arr.length>=10) return false; arr.push(now); loginAttempts.set(key,arr); return true;
}

app.get("/api/health", async (_req,res,next)=>{try{await ensureSchema();res.json({ok:true,service:"wasit",database:"connected",time:new Date().toISOString()});}catch(e){next(e);}});

app.post("/api/admin/login", async (req,res,next)=>{
  try {
    await ensureSchema();
    const email=String(req.body.email||"").trim().toLowerCase(), password=String(req.body.password||"");
    if(!email||!password) return res.status(400).json({error:"البريد وكلمة المرور مطلوبان"});
    if(!loginLimiter(`${clientIp(req)}:${email}`)) return res.status(429).json({error:"محاولات كثيرة. حاول بعد قليل."});
    const {rows}=await pool.query("SELECT * FROM admins WHERE email=$1",[email]); const admin=rows[0];
    if(admin?.locked_until && Number(admin.locked_until)>nowSec()) return res.status(429).json({error:"الحساب مقفول مؤقتًا. حاول لاحقًا."});
    const valid=admin?await verifyPassword(password,admin.password_hash):false;
    if(!valid){if(admin){const failed=admin.failed_attempts+1,lock=failed>=5?nowSec()+900:null;await pool.query("UPDATE admins SET failed_attempts=$1,locked_until=$2,updated_at=NOW() WHERE id=$3",[failed,lock,admin.id]);}return res.status(401).json({error:"بيانات الدخول غير صحيحة"});}
    await pool.query("UPDATE admins SET failed_attempts=0,locked_until=NULL,updated_at=NOW() WHERE id=$1",[admin.id]);
    const rawToken=randomToken(48),csrf=randomToken(24); await pool.query("DELETE FROM sessions WHERE admin_id=$1",[admin.id]);
    await pool.query("INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at,created_at) VALUES($1,$2,$3,$4,$5)",[sha256(rawToken),admin.id,csrf,nowSec()+SESSION_DAYS*86400,nowSec()]);
    setSessionCookie(res,rawToken); await audit(admin.id,"login","admin",admin.id,req); res.json({ok:true,csrfToken:csrf,admin:{id:admin.id,email:admin.email,role:admin.role}});
  }catch(e){next(e)}
});

app.post("/api/admin/logout",requireAuth,requireCsrf,async(req,res,next)=>{try{await pool.query("DELETE FROM sessions WHERE id=$1",[req.session.id]);await audit(req.session.admin_id,"logout","admin",req.session.admin_id,req);clearSessionCookie(res);res.json({ok:true});}catch(e){next(e)}});
app.get("/api/admin/me",requireAuth,(req,res)=>res.json({admin:{id:req.session.admin_id,email:req.session.email,role:req.session.role},csrfToken:req.session.csrf_token}));
app.use("/api/admin",requireAuth,requireCsrf);

app.get("/api/admin/dashboard",async(req,res,next)=>{try{const [s,r]=await Promise.all([
 pool.query(`SELECT (SELECT COUNT(*) FROM mediators) AS mediators,(SELECT COUNT(*) FROM mediators WHERE status='active') AS "activeMediators",(SELECT COUNT(*) FROM operations) AS operations,(SELECT COUNT(*) FROM disputes WHERE status IN ('open','under_review')) AS "openDisputes",(SELECT COUNT(*) FROM operations WHERE status='completed') AS completed,(SELECT COALESCE(SUM(amount),0) FROM operations WHERE status<>'cancelled') AS volume`),
 pool.query(`SELECT o.id,o.code,o.client_name,o.amount,o.status,o.created_at,m.name mediator_name FROM operations o LEFT JOIN mediators m ON m.id=o.mediator_id ORDER BY o.id DESC LIMIT 8`)
]);const x=s.rows[0];res.json({stats:{mediators:Number(x.mediators),activeMediators:Number(x.activeMediators),operations:Number(x.operations),openDisputes:Number(x.openDisputes),completed:Number(x.completed),volume:Number(x.volume)},recent:r.rows});}catch(e){next(e)}});

app.get("/api/admin/mediators",async(req,res,next)=>{try{const q=String(req.query.q||"").trim();const sql=q?`SELECT * FROM mediators WHERE name ILIKE $1 OR email ILIKE $1 OR phone ILIKE $1 ORDER BY id DESC`:`SELECT * FROM mediators ORDER BY id DESC`;const {rows}=await pool.query(sql,q?[`%${q}%`]:[]);res.json(rows.map(r=>({...r,payment_methods:safeJson(r.payment_methods,[])})));}catch(e){next(e)}});
app.post("/api/admin/mediators",async(req,res,next)=>{try{const b=req.body;if(!String(b.name||"").trim())return res.status(400).json({error:"اسم الوسيط مطلوب"});const vals=[String(b.name).trim(),String(b.email||"").trim()||null,String(b.phone||"").trim()||null,["active","inactive","suspended"].includes(b.status)?b.status:"active",["unverified","identity","full"].includes(b.verification)?b.verification:"unverified",Number(b.rating||0),Number(b.completed_count||0),b.fee_percent===""||b.fee_percent==null?null:Number(b.fee_percent),JSON.stringify(Array.isArray(b.payment_methods)?b.payment_methods:[]),String(b.notes||"")];const {rows}=await pool.query(`INSERT INTO mediators(name,email,phone,status,verification,rating,completed_count,fee_percent,payment_methods,notes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10) RETURNING id`,vals);await audit(req.session.admin_id,"create","mediator",rows[0].id,req);res.status(201).json({id:Number(rows[0].id)});}catch(e){next(e)}});
app.patch("/api/admin/mediators/:id",async(req,res,next)=>{try{const id=Number(req.params.id),{rows}=await pool.query("SELECT * FROM mediators WHERE id=$1",[id]);const cur=rows[0];if(!cur)return res.status(404).json({error:"الوسيط غير موجود"});const b=req.body,nextv={name:b.name!==undefined?String(b.name).trim():cur.name,email:b.email!==undefined?String(b.email).trim()||null:cur.email,phone:b.phone!==undefined?String(b.phone).trim()||null:cur.phone,status:["active","inactive","suspended"].includes(b.status)?b.status:cur.status,verification:["unverified","identity","full"].includes(b.verification)?b.verification:cur.verification,rating:b.rating!==undefined?Number(b.rating):cur.rating,completed_count:b.completed_count!==undefined?Number(b.completed_count):cur.completed_count,fee_percent:b.fee_percent!==undefined?(b.fee_percent===""||b.fee_percent==null?null:Number(b.fee_percent)):cur.fee_percent,payment_methods:b.payment_methods!==undefined?JSON.stringify(Array.isArray(b.payment_methods)?b.payment_methods:[]):JSON.stringify(safeJson(cur.payment_methods,[])),notes:b.notes!==undefined?String(b.notes):cur.notes};if(!nextv.name)return res.status(400).json({error:"اسم الوسيط مطلوب"});await pool.query(`UPDATE mediators SET name=$1,email=$2,phone=$3,status=$4,verification=$5,rating=$6,completed_count=$7,fee_percent=$8,payment_methods=$9::jsonb,notes=$10,updated_at=NOW() WHERE id=$11`,[nextv.name,nextv.email,nextv.phone,nextv.status,nextv.verification,nextv.rating,nextv.completed_count,nextv.fee_percent,nextv.payment_methods,nextv.notes,id]);await audit(req.session.admin_id,"update","mediator",id,req,{fields:Object.keys(b)});res.json({ok:true});}catch(e){next(e)}});
app.delete("/api/admin/mediators/:id",async(req,res,next)=>{try{const id=Number(req.params.id),q=await pool.query("SELECT id FROM mediators WHERE id=$1",[id]);if(!q.rowCount)return res.status(404).json({error:"الوسيط غير موجود"});await pool.query("UPDATE mediators SET status='inactive',updated_at=NOW() WHERE id=$1",[id]);await audit(req.session.admin_id,"deactivate","mediator",id,req);res.json({ok:true});}catch(e){next(e)}});

const opStatuses=["created","accepted","payment_pending","payment_confirmed","in_progress","client_confirmation","completed","cancelled","disputed"];
app.get("/api/admin/operations",async(req,res,next)=>{try{const status=String(req.query.status||"");const {rows}=await pool.query(status?`SELECT o.*,m.name mediator_name FROM operations o LEFT JOIN mediators m ON m.id=o.mediator_id WHERE o.status=$1 ORDER BY o.id DESC`:`SELECT o.*,m.name mediator_name FROM operations o LEFT JOIN mediators m ON m.id=o.mediator_id ORDER BY o.id DESC`,status?[status]:[]);res.json(rows);}catch(e){next(e)}});
app.post("/api/admin/operations",async(req,res,next)=>{try{const b=req.body,code=`WS-${String(Date.now()).slice(-8)}-${crypto.randomInt(100,999)}`,status=opStatuses.includes(b.status)?b.status:"created",mediatorId=b.mediator_id?Number(b.mediator_id):null;if(mediatorId&&!(await pool.query("SELECT id FROM mediators WHERE id=$1",[mediatorId])).rowCount)return res.status(400).json({error:"الوسيط غير موجود"});const {rows}=await pool.query(`INSERT INTO operations(code,client_name,client_email,mediator_id,amount,category,payment_method,description,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id,code`,[code,String(b.client_name||"").trim()||null,String(b.client_email||"").trim()||null,mediatorId,Number(b.amount||0),String(b.category||"service"),String(b.payment_method||"").trim()||null,String(b.description||""),status]);await audit(req.session.admin_id,"create","operation",rows[0].id,req);res.status(201).json({id:Number(rows[0].id),code:rows[0].code});}catch(e){next(e)}});
app.patch("/api/admin/operations/:id",async(req,res,next)=>{try{const id=Number(req.params.id),q=await pool.query("SELECT * FROM operations WHERE id=$1",[id]);const cur=q.rows[0];if(!cur)return res.status(404).json({error:"العملية غير موجودة"});const b=req.body,status=opStatuses.includes(b.status)?b.status:cur.status,mediatorId=b.mediator_id===null||b.mediator_id===""?null:(b.mediator_id!==undefined?Number(b.mediator_id):cur.mediator_id);if(mediatorId&&!(await pool.query("SELECT id FROM mediators WHERE id=$1",[mediatorId])).rowCount)return res.status(400).json({error:"الوسيط غير موجود"});await pool.query(`UPDATE operations SET client_name=$1,client_email=$2,mediator_id=$3,amount=$4,category=$5,payment_method=$6,description=$7,status=$8,updated_at=NOW() WHERE id=$9`,[b.client_name!==undefined?String(b.client_name).trim()||null:cur.client_name,b.client_email!==undefined?String(b.client_email).trim()||null:cur.client_email,mediatorId,b.amount!==undefined?Number(b.amount):cur.amount,b.category!==undefined?String(b.category):cur.category,b.payment_method!==undefined?String(b.payment_method).trim()||null:cur.payment_method,b.description!==undefined?String(b.description):cur.description,status,id]);await audit(req.session.admin_id,"update","operation",id,req,{fields:Object.keys(b)});res.json({ok:true});}catch(e){next(e)}});

app.get("/api/admin/disputes",async(req,res,next)=>{try{const status=String(req.query.status||"");const sql=`SELECT d.*,o.code,o.client_name,o.amount,m.name mediator_name FROM disputes d JOIN operations o ON o.id=d.operation_id LEFT JOIN mediators m ON m.id=o.mediator_id ${status?"WHERE d.status=$1":""} ORDER BY d.id DESC`;const {rows}=await pool.query(sql,status?[status]:[]);res.json(rows);}catch(e){next(e)}});
app.post("/api/admin/disputes",async(req,res,next)=>{try{const b=req.body,operationId=Number(b.operation_id);if(!(await pool.query("SELECT id FROM operations WHERE id=$1",[operationId])).rowCount)return res.status(400).json({error:"العملية غير موجودة"});const {rows}=await pool.query(`INSERT INTO disputes(operation_id,opened_by,reason,details,status) VALUES($1,$2,$3,$4,'open') RETURNING id`,[operationId,String(b.opened_by||"admin"),String(b.reason||"مشكلة غير محددة"),String(b.details||"")]);await pool.query("UPDATE operations SET status='disputed',updated_at=NOW() WHERE id=$1",[operationId]);await audit(req.session.admin_id,"create","dispute",rows[0].id,req,{operation_id:operationId});res.status(201).json({id:Number(rows[0].id)});}catch(e){next(e)}});
app.patch("/api/admin/disputes/:id",async(req,res,next)=>{try{const id=Number(req.params.id),q=await pool.query("SELECT * FROM disputes WHERE id=$1",[id]);const cur=q.rows[0];if(!cur)return res.status(404).json({error:"النزاع غير موجود"});const allowed=["open","under_review","resolved_client","resolved_mediator","closed"],status=allowed.includes(req.body.status)?req.body.status:cur.status,note=req.body.resolution_note!==undefined?String(req.body.resolution_note):cur.resolution_note;await pool.query("UPDATE disputes SET status=$1,resolution_note=$2,updated_at=NOW() WHERE id=$3",[status,note,id]);if(["resolved_client","resolved_mediator","closed"].includes(status))await pool.query("UPDATE operations SET status='completed',updated_at=NOW() WHERE id=$1",[cur.operation_id]);await audit(req.session.admin_id,"update","dispute",id,req,{status});res.json({ok:true});}catch(e){next(e)}});
app.get("/api/admin/audit",async(req,res,next)=>{try{const {rows}=await pool.query(`SELECT l.*,a.email admin_email FROM audit_logs l LEFT JOIN admins a ON a.id=l.admin_id ORDER BY l.id DESC LIMIT 100`);res.json(rows.map(x=>({...x,metadata:safeJson(x.metadata,{})})));}catch(e){next(e)}});

const FALLBACK = "<h1>Wasit</h1><p>Page file not found.</p>";
let homeHtml = FALLBACK, adminHtml = FALLBACK;
try { homeHtml = fs.readFileSync(path.join(__dirname, "index.html"), "utf8"); } catch (e) { console.error("index.html:", e.message); }
try { adminHtml = fs.readFileSync(path.join(__dirname, "admin.html"), "utf8"); } catch (e) { console.error("admin.html:", e.message); }
const pages = { home: homeHtml, admin: adminHtml };
const sendPage = html => (_req, res) => { res.setHeader("Content-Type", "text/html; charset=utf-8"); res.send(html); };
app.get(["/", "/index.html"], sendPage(pages.home));
app.get(["/admin", "/admin.html"], sendPage(pages.admin));
app.use((req,res,next)=>{if(req.path.startsWith("/api/"))return res.status(404).json({error:"المسار غير موجود"});next();});
app.use((err,req,res,_next)=>{console.error(err);const st=Number(err.status||err.statusCode)||500;if(st>=400&&st<500)return res.status(st).json({error:st===413?"حجم الطلب كبير":"طلب غير صالح"});res.status(500).json({error:process.env.NODE_ENV==="production"?"حدث خطأ داخلي":err.message||"حدث خطأ داخلي"});});

module.exports=app;
if(require.main===module){const PORT=Number(process.env.PORT||3000);app.listen(PORT,()=>console.log(`Wasit running on http://localhost:${PORT}`));}
