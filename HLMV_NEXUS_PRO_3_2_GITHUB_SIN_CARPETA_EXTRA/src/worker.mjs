// HLMV NEXUS PRO - Cloudflare Worker + D1
// Protege datos administrativos; NO sustituye controles y aprobacion de Informatica.
import qrcode from 'qrcode-generator';
import { unzipSync, zipSync, strFromU8, strToU8 } from 'fflate';

const COLS = new Set(['areas','empleados','bienes','personas','hospital']);
const ROLES = new Set(['administrador','inspector','consulta']);
const MAX_JSON = 1500000, SESSION_AGE = 8*3600;
const rxUser = /^[\w.-]{3,40}$/;
const numId = ()=>crypto.randomUUID().replace(/-/g,'');
const now=()=>new Date().toISOString();
const enc=new TextEncoder();
const fmt=(v)=>String(v??'').trim();
const digits=(v)=>String(v??'').replace(/[^\d]/g,'');
const json=(obj,status=200,headers={})=>new Response(JSON.stringify(obj), {status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff',...headers}});
function fail(message,status=400){const err=new Error(message);err.status=status;throw err;}
const pjson=async(req)=>{
  const raw=await req.text();if(raw.length>MAX_JSON)fail('Solicitud demasiado grande.',413);
  let obj;try{obj=JSON.parse(raw);}catch{fail('JSON inválido.');}
  if(!obj||Array.isArray(obj)||typeof obj!=='object')fail('Formato inválido.');return obj;
};
const hex=arr=>Array.from(new Uint8Array(arr)).map(x=>x.toString(16).padStart(2,'0')).join('');
const sha=async str=>hex(await crypto.subtle.digest('SHA-256',enc.encode(str)));
const passhash=async (password,salt=null)=>{
  salt=salt||hex(crypto.getRandomValues(new Uint8Array(16)));
  const key=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveBits']);
  return salt+':'+hex(await crypto.subtle.deriveBits({name:'PBKDF2',salt:Uint8Array.from(salt.match(/../g).map(x=>parseInt(x,16))),iterations:100000,hash:'SHA-256'},key,256));
};
const passok=async (password,hash)=>{try{const [salt,dig]=hash.split(':');const candidate=(await passhash(password,salt)).split(':')[1];if(candidate.length!==dig.length)return false;let diff=0;for(let i=0;i<dig.length;i++)diff|=dig.charCodeAt(i)^candidate.charCodeAt(i);return diff===0;}catch{return false;}};
const checkPassword=p=>typeof p==='string'&&p.length>=12&&p.length<=128;
const sql=(db,statement,...v)=>db.prepare(statement).bind(...v).first();
const run=(db,statement,...v)=>db.prepare(statement).bind(...v).run();
const all=(db,statement,...v)=>db.prepare(statement).bind(...v).all().then(r=>r.results||[]);
let prepared=false;
async function initialize(db){
 if(prepared)return;
 await db.exec(`CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,username TEXT NOT NULL UNIQUE COLLATE NOCASE,name TEXT NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,created TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires_at INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
 CREATE TABLE IF NOT EXISTS docs(collection TEXT NOT NULL,id TEXT NOT NULL,data TEXT NOT NULL,updated TEXT NOT NULL,PRIMARY KEY(collection,id));
 CREATE INDEX IF NOT EXISTS docs_col ON docs(collection);
 CREATE UNIQUE INDEX IF NOT EXISTS bienes_num_unico ON docs(upper(json_extract(data,'$.numeroInventario'))) WHERE collection='bienes';
 CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,date TEXT NOT NULL,action TEXT NOT NULL,collection TEXT,document_id TEXT,details TEXT);
 CREATE TABLE IF NOT EXISTS images(name TEXT PRIMARY KEY,data TEXT NOT NULL,mime TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS login_limits(username TEXT PRIMARY KEY,count INTEGER NOT NULL,first_time INTEGER NOT NULL);`);
 prepared=true;
}
async function bootAdmin(env){
 if(await sql(env.DB,'SELECT id FROM users LIMIT 1'))return true;
 const username=fmt(env.HLMV_ADMIN_USER).toLowerCase(),password=env.HLMV_ADMIN_PASSWORD||'';
 if(!rxUser.test(username)||!checkPassword(password))return false;
 await run(env.DB,`INSERT OR IGNORE INTO users(id,username,name,password_hash,role,active,created) VALUES(?,?,?,?,?,?,?)`,numId(),username,'Administrador HLMV',await passhash(password),'administrador',1,now());
 return true;
}
const cookieName='__Host-hlmv_session';
function token(req){const ck=req.headers.get('cookie')||'';return decodeURIComponent((ck.match(new RegExp('(?:^|;\\s*)'+cookieName+'=([^;]+)'))||[])[1]||'');}
function sessionCookie(tok){return `${cookieName}=${encodeURIComponent(tok)}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=${tok?SESSION_AGE:0}`;}
async function currentUser(req,db){
 const t=token(req);if(!t)return null;
 const s=await sql(db,`SELECT u.id,u.username,u.name,u.role FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token_hash=? AND s.expires_at>? AND u.active=1`,await sha(t),Math.floor(Date.now()/1000));
 return s||null;
}
function role(user,...r){if(!user)fail('Inicia sesión para acceder al inventario.',401);if(r.length&&!r.includes(user.role))fail('No tienes permisos para esta operación.',403);}
function origin(req){if(!['POST','PUT','DELETE','PATCH'].includes(req.method))return;const o=req.headers.get('origin');if(o&&o!==new URL(req.url).origin)fail('Origen no autorizado.',403);if(req.headers.get('sec-fetch-site')==='cross-site')fail('Solicitud de otro sitio bloqueada.',403);}
const getDoc=async (db,col,id)=>{const x=await sql(db,'SELECT data FROM docs WHERE collection=? AND id=?',col,id);return x?JSON.parse(x.data):null;};
const listDocs=async (db,col)=> (await all(db,'SELECT id,data FROM docs WHERE collection=?',col)).map(r=>({id:r.id,...JSON.parse(r.data)}));
async function record(db,action,col,id,details=''){await run(db,'INSERT INTO audit(date,action,collection,document_id,details) VALUES(?,?,?,?,?)',now(),action,col,id,String(details).slice(0,450));}
function checkCol(col){if(!COLS.has(col))fail('Colección no permitida.');}
function validateData(data){if(!data||Array.isArray(data)||typeof data!=='object')fail('Registro inválido.');const out=Object.fromEntries(Object.entries(data).filter(([k])=>k!=='id'&&!k.startsWith('__')));if(JSON.stringify(out).length>200000)fail('Registro demasiado grande.',413);return out;}
async function cleanDoc(db,col,d,id){
 if(col==='areas'){d.nombre=fmt(d.nombre);if(!d.nombre||d.nombre.length>180)fail('Nombre de área inválido.');
 const old=id?await getDoc(db,col,id):null;if(old?.jefeNombre&&!fmt(d.jefeNombre)){let bens=await listDocs(db,'bienes');if(bens.some(b=>b.areaId===id&&b.personaTipo==='jefe'))fail('Designa un nuevo jefe antes de quitar la jefatura.');}
 }
 if(col==='empleados'){
  d.nombre=fmt(d.nombre);if(!d.nombre||d.nombre.length>180)fail('Nombre de empleado inválido.');
  if(!await getDoc(db,'areas',fmt(d.areaId)))fail('Selecciona un área existente.');
  const others=await listDocs(db,'empleados');if(others.some(p=>p.id!==id&&p.areaId===d.areaId&&((fmt(p.identidad)&&fmt(p.identidad)===fmt(d.identidad))||fmt(p.nombre).toLowerCase()===d.nombre.toLowerCase())))fail('El empleado ya está registrado en el área.');
 }
 if(col==='bienes'){
  d.numeroInventario=fmt(d.numeroInventario);d.descripcion=fmt(d.descripcion);
  if(!d.numeroInventario||!d.descripcion||d.numeroInventario.length>100||d.descripcion.length>1000)fail('Número de inventario y descripción obligatorios.');
  if(!await getDoc(db,'areas',fmt(d.areaId)))fail('Selecciona un área existente.');
  const duplicado=await sql(db,`SELECT id FROM docs WHERE collection='bienes' AND upper(json_extract(data,'$.numeroInventario'))=upper(?) AND id != ? LIMIT 1`,d.numeroInventario,id||'');
  if(duplicado)fail('Ya existe ese número de inventario.');
  if(d.personaTipo==='jefe')d.personaId=d.areaId;
  else if(d.personaTipo==='empleado'){const emp=await getDoc(db,'empleados',fmt(d.personaId));if(!emp||emp.areaId!==d.areaId)fail('Responsable no pertenece al área.');}
  else {d.personaTipo=null;d.personaId=null;}
  d.estadoBueno=!!d.estadoBueno;d.revisado=!!d.revisado;
 }
 for(const k of ['fotoURL','heroURL'])if(d[k]&& !/^\/imagenes\/[a-f0-9]{32}\.(png|jpg|webp|gif)$/.test(String(d[k])))fail('Imagen no permitida.');
 return d;
}
async function writeDoc(req,db,user,method){
 role(user,...(method==='DELETE'?['administrador']:['administrador','inspector']));const b=await pjson(req),col=fmt(b.col),id=fmt(b.id);checkCol(col);
 if(col==='hospital'&&user.role!=='administrador')fail('Solo administrador.',403);
 if(method==='DELETE'){
  if(!id)fail('Falta ID.');const original=await getDoc(db,col,id);if(!original)fail('Registro no encontrado.',404);
  if(col==='areas'){const items=await Promise.all(['bienes','empleados'].map(c=>listDocs(db,c)));if(items.flat().some(r=>r.areaId===id))fail('Área con bienes o empleados: no se puede eliminar.');}
  let reasignados=0;
  if(col==='empleados'){
   const area=await getDoc(db,'areas',original.areaId);const bienes=(await listDocs(db,'bienes')).filter(x=>x.personaTipo==='empleado'&&x.personaId===id);
   if(bienes.length&&!fmt(area?.jefeNombre))fail('Registra un jefe de área antes de retirar al responsable.');
   if(bienes.length){const st=now();const cmds=bienes.map(b=>{const data={...b,personaTipo:'jefe',personaId:b.areaId};delete data.id;return db.prepare('UPDATE docs SET data=?,updated=? WHERE collection=? AND id=?').bind(JSON.stringify(data),st,'bienes',b.id);});
    for(let i=0;i<cmds.length;i+=25)await db.batch(cmds.slice(i,i+25));reasignados=bienes.length;}
  }
  await run(db,'DELETE FROM docs WHERE collection=? AND id=?',col,id);await record(db,'eliminar',col,id,`${reasignados} reasignados`);return {ok:true,reasignados};
 }
 const old=method==='PUT'?await getDoc(db,col,id):null;if(method==='PUT'&&!old)fail('Registro no encontrado.',404);
 const data=await cleanDoc(db,col,validateData({...old,...(b.data||{})}),id);
 const dest=method==='POST'?((col==='hospital'&&id==='info')?'info':numId()):id;
 try{if(method==='POST')await run(db,'INSERT INTO docs(collection,id,data,updated) VALUES(?,?,?,?)',col,dest,JSON.stringify(data),now());
 else await run(db,'UPDATE docs SET data=?,updated=? WHERE collection=? AND id=?',JSON.stringify(data),now(),col,dest);
 }catch(e){if(/UNIQUE/i.test(e.message))fail('El bien ya existe.');throw e;}
 await record(db,method==='POST'?'crear':'actualizar',col,dest,data.numeroInventario||data.nombre||'');return {id:dest};
}
async function userList(db){const r=await all(db,'SELECT id,username,name,role,active,created FROM users ORDER BY username');return {users:r};}
async function handleUsers(req,db,user){role(user,'administrador');if(req.method==='GET')return userList(db);
 const b=await pjson(req),name=fmt(b.name);if(!name||name.length>120)fail('Nombre inválido.');if(!ROLES.has(b.role))fail('Rol no permitido.');
 if(req.method==='POST'){
  const username=fmt(b.username).toLowerCase();if(!rxUser.test(username))fail('Usuario inválido.');if(!checkPassword(b.password))fail('Contraseña: mínimo 12 caracteres.');const id=numId();
  try{await run(db,'INSERT INTO users(id,username,name,password_hash,role,active,created) VALUES(?,?,?,?,?,?,?)',id,username,name,await passhash(b.password),b.role,1,now());}catch(e){if(/UNIQUE/i.test(e.message))fail('Ese usuario ya existe.');throw e;}
  await record(db,'crear_usuario','usuarios',id,username);return {ok:true,id};
 }
 if(req.method==='PUT'){
  const id=fmt(b.id),before=await sql(db,'SELECT * FROM users WHERE id=?',id);if(!before)fail('Usuario no encontrado.',404);
  const active=b.active===false?0:1;
  if(id===user.id&&(!active||b.role!=='administrador'))fail('No puedes quitar tu propio perfil administrador.');
  if(before.role==='administrador'&&(!active||b.role!=='administrador')){const r=await sql(db,"SELECT count(*) AS n FROM users WHERE role='administrador' AND active=1");if(r.n<2)fail('Debe permanecer un administrador activo.');}
  const changed=!!b.password||before.role!==b.role||before.active!==active;
  if(b.password&&!checkPassword(b.password))fail('La nueva contraseña debe tener mínimo 12 caracteres.');
  const newHash=b.password?await passhash(b.password):before.password_hash;
  await run(db,'UPDATE users SET name=?,role=?,active=?,password_hash=? WHERE id=?',name,b.role,active,newHash,id);
  if(changed)await run(db,'DELETE FROM sessions WHERE user_id=?',id);await record(db,'modificar_usuario','usuarios',id);return {ok:true};
 }
 fail('Método no permitido.',405);
}
async function login(req,db){const b=await pjson(req),username=fmt(b.username).toLowerCase(),password=String(b.password||'');
 const lim=await sql(db,'SELECT * FROM login_limits WHERE username=?',username),ts=Math.floor(Date.now()/1000);if(lim&&lim.count>=6&&ts-lim.first_time<900)fail('Demasiados intentos. Intenta luego.',429);
 const u=await sql(db,'SELECT * FROM users WHERE username=?',username);
 if(!u||!u.active||!await passok(password,u.password_hash)){
  if(lim&&ts-lim.first_time<900)await run(db,'UPDATE login_limits SET count=count+1 WHERE username=?',username);
  else await run(db,'INSERT INTO login_limits(username,count,first_time) VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET count=1,first_time=excluded.first_time',username,1,ts);
  fail('Usuario o contraseña incorrectos.',401);
 }
 await run(db,'DELETE FROM login_limits WHERE username=?',username);
 const random=crypto.getRandomValues(new Uint8Array(36));const t=Array.from(random,x=>x.toString(16).padStart(2,'0')).join('');
 await run(db,'INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)',await sha(t),u.id,ts+SESSION_AGE);
 return json({ok:true,user:{id:u.id,username:u.username,name:u.name,role:u.role} },200,{'set-cookie':sessionCookie(t)});
}
function binary(content,mime,file){return new Response(content,{headers:{'content-type':mime,'content-disposition':file?`attachment; filename="${file}"`:'inline','cache-control':'no-store','x-content-type-options':'nosniff'}});}
const xmlesc=v=>fmt(v).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
async function report(db,areaId){const areas=Object.fromEntries((await listDocs(db,'areas')).map(a=>[a.id,a]));const empl=Object.fromEntries((await listDocs(db,'empleados')).map(x=>[x.id,x]));let bienes=await listDocs(db,'bienes');if(areaId)bienes=bienes.filter(b=>b.areaId===areaId);bienes.sort((a,b)=>fmt(a.numeroInventario).localeCompare(fmt(b.numeroInventario),'es'));
 const headers=['Inventario','Descripción','Serie','Color','Estado','Área','Responsable','Valor L','Fecha adquisición','Marca','Modelo','Ficha','Revisión'];const rows=bienes.map(b=>[b.numeroInventario,b.descripcion,b.numeroSerie,b.color,b.estadoBueno?'Bueno':'Por verificar',areas[b.areaId]?.nombre||'',b.personaTipo==='jefe'?areas[b.areaId]?.jefeNombre:b.personaTipo==='empleado'?empl[b.personaId]?.nombre:'',b.precio,b.fechaAdquisicion,b.marca,b.modelo,b.numeroFicha,b.revisado?'Revisado':'Pendiente'].map(fmt));return {headers,rows};}
function exportOffice(r,format){
 const Z={};
 if(format==='xlsx'){
  const sheet=[r.headers,...r.rows].map((x,i)=>`<row r="${i+1}">${x.map((v,j)=>`<c r="${String.fromCharCode(65+j)}${i+1}" t="inlineStr"><is><t>${xmlesc(v)}</t></is></c>`).join('')}</row>`).join('');
  Z['[Content_Types].xml']=`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>`;
  Z['_rels/.rels']=`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/office/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`;
  Z['xl/workbook.xml']=`<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Inventario HLMV" sheetId="1" r:id="rId1"/></sheets></workbook>`;
  Z['xl/_rels/workbook.xml.rels']=`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/office/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`;
  Z['xl/worksheets/sheet1.xml']=`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>${sheet}</sheetData></worksheet>`;
 }else{
  const p=(x,b=false)=>`<w:p><w:r>${b?'<w:rPr><w:b/></w:rPr>':''}<w:t>${xmlesc(x)}</w:t></w:r></w:p>`;
  const tr=(x,b=false)=>`<w:tr>${x.map(v=>`<w:tc>${p(v,b)}</w:tc>`).join('')}</w:tr>`;
  Z['[Content_Types].xml']=`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`;
  Z['_rels/.rels']=`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/office/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`;
  Z['word/document.xml']=`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${p('Inventario HLMV',true)}<w:tbl>${tr(r.headers,true)}${r.rows.map(x=>tr(x)).join('')}</w:tbl><w:sectPr/></w:body></w:document>`;
 }
 return zipSync(Object.fromEntries(Object.entries(Z).map(([k,v])=>[k,strToU8(v)])),{level:5});
}
function normalize(s){return fmt(s).toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'');}
function decodeXml(s){return s.replace(/&#x([0-9a-f]+);/gi,(_,n)=>String.fromCodePoint(parseInt(n,16))).replace(/&#(\d+);/g,(_,n)=>String.fromCodePoint(+n)).replace(/&(?:amp|lt|gt|quot|apos);/g,m=>({'&amp;':'&','&lt;':'<','&gt;':'>','&quot;':'"','&apos;':"'"}[m]));}
const unxml=s=>decodeXml(s.replace(/<[^>]*>/g,''));
function readXlsx(bytes){
 if(bytes.byteLength>12*1024*1024)fail('Excel demasiado grande (máximo 12 MB).',413);
 let z;try{z=unzipSync(bytes);}catch{fail('Archivo Excel dañado.');}
 const keys=Object.keys(z),size=keys.reduce((a,k)=>a+z[k].length,0);if(keys.length>3000||size>90*1024*1024)fail('Excel demasiado grande o comprimido de forma sospechosa.');
 const read=k=>z[k]?strFromU8(z[k]):'';if(!read('xl/workbook.xml'))fail('No se encontraron las hojas del Excel.');
 const shared=Array.from(read('xl/sharedStrings.xml').matchAll(/<si(?:\s[^>]*)?>([\s\S]*?)<\/si>/g),m=>unxml(m[1]));
 const book=read('xl/workbook.xml'),rel=read('xl/_rels/workbook.xml.rels');const links={};for(const m of rel.matchAll(/<Relationship\b([^>]*)\/>/g)){const id=(m[1].match(/\bId="([^"]+)"/)||[])[1],target=(m[1].match(/\bTarget="([^"]+)"/)||[])[1];if(id&&target)links[id]=target;}
 const sheets=[];
 for(const sh of book.matchAll(/<sheet\s+[^>]*name="([^"]+)"[^>]*(?:r:id|id)="([^"]+)"[^>]*\/?\s*>/g)){
  let file=links[sh[2]]||'';file=file.replace(/^\//,'');if(!file.startsWith('xl/'))file='xl/'+file;if(!file.startsWith('xl/worksheets/'))continue;
  const xml=read(file);if(!xml)continue;let rows=[];
  for(const row of xml.matchAll(/<row\b[^>]*r="(\d+)"[^>]*>([\s\S]*?)<\/row>/g)){
   const i=+row[1];if(i>30000)fail('La hoja es demasiado larga.');const cols={};
   for(const c of row[2].matchAll(/<c\b([^>]*?)(?:\/>|>([\s\S]*?)<\/c>)/g)){
    const rf=(c[1].match(/\br="([A-Z]+)\d+"/)||[])[1];if(!rf)continue;let idx=0;for(const x of rf)idx=idx*26+x.charCodeAt(0)-64;idx--;if(idx>180)continue;
    const type=(c[1].match(/\bt="([^"]+)"/)||[])[1];const payload=c[2]||'';let v=(payload.match(/<v>([\s\S]*?)<\/v>/)||[])[1]||'';
    if(type==='s')v=shared[+v]||'';else if(type==='inlineStr')v=unxml(payload);
    cols[idx]=fmt(decodeXml(v));
   }
   rows.push({n:i,cols});
  }
  sheets.push({name:decodeXml(sh[1]),rows});
 }
 if(!sheets.length)fail('No se encontraron hojas compatibles.');return sheets;
}
const pick=(row,opts)=>Number(Object.entries(row).find(([k,v])=>opts.some(o=>normalize(v).includes(o)))?.[0]??-1);
function parseExcel(bytes){
 const sheets=readXlsx(bytes);const bienes=[],ignored=[];
 for(const sh of sheets){let hdr=null;for(const r of sh.rows.slice(0,45)){const ci=pick(r.cols,['inventario','siafi','codigo del bien']),cd=pick(r.cols,['descripcion','nombre del bien','detalle del bien']);if(ci>=0&&cd>=0&&ci!==cd){hdr={row:r.n,col:r.cols,ci,cd};break;}}
 if(!hdr){ignored.push(sh.name);continue;}
 const getCol=options=>pick(hdr.col,options),fields={marca:getCol(['marca']),modelo:getCol(['modelo']),numeroSerie:getCol(['serie']),color:getCol(['color']),estadoOriginal:getCol(['estado']),numeroFicha:getCol(['ficha']),precio:getCol(['precio','valor','costo'])};
 let area='',jefe='';for(const r of sh.rows.slice(0,15)){for(const [k,v] of Object.entries(r.cols)){const n=normalize(v),i=+k;if(n.includes('departamento/oficina')||n.includes('institucion:'))area=area||fmt(r.cols[i+2]||r.cols[i+1]);if(n.includes('nombre de responsable'))jefe=jefe||fmt(r.cols[i+2]||r.cols[i+1]);}}
 if(!area){const line=sh.rows.find(r=>r.n===8)||sh.rows.find(r=>r.n===7);area=fmt(line?.cols[2])||sh.name;}
 let count=0;
 for(const r of sh.rows){if(r.n<=hdr.row)continue;const val=k=>k>=0?fmt(r.cols[k]):'';const desc=val(hdr.cd),number=val(hdr.ci);if(!desc||normalize(desc)==='descripcion del bien')continue;
 if(hdr.ci===1&&!/^\d+(?:\.0+)?$/.test(val(0)))continue;if(!number&&hdr.ci!==1)continue;
 const inventory=number.replace(/\.0+$/,'');const valid=/^\d[\dA-Za-z._/-]*$/.test(inventory)&&!/^(0|000)$/.test(inventory);
 const id=valid?inventory:'PEND-'+digits(r.n).padStart(7,'0')+'-'+normalize(area).replace(/[^a-z]/g,'').slice(0,5).toUpperCase();
 bienes.push({area,responsable:jefe,numeroInventario:id,numeroOriginal:number,pendienteNumero:!valid,descripcion:desc,...Object.fromEntries(Object.entries(fields).map(([k,v])=>[k,val(v)])),estadoBueno:['bueno','buen estado','excelente'].includes(normalize(val(fields.estadoOriginal))),hoja:sh.name,fila:r.n});count++;
 }
 if(!count)ignored.push(sh.name);
 }
 if(!bienes.length)fail('No se encontraron bienes completos en el Excel.');if(bienes.length>500)fail('Máximo 500 bienes por Excel en la versión gratuita; divide la hoja en varios archivos.');
 return {bienes,hojasIgnoradas:ignored};
}
async function importExcel(req,db,user,preview){
 role(user,'administrador','inspector');if(!fmt(req.headers.get('X-Filename')).toLowerCase().endsWith('.xlsx'))fail('Selecciona un .xlsx.');
 const raw=new Uint8Array(await req.arrayBuffer());const parsed=parseExcel(raw);const current=await listDocs(db,'bienes');const used=new Set(current.map(x=>normalize(x.numeroInventario)));
 let added=0,dup=0;const records=[];
 for(const b of parsed.bienes){if(used.has(normalize(b.numeroInventario))){dup++;continue;}used.add(normalize(b.numeroInventario));records.push(b);added++;}
 if(preview)return {
 total:parsed.bienes.length,nuevos:added,duplicados:dup,yaImportados:dup,
 sinSIAFI:parsed.bienes.filter(x=>x.pendienteNumero).length,
 areas:[...new Set(parsed.bienes.map(x=>x.area))],
 ignoradas:parsed.hojasIgnoradas.map(hoja=>({hoja})),
 filas:parsed.bienes.slice(0,100).map(x=>({...x,estadoImportacion:current.some(z=>normalize(z.numeroInventario)===normalize(x.numeroInventario))?'ya_importado':x.pendienteNumero?'nuevo_pendiente':'nuevo'}))
 };
 let areaIds=new Map((await listDocs(db,'areas')).map(a=>[normalize(a.nombre),a.id]));const originalAreas=areaIds.size;const timestamp=now();
 for(const b of records){const name=b.area||'Área por verificar';if(!areaIds.has(normalize(name))){const id=numId();await run(db,'INSERT INTO docs(collection,id,data,updated) VALUES(?,?,?,?)','areas',id,JSON.stringify({nombre:name,jefeNombre:b.responsable||'',jefeIdentidad:''}),timestamp);areaIds.set(normalize(name),id);}}
 let imported=0;
 for(let i=0;i<records.length;i+=30){const chunk=records.slice(i,i+30);const placeholders=chunk.map(()=>'(?,?,?,?)').join(',');const bind=[];
 for(const b of chunk){const areaId=areaIds.get(normalize(b.area||'Área por verificar'));let obj={...b,areaId,personaTipo:b.responsable?'jefe':null,personaId:b.responsable?areaId:null,revisado:true,revisionOrigen:'Documento Excel oficial',revisionFecha:timestamp};delete obj.area;delete obj.responsable;
 bind.push('bienes',numId(),JSON.stringify(obj),timestamp);}
 // D1 soporta máximo 100 parámetros por consulta: 4 por registro => lotes de 24.
 if(bind.length>100){for(let a=0;a<chunk.length;a+=24){const subset=chunk.slice(a,a+24);const vals=[];
 for(const b of subset){const areaId=areaIds.get(normalize(b.area||'Área por verificar'));const obj={...b,areaId,personaTipo:b.responsable?'jefe':null,personaId:b.responsable?areaId:null,revisado:true,revisionOrigen:'Documento Excel oficial',revisionFecha:timestamp};delete obj.area;delete obj.responsable;vals.push('bienes',numId(),JSON.stringify(obj),timestamp);}
 const q='INSERT OR IGNORE INTO docs(collection,id,data,updated) VALUES '+subset.map(()=>'(?,?,?,?)').join(',');const rr=await run(db,q,...vals);imported+=(rr.meta?.changes||0);}
 }else{const rr=await run(db,'INSERT OR IGNORE INTO docs(collection,id,data,updated) VALUES '+placeholders,...bind);imported+=(rr.meta?.changes||0);}
 }
 await record(db,'import_excel','bienes','',`${imported} nuevos / ${dup} duplicados`);
 return {ok:true,importados:imported,insertados:imported,nuevos:imported,areasCreadas:areaIds.size-originalAreas,responsablesCreados:0,jefaturasPorVerificar:0,duplicados:dup,total:parsed.bienes.length};
}
async function route(req,env){
 const url=new URL(req.url),path=url.pathname,method=req.method,db=env.DB;
 if(!db)fail('Falta vincular la base D1 con nombre DB en Cloudflare.',503);
 await initialize(db);origin(req);
 if(path==='/api/health')return json({ok:true,db:'d1'});
 const ready=await bootAdmin(env);if(!ready)fail('Falta configurar los secretos HLMV_ADMIN_USER y HLMV_ADMIN_PASSWORD en Cloudflare.',503);
 const user=await currentUser(req,db);
 if(path==='/api/status'&&method==='GET')return json({initialized:true,authenticated:!!user,user,version:'3.3-cloudflare',central:true,lan:false,publicUrl:url.origin});
 if(path==='/api/setup')fail('El administrador inicial se configura mediante secretos de Cloudflare.',403);
 if(path==='/api/login'&&method==='POST')return login(req,db);
 if(path==='/api/logout'&&method==='POST'){const t=token(req);if(t)await run(db,'DELETE FROM sessions WHERE token_hash=?',await sha(t));return json({ok:true},200,{'set-cookie':sessionCookie('')});}
 role(user);
 if(path==='/api/users'&&['GET','POST','PUT'].includes(method))return json(await handleUsers(req,db,user));
 if(path==='/api/password'&&method==='POST'){
  const b=await pjson(req),u=await sql(db,'SELECT password_hash FROM users WHERE id=?',user.id);if(!await passok(fmt(b.actual),u.password_hash))fail('Contraseña actual incorrecta.',403);
  if(!checkPassword(b.nueva))fail('La contraseña nueva necesita 12 caracteres.');await run(db,'UPDATE users SET password_hash=? WHERE id=?',await passhash(b.nueva),user.id);await run(db,'DELETE FROM sessions WHERE user_id=?',user.id);return json({ok:true,relogin:true});
 }
 if(path==='/api/list'&&method==='GET'){
  const col=fmt(url.searchParams.get('col'));checkCol(col);let docs=await listDocs(db,col);const fld=url.searchParams.get('field');if(fld)docs=docs.filter(d=>fmt(d[fld])===fmt(url.searchParams.get('value')));
  const ord=url.searchParams.get('order');if(ord)docs.sort((a,b)=>fmt(a[ord]).localeCompare(fmt(b[ord]),'es'));const lim=Number(url.searchParams.get('limit'))||docs.length;return json({docs:docs.slice(0,Math.max(0,Math.min(lim,25000))),size:docs.length});
 }
 if(path==='/api/doc'&&method==='GET'){const col=fmt(url.searchParams.get('col')),id=fmt(url.searchParams.get('id'));checkCol(col);const d=await getDoc(db,col,id);return json({id,exists:!!d,data:d});}
 if(path==='/api/doc'&&['POST','PUT','DELETE'].includes(method))return json(await writeDoc(req,db,user,method));
 if(path==='/api/audit'&&method==='GET'){role(user,'administrador','inspector');return json({events:await all(db,'SELECT * FROM audit ORDER BY seq DESC LIMIT 200')});}
 if(path==='/api/bienes/revision'&&method==='POST'){
  role(user,'administrador','inspector');const b=await pjson(req),ids=[...new Set(b.ids||[])];if(ids.length>3000||ids.some(x=>!/^[a-f0-9]{32}$/.test(x)))fail('Lista de bienes inválida.');
  const st=now(),rv=b.revisado?1:0;for(let i=0;i<ids.length;i+=90){const ch=ids.slice(i,i+90);await run(db,`UPDATE docs SET data=json_set(data,'$.revisado',json(?),'$.revisionFecha',?,'$.revisionOrigen',?),updated=? WHERE collection='bienes' AND id IN (${ch.map(()=>'?').join(',')})`,rv?'true':'false',rv?st:'',rv?'Revisión manual':'',st,...ch);}
  await record(db,'revision_masiva','bienes','',String(ids.length));return json({ok:true,actualizados:ids.length});
 }
 if(path==='/api/qr'&&method==='GET'){
  const number=fmt(url.searchParams.get('numero'));if(!number)fail('Falta número de inventario.');const b=await sql(db,`SELECT id FROM docs WHERE collection='bienes' AND upper(json_extract(data,'$.numeroInventario'))=upper(?)`,number);if(!b)fail('Bien no registrado.',404);
  const addr=url.origin+'/index.html#/bien/'+encodeURIComponent(number);const qr=qrcode(0,'M');qr.addData(addr);qr.make();return binary(qr.createSvgTag({cellSize:5,margin:3}), 'image/svg+xml');
 }
 if(path.startsWith('/imagenes/')&&method==='GET'){const name=path.slice(10);if(!/^[a-f0-9]{32}\.(png|jpg|webp|gif)$/.test(name))fail('Imagen no encontrada.',404);const x=await sql(db,'SELECT data,mime FROM images WHERE name=?',name);if(!x)fail('Imagen no encontrada.',404);const raw=Uint8Array.from(atob(x.data),c=>c.charCodeAt(0));return binary(raw,x.mime);}
 if(path==='/api/photo'&&method==='POST'){
  role(user,'administrador','inspector');const b=await pjson(req),raw=fmt(b.data);if(raw.length>1100000)fail('Foto demasiado grande para D1. Reduce la imagen a menos de 750 KB.',413);
  let u;try{u=Uint8Array.from(atob(raw),c=>c.charCodeAt(0));}catch{fail('Imagen inválida.');}if(u.length>750000||u.length<8)fail('Foto debe ocupar menos de 750 KB.');
  let ext,mime;if(u[0]===255&&u[1]===216){ext='jpg';mime='image/jpeg';}else if(u[0]===137&&u[1]===80){ext='png';mime='image/png';}else if(String.fromCharCode(...u.slice(0,4))==='RIFF'){ext='webp';mime='image/webp';}else if(String.fromCharCode(...u.slice(0,3))==='GIF'){ext='gif';mime='image/gif';}else fail('Formato de imagen inválido.');
  const name=numId()+'.'+ext;await run(db,'INSERT INTO images(name,data,mime) VALUES(?,?,?)',name,raw,mime);return json({url:'/imagenes/'+name});
 }
 if(path==='/api/export'&&method==='GET'){const f=url.searchParams.get('format')||'xlsx';if(!['xlsx','docx'].includes(f))fail('Formato no disponible.');const buf=exportOffice(await report(db,url.searchParams.get('areaId')),f);return binary(buf,f==='xlsx'?'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet':'application/vnd.openxmlformats-officedocument.wordprocessingml.document','inventario-hlmv.'+f);}
 if(path==='/api/backup'&&method==='GET'){
  role(user,'administrador');const docs=await all(db,'SELECT collection,id,data,updated FROM docs ORDER BY collection,id');const images=await all(db,'SELECT name,data,mime FROM images');const obj={format:'HLMV-D1-3.3',created:now(),docs,images};const zip=zipSync({'inventario.json':strToU8(JSON.stringify(obj))},{level:6});return binary(zip,'application/zip','respaldo-hlmv-d1.zip');
 }
 if(path==='/api/import/review'&&method==='GET')return json({pendientes:[]});
 if(path==='/api/import/preview'&&method==='POST')return json(await importExcel(req,db,user,true));
 if(path==='/api/import/commit'&&method==='POST')return json(await importExcel(req,db,user,false));
 if(path.startsWith('/api/import/pdf/'))fail('El lector de PDF SIAFI aún no está disponible en Cloudflare Workers. Utiliza la versión Windows para extraerlo y luego importa el Excel resultante.',501);
 if(path==='/api/restore')fail('La restauración desde ZIP de Windows aún no está habilitada en Cloudflare. Guarda los respaldos y consulta a Informática para migraciones.',501);
 fail('Ruta no encontrada.',404);
}
export default {async fetch(req,env){try{const url=new URL(req.url);if(url.pathname.startsWith('/api/')||url.pathname.startsWith('/imagenes/'))return await route(req,env);return env.ASSETS.fetch(req);}catch(e){return json({error:e.message||'Error interno.'},e.status||500);}}};
