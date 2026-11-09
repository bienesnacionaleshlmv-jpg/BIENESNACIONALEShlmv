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
 CREATE TABLE IF NOT EXISTS public_qr(asset_id TEXT NOT NULL PRIMARY KEY,token TEXT NOT NULL UNIQUE,created TEXT NOT NULL);
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
  d.estadoBueno=!!d.estadoBueno;if(d.descargado)d.estadoBueno=false;d.revisado=!!d.revisado;
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
  if(col==='bienes')await run(db,'DELETE FROM public_qr WHERE asset_id=?',id);
  await run(db,'DELETE FROM docs WHERE collection=? AND id=?',col,id);await record(db,'eliminar',col,id,col==='bienes'?fmt(original.numeroInventario):`${reasignados} reasignados`);return {ok:true,reasignados};
 }
 const old=method==='PUT'?await getDoc(db,col,id):null;if(method==='PUT'&&!old)fail('Registro no encontrado.',404);
 const incoming={...old,...(b.data||{})};
 if(col==='bienes'){
   if(old?.descargado&&user.role!=='administrador')fail('Un bien descargado solo puede modificarse por administración.',403);
   const exclusive=['descargado','fechaDescargo','motivoDescargo','referenciaDescargo','descargadoPor','fechaReactivacion','motivoReactivacion','historialDescargos'];
   for(const key of exclusive){if(old&&Object.prototype.hasOwnProperty.call(old,key))incoming[key]=old[key];else delete incoming[key];}
 }
 const data=await cleanDoc(db,col,validateData(incoming),id);
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
const xmlesc=v=>fmt(v).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\uFFFE\uFFFF]/g,'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&apos;');
async function report(db,areaId){
 const areas=Object.fromEntries((await listDocs(db,'areas')).map(a=>[a.id,a]));
 const empl=Object.fromEntries((await listDocs(db,'empleados')).map(x=>[x.id,x]));
 let bienes=await listDocs(db,'bienes');
 if(areaId)bienes=bienes.filter(b=>b.areaId===areaId);
 bienes.sort((a,b)=>fmt(a.numeroInventario).localeCompare(fmt(b.numeroInventario),'es',{numeric:true}));
 if(bienes.length>5000)fail('Este reporte supera los 5000 bienes. Exporta por área para no exceder el límite gratuito del servidor.',413);
 const headers=['N.º inventario','Descripción','N.º serie','Color','Estado físico','Área','Responsable','Valor de adquisición (L)','Fecha adquisición','Marca','Modelo','N.º ficha','Situación','Fecha de descargo','Motivo del descargo','Referencia de descargo'];
 const rows=bienes.map(b=>[b.numeroInventario,b.descripcion,b.numeroSerie,b.color,b.descargado?'Fuera de servicio':b.estadoBueno?'Funciona':'Sin confirmar',areas[b.areaId]?.nombre||'',b.personaTipo==='jefe'?areas[b.areaId]?.jefeNombre:b.personaTipo==='empleado'?empl[b.personaId]?.nombre:'',b.precio,b.fechaAdquisicion,b.marca,b.modelo,b.numeroFicha,b.descargado?'Descargado':'Activo',b.fechaDescargo||'',b.motivoDescargo||'',b.referenciaDescargo||''].map(fmt));
 return {headers,rows,area:areaId?(areas[areaId]?.nombre||'Área seleccionada'):'Todo el hospital'};
}
// Ambos formatos se generan directamente en Cloudflare Workers como archivos Office Open XML.
// No requiere Microsoft Office instalado ni enviar el inventario a un servicio externo.
function exportOffice(r,format){
 const Z={};
 if(format==='xlsx'){
  const cref=(n)=>{let v=n+1,x='';while(v){v--;x=String.fromCharCode(65+v%26)+x;v=Math.floor(v/26);}return x;};
  const cell=(v,i,j)=>{
   const address=cref(j)+(i+1);
   if(i>0&&j===7&&fmt(v)!==''&&Number.isFinite(Number(v)))return `<c r="${address}" s="2"><v>${Number(v)}</v></c>`;
   const text=xmlesc(v);
   return `<c r="${address}" t="inlineStr"${i===0?' s="1"':''}><is><t xml:space="preserve">${text}</t></is></c>`;
  };
  const cells=[r.headers,...r.rows].map((x,i)=>`<row r="${i+1}"${i===0?' ht="30" customHeight="1"':''}>${x.map((v,j)=>cell(v,i,j)).join('')}</row>`).join('');
  const widths=[18,42,22,16,19,27,27,22,20,22,22,18,22].map((w,i)=>`<col min="${i+1}" max="${i+1}" width="${w}" customWidth="1"/>`).join('');
  const last=r.rows.length+1;
  Z['[Content_Types].xml']=`<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>`;
  Z['_rels/.rels']=`<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`;
  Z['xl/workbook.xml']=`<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Inventario HLMV" sheetId="1" r:id="rId1"/></sheets></workbook>`;
  Z['xl/_rels/workbook.xml.rels']=`<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`;
  Z['xl/styles.xml']=`<?xml version="1.0" encoding="UTF-8"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="10"/><name val="Calibri"/></font><font><b/><sz val="10"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF21422B"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/><xf numFmtId="2" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/></cellXfs></styleSheet>`;
  Z['xl/worksheets/sheet1.xml']=`<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><cols>${widths}</cols><sheetData>${cells}</sheetData><autoFilter ref="A1:M${Math.max(1,last)}"/></worksheet>`;
 }else{
  const p=(text,b=false)=>`<w:p><w:pPr><w:spacing w:after="0"/></w:pPr><w:r>${b?'<w:rPr><w:b/></w:rPr>':''}<w:t xml:space="preserve">${xmlesc(text)}</w:t></w:r></w:p>`;
  const cell=(v,b=false)=>`<w:tc><w:tcPr><w:tcW w:w="1400" w:type="dxa"/></w:tcPr>${p(v,b)}</w:tc>`;
  const tableRow=(v,b=false)=>`<w:tr>${v.map(x=>cell(x,b)).join('')}</w:tr>`;
  const fields=[0,1,2,5,6,12];
  const cols=fields.map(i=>r.headers[i]);
  const records=r.rows.map(x=>tableRow(fields.map(i=>x[i]))).join('');
  const annex=r.rows.map((x,i)=>p(`${x[0] || '(sin número)'} — ${x[1] || 'Bien sin descripción'}`,true)+p(`Marca: ${x[9]||'—'}  |  Modelo: ${x[10]||'—'}  |  Color: ${x[3]||'—'}  |  Valor: L ${x[7]||'—'}  |  Adquisición: ${x[8]||'—'}  |  Ficha: ${x[11]||'—'}`)).join('');
  Z['[Content_Types].xml']=`<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`;
  Z['_rels/.rels']=`<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`;
  Z['word/document.xml']=`<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${p('HOSPITAL LEONARDO MARTÍNEZ VALENZUELA',true)}${p('Departamento de Bienes Nacionales',true)}${p(`Inventario: ${r.area}`)}${p(`Fecha de exportación: ${new Date().toISOString().slice(0,10)}  ·  Total de bienes: ${r.rows.length}`)}<w:tbl><w:tblPr><w:tblBorders><w:top w:val="single"/><w:left w:val="single"/><w:bottom w:val="single"/><w:right w:val="single"/><w:insideH w:val="single"/><w:insideV w:val="single"/></w:tblBorders></w:tblPr>${tableRow(cols,true)}${records}</w:tbl>${p('Información adicional de los bienes',true)}${annex}<w:sectPr><w:pgSz w:w="15840" w:h="12240" w:orient="landscape"/><w:pgMar w:top="720" w:right="720" w:bottom="720" w:left="720"/></w:sectPr></w:body></w:document>`;
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
// QR publicos: URL aleatoria de 128 bits. No se permite consultar el inventario completo sin sesion.
const publicQrPath=(token)=>'/api/public/ficha/'+token;
async function publicQrLink(db,numero,originUrl){
 const asset=await sql(db,`SELECT id FROM docs WHERE collection='bienes' AND upper(json_extract(data,'$.numeroInventario'))=upper(?) LIMIT 1`,numero);
 if(!asset)fail('Bien no registrado.',404);
 await run(db,'INSERT OR IGNORE INTO public_qr(asset_id,token,created) VALUES(?,?,?)',asset.id,numId(),now());
 const row=await sql(db,'SELECT token FROM public_qr WHERE asset_id=?',asset.id);
 if(!row?.token)fail('No se pudo crear el enlace QR.',500);
 return originUrl+publicQrPath(row.token);
}
function publicHtmlEscape(value){return fmt(value).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
// Los enlaces publicos revelan expresamente el nombre del responsable para el bien
// cuyo QR se ha escaneado. Identidad, telefono, correo, costo e historial NO se exponen.
async function responsibleForPublicAsset(db,b){
 const areaId=fmt(b.areaId),personaId=fmt(b.personaId);
 if(b.personaTipo==='jefe'){
  const area=areaId?await getDoc(db,'areas',areaId):null;
  return {nombre:fmt(area?.jefeNombre)||'Sin responsable asignado',cargo:fmt(area?.jefeNombre)?'Jefatura de área':''};
 }
 if(b.personaTipo==='empleado'){
  const emp=personaId?await getDoc(db,'empleados',personaId):null;
  if(emp&&fmt(emp.areaId)===areaId&&fmt(emp.nombre))return {nombre:fmt(emp.nombre),cargo:'Personal asignado'};
 }
 return {nombre:'Sin responsable asignado',cargo:''};
}
function publicFichaHTML(b,responsible,token){
 // Lista blanca de CAMPOS publicos: datos del objeto y NOMBRE del encargado.
 // No mostrar números de identidad, contacto, costos, documentos ni historial.
 const fields=[
  ['Número de inventario',b.numeroInventario],
  ['Descripción',b.descripcion],
  ['Marca',b.marca],['Modelo',b.modelo],['Serie',b.numeroSerie],['Color',b.color],
  ['Responsable del bien',responsible.nombre],
  ...(responsible.cargo?[['Tipo de asignación',responsible.cargo]]:[]),
  ['Situación del bien',b.descargado?'Descargado · Fuera de servicio':'Activo'],
  ['Estado físico',b.descargado?'Fuera de servicio':b.estadoBueno===true?'Registrado como bueno':'Sin confirmar']
 ];
 const photo=/^\/imagenes\/[a-f0-9]{32}\.(?:png|jpg|webp|gif)$/.test(fmt(b.fotoURL));
 const rows=fields.filter(([,v])=>v!==undefined&&v!==null&&v!=='').map(([k,v])=>'<div class="pair"><dt>'+publicHtmlEscape(k)+'</dt><dd>'+publicHtmlEscape(v)+'</dd></div>').join('');
 return `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex,nofollow,noarchive"><title>Ficha pública - ${publicHtmlEscape(b.numeroInventario)}</title><style>
 :root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#f6f8fb;color:#1d2c3d;font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}header{display:flex;align-items:center;gap:14px;border-bottom:1px solid #d7e2ec;padding:15px 18px;background:#ffffff;color:#17324f;font-size:14px;flex-wrap:wrap}.wrap{max-width:820px;margin:32px auto;padding:0 16px}.card{background:#fff;border:1px solid #dbe4ee;border-radius:20px;overflow:hidden;padding:25px;box-shadow:0 18px 42px rgba(12,45,87,.06)}small{color:#64758b}.eyebrow{color:#0B4DA2;text-transform:uppercase;letter-spacing:.1em;font-weight:800;font-size:12px}h1{font-size:clamp(23px,5vw,34px);line-height:1.15;margin:10px 0 18px;color:#0b2c4e}.photo{display:block;max-height:350px;max-width:100%;object-fit:contain;border-radius:14px;margin:0 auto 20px;background:#f5f8fc;border:1px solid #e3ebf3}.pair{display:grid;grid-template-columns:minmax(135px,1fr) minmax(0,2fr);gap:12px;padding:13px 0;border-top:1px solid #e3ebf3}dt{color:#64758b}dd{margin:0;overflow-wrap:anywhere;font-weight:700;color:#17324f}.note{margin:18px 0 0;color:#64758b;font-size:13px}.mark{color:#0B4DA2;font-weight:900;margin-right:9px}.brandline{display:flex;align-items:center;gap:8px;min-width:0}.hospital{font-size:12px;color:#64758b}.govimg{height:48px;width:auto;max-width:min(50vw,430px);object-fit:contain;display:block}.bnmark{height:44px;width:auto;display:block}@media(max-width:480px){header{padding:12px 14px;gap:10px}.wrap{margin:18px auto}.card{padding:18px}.pair{grid-template-columns:1fr;gap:2px}.govimg{height:34px;max-width:47vw}.bnmark{height:32px}}
 </style></head><body><header><img class="govimg" src="/icons/gobierno-salud-full.png" alt="Gobierno de Honduras - Secretaría de Salud"><img class="bnmark" src="/icons/bn-logo.png" alt="BN"><div class="brandline"><strong>Bienes Nacionales</strong><span class="hospital">Hospital Leonardo Martínez Valenzuela</span></div></header><main class="wrap"><article class="card"><div class="eyebrow">Consulta de inventario · Solo lectura</div><h1>${publicHtmlEscape(b.descripcion||'Bien inventariado')}</h1>${photo?`<img class="photo" src="/api/public/foto/${token}" alt="Fotografía del bien" loading="lazy">`:''}<dl>${rows}</dl><p class="note">Esta ficha pública muestra el nombre del responsable asignado actualmente. No da acceso a editar el inventario ni muestra identidad, teléfono, correo, valores de adquisición o historial. Los nombres están visibles para cualquier persona que tenga el QR.</p></article></main></body></html>`;
}
async function publicFicha(req,db,token){
 if(req.method!=='GET'&&req.method!=='HEAD')fail('Método no permitido.',405);
 if(!/^[a-f0-9]{32}$/.test(token))fail('Ficha no encontrada.',404);
 const row=await sql(db,`SELECT d.data FROM public_qr p JOIN docs d ON d.collection='bienes' AND d.id=p.asset_id WHERE p.token=? LIMIT 1`,token);
 if(!row)fail('Ficha no encontrada.',404);
 const bien=JSON.parse(row.data);
 const responsible=await responsibleForPublicAsset(db,bien);
 const body=publicFichaHTML(bien,responsible,token);
 return new Response(req.method==='HEAD'?null:body,{status:200,headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','x-frame-options':'DENY','referrer-policy':'no-referrer','content-security-policy':"default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"}});
}
async function publicFichaPhoto(req,db,token){
 if(req.method!=='GET'&&req.method!=='HEAD')fail('Método no permitido.',405);
 if(!/^[a-f0-9]{32}$/.test(token))fail('Fotografía no encontrada.',404);
 const row=await sql(db,`SELECT d.data FROM public_qr p JOIN docs d ON d.collection='bienes' AND d.id=p.asset_id WHERE p.token=? LIMIT 1`,token);
 if(!row)fail('Fotografía no encontrada.',404);
 const b=JSON.parse(row.data),foto=fmt(b.fotoURL);
 if(!/^\/imagenes\/[a-f0-9]{32}\.(?:png|jpg|webp|gif)$/.test(foto))fail('Fotografía no encontrada.',404);
 const img=await sql(db,'SELECT data,mime FROM images WHERE name=?',foto.slice('/imagenes/'.length));
 if(!img)fail('Fotografía no encontrada.',404);
 if(!['image/jpeg','image/png','image/webp','image/gif'].includes(img.mime))fail('Fotografía no encontrada.',404);
 const raw=Uint8Array.from(atob(img.data),c=>c.charCodeAt(0));
 return new Response(req.method==='HEAD'?null:raw,{status:200,headers:{'content-type':img.mime,'cache-control':'no-store','x-content-type-options':'nosniff','x-frame-options':'DENY','referrer-policy':'no-referrer'}});
}
async function route(req,env){
 const url=new URL(req.url),path=url.pathname,method=req.method,db=env.DB;
 if(!db)fail('Falta vincular la base D1 con nombre DB en Cloudflare.',503);
 await initialize(db);origin(req);
 if(path==='/api/health')return json({ok:true,db:'d1'});
 // La ficha publica se resuelve ANTES de comprobar una sesion. No expone /api/doc ni /api/list.
 if(path.startsWith('/api/public/ficha/'))return publicFicha(req,db,path.slice('/api/public/ficha/'.length));
 if(path.startsWith('/api/public/foto/'))return publicFichaPhoto(req,db,path.slice('/api/public/foto/'.length));
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
 if(path==='/api/bienes/descargo'&&method==='POST'){
  role(user,'administrador');
  const body=await pjson(req);
  const id=fmt(body.id), accion=fmt(body.accion);
  if(!/^[a-f0-9]{32}$/.test(id))fail('Bien inválido.',400);
  if(!['descargar','reactivar'].includes(accion))fail('Acción no permitida.',400);
  const motivo=fmt(body.motivo),referencia=fmt(body.referencia);
  if(motivo.length<8||motivo.length>500)fail('Indica un motivo de 8 a 500 caracteres.',400);
  if(referencia.length>120)fail('Referencia documental demasiado larga.',400);
  const bien=await getDoc(db,'bienes',id);if(!bien)fail('Bien no encontrado.',404);
  if(!!bien.descargado===(accion==='descargar'))fail('La situación del bien ya fue actualizada. Refresca la página.',409);
  const fecha=now();
  const movimiento={fecha,accion,motivo,referencia,usuario:user.username};
  const historico=Array.isArray(bien.historialDescargos)?bien.historialDescargos.slice(-49):[];
  historico.push(movimiento);
  const nuevo={...bien,descargado:accion==='descargar',historialDescargos:historico};
  if(accion==='descargar'){
    nuevo.fechaDescargo=fecha;nuevo.motivoDescargo=motivo;
    nuevo.referenciaDescargo=referencia;nuevo.descargadoPor=user.username;
    nuevo.estadoBueno=false;
  }else{
    nuevo.fechaReactivacion=fecha;nuevo.motivoReactivacion=motivo;
  }
  // No tocar el número SIAFI, el QR, el área ni el responsable.
  const current=await run(db,"UPDATE docs SET data=?,updated=? WHERE collection=? AND id=? AND json_extract(data,'$.descargado') IS ?",JSON.stringify(nuevo),fecha,'bienes',id,bien.descargado?1:null);
  // El control condicional cubre las fichas anteriores que no tenían el campo descargado.
  if(!current.meta?.changes)fail('Otro usuario modificó este bien. Actualiza e inténtalo nuevamente.',409);
  await record(db,accion==='descargar'?'descargo':'reactivacion','bienes',id,`${fmt(bien.numeroInventario)} | ${motivo} | Ref: ${referencia}`);
  return json({ok:true,descargado:nuevo.descargado,fecha});
 }
 if(path==='/api/bienes/eliminar'&&method==='POST'){
  role(user,'administrador');
  const b=await pjson(req),ids=[...new Set(Array.isArray(b.ids)?b.ids:[])];
  if(!ids.length||ids.length>25||ids.some(id=>typeof id!=='string'||!/^[a-f0-9]{32}$/.test(id)))fail('Selecciona entre 1 y 25 bienes para eliminar.',400);
  const encontrados=await all(db,`SELECT id,json_extract(data,'$.numeroInventario') AS numero FROM docs WHERE collection='bienes' AND id IN (${ids.map(()=>'?').join(',')})`,...ids);
  if(encontrados.length!==ids.length)fail('Uno o varios bienes ya no existen. Actualiza el buscador antes de eliminarlos.',409);
  const fecha=now(),cmds=[];
  for(const x of encontrados){
   cmds.push(db.prepare('DELETE FROM public_qr WHERE asset_id=?').bind(x.id));
   cmds.push(db.prepare('DELETE FROM docs WHERE collection=? AND id=?').bind('bienes',x.id));
   cmds.push(db.prepare('INSERT INTO audit(date,action,collection,document_id,details) VALUES(?,?,?,?,?)').bind(fecha,'eliminar','bienes',x.id,fmt(x.numero).slice(0,100)));
  }
  await db.batch(cmds);
  return json({ok:true,eliminados:encontrados.length});
 }

 if(path==='/api/audit'&&method==='GET'){role(user,'administrador','inspector');return json({events:await all(db,'SELECT * FROM audit ORDER BY seq DESC LIMIT 200')});}
 if(path==='/api/public/link'&&method==='GET'){
  const numero=fmt(url.searchParams.get('numero'));if(!numero)fail('Falta numero de inventario.');
  return json({url:await publicQrLink(db,numero,url.origin)});
 }
 if(path==='/api/qr'&&method==='GET'){
  const numero=fmt(url.searchParams.get('numero'));if(!numero)fail('Falta numero de inventario.');
  const addr=await publicQrLink(db,numero,url.origin);const qr=qrcode(0,'M');qr.addData(addr);qr.make();return binary(qr.createSvgTag({cellSize:5,margin:3}),'image/svg+xml');
 }
 if(path.startsWith('/imagenes/')&&method==='GET'){const name=path.slice(10);if(!/^[a-f0-9]{32}\.(png|jpg|webp|gif)$/.test(name))fail('Imagen no encontrada.',404);const x=await sql(db,'SELECT data,mime FROM images WHERE name=?',name);if(!x)fail('Imagen no encontrada.',404);const raw=Uint8Array.from(atob(x.data),c=>c.charCodeAt(0));return binary(raw,x.mime);}
 if(path==='/api/photo'&&method==='POST'){
  role(user,'administrador','inspector');const b=await pjson(req),raw=fmt(b.data);if(raw.length>1100000)fail('Foto demasiado grande para D1. Reduce la imagen a menos de 750 KB.',413);
  let u;try{u=Uint8Array.from(atob(raw),c=>c.charCodeAt(0));}catch{fail('Imagen inválida.');}if(u.length>750000||u.length<8)fail('Foto debe ocupar menos de 750 KB.');
  let ext,mime;if(u[0]===255&&u[1]===216){ext='jpg';mime='image/jpeg';}else if(u[0]===137&&u[1]===80){ext='png';mime='image/png';}else if(String.fromCharCode(...u.slice(0,4))==='RIFF'){ext='webp';mime='image/webp';}else if(String.fromCharCode(...u.slice(0,3))==='GIF'){ext='gif';mime='image/gif';}else fail('Formato de imagen inválido.');
  const name=numId()+'.'+ext;await run(db,'INSERT INTO images(name,data,mime) VALUES(?,?,?)',name,raw,mime);return json({url:'/imagenes/'+name});
 }
 if(path==='/api/export'&&(method==='GET'||method==='HEAD')){
  const f=url.searchParams.get('format')||'xlsx';if(!['xlsx','docx'].includes(f))fail('Formato no disponible.');
  const mime=f==='xlsx'?'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet':'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
  const filename=(url.searchParams.get('areaId')?'inventario-area-hlmv.':'inventario-general-hlmv.')+f;
  if(method==='HEAD')return new Response(null,{headers:{'content-type':mime,'content-disposition':`attachment; filename="${filename}"`,'cache-control':'no-store'}});
  const buf=exportOffice(await report(db,url.searchParams.get('areaId')),f);
  return binary(buf,mime,filename);
 }
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
