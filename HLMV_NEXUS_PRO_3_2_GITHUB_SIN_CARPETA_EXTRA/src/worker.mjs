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
 const rows=bienes.map(b=>[b.numeroInventario,b.descripcion,b.numeroSerie,b.color,fmt(b.estadoOriginal)||(b.estadoBueno?'BUENO':'SIN CONFIRMAR'),areas[b.areaId]?.nombre||'',b.personaTipo==='jefe'?areas[b.areaId]?.jefeNombre:b.personaTipo==='empleado'?empl[b.personaId]?.nombre:'',b.precio,b.fechaAdquisicion,b.marca,b.modelo,b.numeroFicha,b.descargado?'Descargado':'Activo',b.fechaDescargo||'',b.motivoDescargo||'',b.referenciaDescargo||''].map(fmt));
 return {headers,rows,area:areaId?(areas[areaId]?.nombre||'Área seleccionada'):'Todo el hospital'};
}
// Exportación PRE FICHA: formato basado en el archivo Auditoria.xlsx proporcionado por Bienes Nacionales.
// Ambos formatos se generan directamente en Cloudflare Workers como archivos Office Open XML.
// No requiere Microsoft Office instalado ni enviar el inventario a un servicio externo.
// Exportación institucional basada en el modelo "PRE FICHA" de Auditoria.xlsx.
// Usa únicamente datos existentes de D1; no modifica ningún registro.
function exportOffice(r,format){
 const areaGroups=new Map();
 for(const rec of r.rows){
  const area=fmt(rec[5])||'SIN ÁREA';
  if(!areaGroups.has(area))areaGroups.set(area,[]);
  areaGroups.get(area).push(rec);
 }
 if(!areaGroups.size)areaGroups.set(r.area==='Todo el hospital'?'SIN REGISTROS':r.area,[]);
 const groups=Array.from(areaGroups,([name,records])=>({name,records})).sort((a,b)=>a.name.localeCompare(b.name,'es'));
 const fecha=new Date().toLocaleDateString('es-HN',{timeZone:'America/Tegucigalpa',day:'2-digit',month:'2-digit',year:'numeric'});
 const firstNonEmpty=s=>fmt(s)||'—';
 function responsibleOf(g){
  const names=[...new Set(g.records.map(x=>fmt(x[6])).filter(Boolean))];
  return names.length===1?names[0]:names.length>1?'VARIOS RESPONSABLES (VER DETALLE)':'SIN RESPONSABLE ASIGNADO';
 }
 const localText=x=>xmlesc(x===undefined||x===null?'':String(x));
 if(format==='xlsx'){
  const Z={};
  const excelCol=n=>{let a='';for(n++;n;n=Math.floor((n-1)/26))a=String.fromCharCode(65+(n-1)%26)+a;return a;};
  const numericPrice=v=>{
   if(typeof v==='number')return Number.isFinite(v)?v:null;
   const s=fmt(v).replace(/\s|L\.?|HNL|\$/gi,'').replace(/,/g,'');
   return s&&/^-?\d+(?:\.\d+)?$/.test(s)?Number(s):null;
  };
  const textCell=(col,row,value,style=0,number=false)=>{
   const ref=excelCol(col-1)+row;
   if(number&&Number.isFinite(value))return `<c r="${ref}" s="${style}"><v>${value}</v></c>`;
   return `<c r="${ref}" s="${style}" t="inlineStr"><is><t xml:space="preserve">${localText(value)}</t></is></c>`;
  };
  const rowXml=(i,cols,height)=>`<row r="${i}" ht="${height}" customHeight="1">${cols.map((v,j)=>textCell(j+1,i,v.v,v.s,v.n)).join('')}</row>`;
  const blank=(style=0,n=15)=>Array.from({length:n},()=>({v:'',s:style}));
  const merged=(cellValues,start,end,rn,fromStyle=0)=>{
   for(let j=start;j<=end;j++)if(!cellValues[j-1])cellValues[j-1]={v:'',s:fromStyle};
  };
  const allSheets=[];
  const used=new Set();
  const uniqueName=(name)=>{
   let s=fmt(name).replace(/[\\/?*\[\]:]/g,' ').replace(/[\u0000-\u001F]/g,'').trim().slice(0,31)||'Área';
   let base=s,n=2;while(used.has(s.toLowerCase())){const suffix=' '+n++;s=base.slice(0,31-suffix.length)+suffix;}
   used.add(s.toLowerCase());return s;
  };
  function makePreFicha(g){
   const lines=[],merges=[];
   const row=(i,cols,h=25)=>lines.push(rowXml(i,cols,h));
   const mg=(a)=>merges.push(`<mergeCell ref="${a}"/>`);
   for(let i=1;i<=4;i++){const c=blank(1);c[0].v=['SECRETARÍA DE SALUD','DIRECCIÓN NACIONAL DE BIENES DEL ESTADO','BIENES NACIONALES','PRE FICHA'][i-1];c[0].s=i===4?2:1;row(i,c,i===4?30:27);mg(`A${i}:O${i}`);}
   row(5,blank(0),10);row(6,blank(0),12);
   const v7=blank(0);v7[0]={v:'INSTITUCIÓN:',s:3};v7[2]={v:'SECRETARÍA DE SALUD',s:4};v7[7]={v:'NOMBRE DE RESPONSABLE:',s:3};v7[9]={v:responsibleOf(g),s:4};row(7,v7,30);
   ['A7:B7','C7:F7','H7:I7','J7:O7'].forEach(mg);
   const v8=blank(0);v8[0]={v:'DEPARTAMENTO/OFICINA:',s:3};v8[2]={v:g.name,s:4};v8[7]={v:'FECHA:',s:3};v8[9]={v:fecha,s:4};row(8,v8,30);
   ['A8:B8','C8:F8','H8:I8','J8:O8'].forEach(mg);
   row(9,blank(0),10);row(10,blank(0),10);
   const h11=blank(5);h11[0].v='DOCUMENTO RESPALDO';h11[2].v='DATOS DEL BIEN';h11[12].v='ESTADO DEL BIEN';h11[13].v='NÚMERO DE FICHA';h11[14].v='Precio/Total';row(11,h11,30);
   ['A11:B11','C11:L11','M11:M12','N11:N12','O11:O12'].forEach(mg);
   const h12=blank(6);[[0,'N°'],[1,'INVENTARIO'],[2,'DESCRIPCIÓN DEL BIEN'],[5,'MARCA'],[7,'MODELO'],[9,'SERIE'],[11,'COLOR']].forEach(([i,v])=>h12[i].v=v);h12[12].v='';h12[13].v='';h12[14].v='';row(12,h12,33);
   ['C12:E12','F12:G12','H12:I12','J12:K12'].forEach(mg);
   g.records.forEach((x,i)=>{
    const n=i+13,cols=blank(i%2?8:7),status=fmt(x[4])||'SIN CONFIRMAR';
    cols[0].v=i+1;cols[0].n=true;
    cols[1].v=x[0];cols[2].v=x[1];cols[5].v=x[9]||'SIN MARCA';cols[7].v=x[10]||'SIN MODELO';
    cols[9].v=x[2]||'SIN SERIE';cols[11].v=x[3];cols[12].v=status.toUpperCase();cols[13].v=x[11];
    const precio=numericPrice(x[7]);if(precio!==null){cols[14]={v:precio,s:9,n:true};}else cols[14].v=x[7];
    const dlen=fmt(x[1]).length;row(n,cols,Math.min(90,Math.max(29,Math.ceil(dlen/55)*16)));
    [`C${n}:E${n}`,`F${n}:G${n}`,`H${n}:I${n}`,`J${n}:K${n}`].forEach(mg);
   });
   // Deja espacio para firmas al final de cada pre ficha.
   const bottom=12+g.records.length,sign=bottom+4;
   row(bottom+1,blank(0),12);row(bottom+2,blank(0),12);row(bottom+3,blank(0),12);
   let f=blank(10);f[0].v='JEFE DE BIENES NACIONALES';f[5].v='ADMINISTRACIÓN';f[10].v='AUDITORÍA INTERNA';row(sign,f,25);
   let s=blank(11);s[0].v='________________________________';s[5].v='________________________________';s[10].v='________________________________';row(sign+1,s,24);
   let fs=blank(11);fs[0].v='Firma';fs[5].v='Firma';fs[10].v='Firma';row(sign+2,fs,24);
   let dni=blank(11);dni[0].v='DNI: ________________________';dni[5].v='DNI: ________________________';dni[10].v='DNI: ________________________';row(sign+3,dni,24);
   for(let j=0;j<4;j++)for(const [a,b] of [[1,5],[6,10],[11,15]])mg(`${excelCol(a-1)}${sign+j}:${excelCol(b-1)}${sign+j}`);
   const ref=`A1:O${sign+3}`;
   const dims=[9,19,18,7,7,11,11,12,10,12,10,17,20,19,18];
   const colxml=dims.map((w,i)=>`<col min="${i+1}" max="${i+1}" width="${w}" customWidth="1"/>`).join('');
   return `<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetPr><pageSetUpPr fitToPage="1"/></sheetPr><dimension ref="${ref}"/><sheetViews><sheetView workbookViewId="0" showGridLines="0" zoomScale="80"><pane ySplit="12" topLeftCell="A13" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><sheetFormatPr defaultRowHeight="17"/><cols>${colxml}</cols><sheetData>${lines.join('')}</sheetData><mergeCells count="${merges.length}">${merges.join('')}</mergeCells><printOptions horizontalCentered="1"/><pageMargins left="0.25" right="0.25" top="0.6" bottom="0.6" header="0.3" footer="0.3"/><pageSetup paperSize="5" orientation="landscape" fitToWidth="1" fitToHeight="0"/></worksheet>`;
  }
  const detHeaders=['INVENTARIO','DESCRIPCIÓN DEL BIEN','ÁREA','RESPONSABLE ACTUAL','SITUACIÓN','FECHA DESCARGO','MOTIVO DESCARGO','REFERENCIA','FECHA ADQUISICIÓN','N.º SERIE'];
  function makeDetalle(){
   const lines=[];const c1=detHeaders.map(h=>({v:h,s:5}));lines.push(rowXml(1,c1,33));
   const detail=r.rows;
   detail.forEach((x,i)=>{
    const c=[x[0],x[1],x[5],x[6],x[12],x[13],x[14],x[15],x[8],x[2]].map(v=>({v,s:i%2?8:7}));
    lines.push(rowXml(i+2,c,Math.min(70,Math.max(25,Math.ceil(fmt(x[1]).length/50)*14))));
   });
   const widths=[19,48,31,35,18,18,40,28,18,22];
   const colxml=widths.map((w,i)=>`<col min="${i+1}" max="${i+1}" width="${w}" customWidth="1"/>`).join('');
   return `<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><cols>${colxml}</cols><sheetData>${lines.join('')}</sheetData><autoFilter ref="A1:J${Math.max(1,r.rows.length+1)}"/><pageMargins left="0.25" right="0.25" top="0.5" bottom="0.5" header="0.3" footer="0.3"/><pageSetup paperSize="5" orientation="landscape" fitToWidth="1" fitToHeight="0"/></worksheet>`;
  }
  for(const g of groups)allSheets.push({name:uniqueName(g.name),xml:makePreFicha(g)});
  allSheets.push({name:uniqueName('DETALLE RESPONSABLES'),xml:makeDetalle()});
  const font=(bold=false,color='FF192A3E',size=10)=>`<font>${bold?'<b/>':''}<sz val="${size}"/><color rgb="${color}"/><name val="Calibri"/></font>`;
  const fill=color=>`<fill><patternFill patternType="solid"><fgColor rgb="${color}"/><bgColor indexed="64"/></patternFill></fill>`;
  const fullBorder='<border><left style="thin"><color rgb="FF454545"/></left><right style="thin"><color rgb="FF454545"/></right><top style="thin"><color rgb="FF454545"/></top><bottom style="thin"><color rgb="FF454545"/></bottom><diagonal/></border>';
  const styles=`<?xml version="1.0" encoding="UTF-8"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><numFmts count="1"><numFmt numFmtId="164" formatCode="#,##0.00"/></numFmts><fonts count="5">${font()}${font(true,'FF111827',14)}${font(true,'FF111827',12)}${font(true,'FF15283B',10)}${font(false,'FF5F6E82',9)}</fonts><fills count="5"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill>${fill('FFB8CAEA')}${fill('FFD6D6D8')}${fill('FFF6F8FB')}</fills><borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border>${fullBorder}</borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="12"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf><xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf><xf numFmtId="0" fontId="3" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="3" fillId="2" borderId="1" xfId="0" applyFill="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="3" fillId="3" borderId="1" xfId="0" applyFill="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="0" fillId="4" borderId="1" xfId="0" applyFill="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf><xf numFmtId="164" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyAlignment="1"><alignment horizontal="right" vertical="center"/></xf><xf numFmtId="0" fontId="3" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf><xf numFmtId="0" fontId="4" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf></cellXfs></styleSheet>`;
  Z['[Content_Types].xml']=`<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>${allSheets.map((s,i)=>`<Override PartName="/xl/worksheets/sheet${i+1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`).join('')}</Types>`;
  Z['_rels/.rels']='<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>';
  Z['xl/workbook.xml']=`<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>${allSheets.map((s,i)=>`<sheet name="${localText(s.name)}" sheetId="${i+1}" r:id="rId${i+1}"/>`).join('')}</sheets></workbook>`;
  Z['xl/_rels/workbook.xml.rels']=`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${allSheets.map((s,i)=>`<Relationship Id="rId${i+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${i+1}.xml"/>`).join('')}<Relationship Id="rId${allSheets.length+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`;
  Z['xl/styles.xml']=styles;
  allSheets.forEach((s,i)=>{Z[`xl/worksheets/sheet${i+1}.xml`]=s.xml;});
  return zipSync(Object.fromEntries(Object.entries(Z).map(([k,v])=>[k,strToU8(v)])),{level:5});
 }
 // WORD: reproduce el encabezado, campos de oficina, cuadro de bienes y firmas.
 const Z={};
 const p=(t,style={})=>{
  const content=localText(t),size=style.size||18,spacing=style.after??90;
  let para=`<w:p><w:pPr><w:spacing w:after="${spacing}"/>${style.center?'<w:jc w:val="center"/>':''}${style.break?'<w:pageBreakBefore/>':''}</w:pPr><w:r><w:rPr>${style.bold?'<w:b/>':''}<w:sz w:val="${size}"/>${style.color?`<w:color w:val="${style.color}"/>`:''}</w:rPr><w:t xml:space="preserve">${content}</w:t></w:r></w:p>`;
  return para;
 };
 const tableCell=(value,width,opts={})=>{
  const shading=opts.fill?`<w:shd w:val="clear" w:fill="${opts.fill}"/>`:'';
  const span=opts.span?`<w:gridSpan w:val="${opts.span}"/>`:'';
  const vertical=opts.vMerge?`<w:vMerge${opts.vMerge==='restart'?' w:val="restart"':''}/>`:'';
  const text=p(value,{bold:opts.bold,size:opts.fontSize||16,center:opts.center,after:0,color:opts.color});
  return `<w:tc><w:tcPr><w:tcW w:w="${width}" w:type="dxa"/>${span}${vertical}${shading}<w:vAlign w:val="center"/></w:tcPr>${text}</w:tc>`;
 };
 const row=(cells,repeat=false)=>`<w:tr>${repeat?'<w:trPr><w:tblHeader w:val="true"/></w:trPr>':''}${cells.join('')}</w:tr>`;
 const borders=`<w:tblBorders>${['top','left','bottom','right','insideH','insideV'].map(e=>`<w:${e} w:val="single" w:sz="6" w:color="465160"/>`).join('')}</w:tblBorders>`;
 const simpleTable=(rows,widths,opts={})=>`<w:tbl><w:tblPr><w:tblW w:w="${widths.reduce((a,b)=>a+b,0)}" w:type="dxa"/><w:tblLayout w:type="fixed"/>${opts.borders===false?'':borders}</w:tblPr><w:tblGrid>${widths.map(w=>`<w:gridCol w:w="${w}"/>`).join('')}</w:tblGrid>${rows.join('')}</w:tbl>`;
 const widths=[650,1800,5150,1700,1700,1900,1450,1350,1550,1550];
 const wsum=(start,count)=>widths.slice(start,start+count).reduce((a,b)=>a+b,0);
 const makeDocs=groups.map((g,gi)=>{
  const parts=[];
  parts.push(p('SECRETARÍA DE SALUD',{bold:true,size:26,center:true,after:20,break:gi>0}));
  parts.push(p('DIRECCIÓN NACIONAL DE BIENES DEL ESTADO',{bold:true,size:21,center:true,after:20}));
  parts.push(p('BIENES NACIONALES',{bold:true,size:21,center:true,after:20}));
  parts.push(p('PRE FICHA',{bold:true,size:23,center:true,after:210}));
  const mw=[2600,6550,2600,6550];
  const infoRows=[
   row([tableCell('INSTITUCIÓN:',mw[0],{bold:true}),tableCell('SECRETARÍA DE SALUD',mw[1]),tableCell('NOMBRE DE RESPONSABLE:',mw[2],{bold:true}),tableCell(responsibleOf(g),mw[3])]),
   row([tableCell('DEPARTAMENTO/OFICINA:',mw[0],{bold:true}),tableCell(g.name,mw[1]),tableCell('FECHA:',mw[2],{bold:true}),tableCell(fecha,mw[3])])
  ];
  parts.push(simpleTable(infoRows,mw));
  parts.push(p(' ',{after:125,size:12}));
  const hdr1=row([
   tableCell('DOCUMENTO RESPALDO',wsum(0,2),{span:2,fill:'B8CAEA',bold:true,center:true}),
   tableCell('DATOS DEL BIEN',wsum(2,5),{span:5,fill:'B8CAEA',bold:true,center:true}),
   tableCell('ESTADO DEL BIEN',widths[7],{fill:'B8CAEA',bold:true,center:true,vMerge:'restart'}),
   tableCell('NÚMERO DE FICHA',widths[8],{fill:'B8CAEA',bold:true,center:true,vMerge:'restart'}),
   tableCell('PRECIO/TOTAL',widths[9],{fill:'B8CAEA',bold:true,center:true,vMerge:'restart'})
  ],true);
  const hdr2=row(['N°','INVENTARIO','DESCRIPCIÓN DEL BIEN','MARCA','MODELO','SERIE','COLOR'].map((t,i)=>tableCell(t,widths[i],{fill:i<2?'B8CAEA':'D6D6D8',bold:true,center:true})).concat([tableCell('',widths[7],{vMerge:'continue',fill:'B8CAEA'}),tableCell('',widths[8],{vMerge:'continue',fill:'B8CAEA'}),tableCell('',widths[9],{vMerge:'continue',fill:'B8CAEA'})]),true);
  const rows=[hdr1,hdr2];
  g.records.forEach((x,i)=>{
   const values=[i+1,x[0],x[1],x[9]||'SIN MARCA',x[10]||'SIN MODELO',x[2]||'SIN SERIE',x[3],x[4]||'SIN CONFIRMAR',x[11],x[7]];
   rows.push(row(values.map((v,j)=>tableCell(v,widths[j],{center:j!==2,fill:i%2?'F6F8FB':null,fontSize:15}))));
  });
  if(!g.records.length)rows.push(row([tableCell('SIN BIENES REGISTRADOS',widths.reduce((a,b)=>a+b,0),{span:10,center:true})]));
  parts.push(simpleTable(rows,widths));
  parts.push(p(' ',{after:200}));
  const sigW=[6250,6250,6250];
  parts.push(simpleTable([
   row([tableCell('JEFE DE BIENES NACIONALES',sigW[0],{bold:true,center:true}),tableCell('ADMINISTRACIÓN',sigW[1],{bold:true,center:true}),tableCell('AUDITORÍA INTERNA',sigW[2],{bold:true,center:true})]),
   row(sigW.map(w=>tableCell('_____________________________',w,{center:true}))),
   row(sigW.map(w=>tableCell('Firma',w,{center:true}))),
   row(sigW.map(w=>tableCell('DNI: _________________________',w,{center:true})))
  ],sigW,{borders:false}));
  // Un anexo opcional preserva la asignación individual y la información de descargo
  // cuando la oficina tiene más de una persona responsable o hay bajas registradas.
  const respCount=new Set(g.records.map(x=>fmt(x[6])).filter(Boolean)).size;
  if(respCount>1||g.records.some(x=>fmt(x[12])==='Descargado')){
   parts.push(p('ANEXO: ASIGNACIÓN Y SITUACIÓN DE LOS BIENES',{bold:true,size:19,after:85}));
   const aw=[2000,5300,2800,2600,6000];
   const annexRows=[row(['Inventario','Descripción','Responsable','Situación','Descargo / referencia'].map((v,i)=>tableCell(v,aw[i],{fill:'B8CAEA',bold:true,center:true})),true)];
   for(const x of g.records)annexRows.push(row([x[0],x[1],x[6],x[12],`${x[13]||''} ${x[15]||''} ${x[14]||''}`.trim()].map((v,i)=>tableCell(v,aw[i],{fontSize:15,center:i!==1}))));
   parts.push(simpleTable(annexRows,aw));
  }
  return parts.join('');
 });
 Z['[Content_Types].xml']='<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>';
 Z['_rels/.rels']='<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>';
 Z['word/document.xml']=`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${makeDocs.join('')}<w:sectPr><w:pgSz w:w="20160" w:h="12240" w:orient="landscape"/><w:pgMar w:top="650" w:right="650" w:bottom="650" w:left="650" w:header="300" w:footer="300"/></w:sectPr></w:body></w:document>`;
 return zipSync(Object.fromEntries(Object.entries(Z).map(([k,v])=>[k,strToU8(v)])),{level:5});
}

function normalize(s){return fmt(s).toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'');}
function decodeXml(s){return s.replace(/&#x([0-9a-f]+);/gi,(_,n)=>String.fromCodePoint(parseInt(n,16))).replace(/&#(\d+);/g,(_,n)=>String.fromCodePoint(+n)).replace(/&(?:amp|lt|gt|quot|apos);/g,m=>({'&amp;':'&','&lt;':'<','&gt;':'>','&quot;':'"','&apos;':"'"}[m]));}
const unxml=s=>decodeXml(s.replace(/<[^>]*>/g,''));

// Lector XLSX/CSV institucional: compatible con variaciones de Excel y encabezados.
// No modifica registros hasta confirmar la importación desde la vista previa.
function readCsv(bytes){
 if(bytes.byteLength>12*1024*1024)fail('Archivo demasiado grande (máximo 12 MB).',413);
 let content=new TextDecoder('utf-8').decode(bytes);
 if(content.includes('\uFFFD'))content=new TextDecoder('windows-1252').decode(bytes);
 content=content.replace(/^\uFEFF/,'');
 const first=content.split(/\r?\n/,2)[0]||'';
 const delimiter=(first.match(/;/g)||[]).length>(first.match(/,/g)||[]).length?';':',';
 const records=[];let row=[],value='',quoted=false;
 for(let i=0;i<content.length;i++){
  const ch=content[i];
  if(ch==='"'){
   if(quoted&&content[i+1]==='"'){value+='"';i++;}
   else quoted=!quoted;
  }else if(!quoted&&ch===delimiter){row.push(value);value='';}
  else if(!quoted&&(ch==='\r'||ch==='\n')){
   row.push(value);value='';
   if(row.some(v=>v.trim()))records.push(row);
   row=[];if(ch==='\r'&&content[i+1]==='\n')i++;
  }else value+=ch;
 }
 if(quoted)fail('El archivo CSV tiene comillas sin cerrar.');
 row.push(value);if(row.some(v=>v.trim()))records.push(row);
 if(records.length>30000)fail('El archivo tiene demasiadas filas.',413);
 return [{name:'Archivo CSV',rows:records.map((cells,i)=>({
  n:i+1,cols:Object.fromEntries(cells.slice(0,181).map((v,k)=>[k,fmt(v)]))
 }))}];
}
function xmlAttributes(s){
 const result={};
 for(const m of s.matchAll(/([A-Za-z_:][\w:.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)){
  result[m[1]]=decodeXml(m[2]===undefined?m[3]:m[2]);
 }
 return result;
}
function readXlsx(bytes){
 if(bytes.byteLength>12*1024*1024)fail('Excel demasiado grande (máximo 12 MB).',413);
 let z;try{z=unzipSync(bytes);}catch{fail('No se pudo leer el XLSX. Abre el archivo en Excel y guárdalo de nuevo como .xlsx.');}
 const keys=Object.keys(z),size=keys.reduce((a,k)=>a+z[k].length,0);
 if(keys.length>3000||size>90*1024*1024)fail('Excel demasiado grande o comprimido de forma sospechosa.',413);
 const read=k=>z[k]?strFromU8(z[k]):'';
 const book=read('xl/workbook.xml'),rels=read('xl/_rels/workbook.xml.rels');
 if(!book)fail('El archivo no contiene un libro Excel XLSX válido.');
 const shared=Array.from(read('xl/sharedStrings.xml').matchAll(/<si\b[^>]*>([\s\S]*?)<\/si>/g),m=>unxml(m[1]));
 const links={};
 for(const m of rels.matchAll(/<Relationship\b([^>]*)\/?>/g)){
  const a=xmlAttributes(m[1]);if(a.Id&&a.Target)links[a.Id]=a.Target;
 }
 const sheets=[];
 for(const [sheetIndex,match] of [...book.matchAll(/<sheet\b([^>]*)\/?>/g)].entries()){
  const a=xmlAttributes(match[1]),name=a.name||'Hoja '+(sheetIndex+1);
  let target=links[a['r:id']||a.id]||'worksheets/sheet'+(sheetIndex+1)+'.xml';
  target=target.replace(/^\//,'');
  const file=target.startsWith('xl/')?target:'xl/'+target;
  if(!/^xl\/worksheets\/[^/]+\.xml$/i.test(file))continue;
  const xml=read(file);if(!xml)continue;
  const rows=[];
  for(const rm of xml.matchAll(/<row\b([^>]*?)>([\s\S]*?)<\/row>/g)){
   const attr=xmlAttributes(rm[1]),number=+(attr.r||rows.length+1);
   if(number>30000)fail('La hoja es demasiado larga.',413);
   const cols={};
   for(const cm of rm[2].matchAll(/<c\b([^>]*?)(?:\/>|>([\s\S]*?)<\/c>)/g)){
    const cattr=xmlAttributes(cm[1]),ref=(cattr.r||'').match(/^([A-Z]+)\d+$/i);
    if(!ref)continue;
    let idx=0;for(const ch of ref[1].toUpperCase())idx=idx*26+ch.charCodeAt(0)-64;
    idx--;if(idx>180)continue;
    const payload=cm[2]||'';
    let v=(payload.match(/<v>([\s\S]*?)<\/v>/)||[])[1]||'';
    if(cattr.t==='s')v=shared[Number(v)]||'';
    else if(cattr.t==='inlineStr')v=unxml(payload);
    cols[idx]=fmt(decodeXml(v));
   }
   rows.push({n:number,cols});
  }
  sheets.push({name,rows});
 }
 if(!sheets.length)fail('No se encontraron hojas compatibles en el XLSX. Prueba guardar una copia como Libro de Excel (.xlsx).');
 return sheets;
}
const headerNorm=s=>normalize(s).replace(/[º°#.:/_-]+/g,' ').replace(/\s+/g,' ').trim();
const pick=(row,opts)=>{
 const entries=Object.entries(row);
 for(const term of opts){
  const hit=entries.find(([k,v])=>headerNorm(v)===headerNorm(term));
  if(hit)return Number(hit[0]);
 }
 for(const term of opts){
  const q=headerNorm(term);
  const hit=entries.find(([k,v])=>headerNorm(v).includes(q));
  if(hit)return Number(hit[0]);
 }
 return -1;
};
function parseExcel(bytes,filename){
 const sheets=filename.toLowerCase().endsWith('.csv')?readCsv(bytes):readXlsx(bytes);
 const bienes=[],ignored=[];
 for(const sh of sheets){
  let hdr=null;
  for(const r of sh.rows.slice(0,80)){
   const ci=pick(r.cols,['numero de inventario','no inventario','n inventario','inventario','numero siafi','siafi','codigo del bien','codigo de inventario']);
   const cd=pick(r.cols,['descripcion del bien','descripcion','nombre del bien','detalle del bien','nombre del objeto','articulo','objeto']);
   if(ci>=0&&cd>=0&&ci!==cd){hdr={row:r.n,col:r.cols,ci,cd};break;}
  }
  if(!hdr){ignored.push(sh.name);continue;}
  const col=opts=>pick(hdr.col,opts);
  const fields={
   marca:col(['marca']),modelo:col(['modelo']),numeroSerie:col(['numero de serie','serie']),
   color:col(['color']),estadoOriginal:col(['estado del bien','estado fisico','estado']),
   numeroFicha:col(['numero de ficha','ficha']),precio:col(['precio','valor adquisicion','valor','costo'])
  };
  const areaCol=col(['area','ubicacion','servicio','departamento','oficina','unidad']);
  const jefeCol=col(['responsable','encargado','custodio','asignado a','persona a cargo']);
  let area='',jefe='';
  for(const r of sh.rows.slice(0,20)){
   for(const [k,v] of Object.entries(r.cols)){
    const n=normalize(v),i=+k;
    if(n.includes('departamento/oficina')||n.includes('institucion:'))area=area||fmt(r.cols[i+2]||r.cols[i+1]);
    if(n.includes('nombre de responsable'))jefe=jefe||fmt(r.cols[i+2]||r.cols[i+1]);
   }
  }
  if(!area)area=sh.name==='Archivo CSV'?'Área por verificar':sh.name;
  let count=0;
  for(const r of sh.rows){
   if(r.n<=hdr.row)continue;
   const val=k=>k>=0?fmt(r.cols[k]):'';
   const desc=val(hdr.cd),number=val(hdr.ci);
   if(!desc||headerNorm(desc)==='descripcion del bien'||headerNorm(desc)==='descripcion')continue;
   if(!number&&!desc)continue;
   const rowArea=val(areaCol)||area;
   const rowJefe=val(jefeCol)||jefe;
   const inventory=number.replace(/\.0+$/,'').trim();
   const valid=/^\d[\dA-Za-z._/-]*$/.test(inventory)&&!/^(0|000)$/.test(inventory);
   const suffix=normalize(rowArea+'-'+sh.name).replace(/[^a-z0-9]/g,'').slice(0,12).toUpperCase();
   const id=valid?inventory:'PEND-'+digits(r.n).padStart(7,'0')+'-'+suffix;
   bienes.push({area:rowArea,responsable:rowJefe,numeroInventario:id,numeroOriginal:number,
    pendienteNumero:!valid,descripcion:desc,
    ...Object.fromEntries(Object.entries(fields).map(([k,v])=>[k,val(v)])),
    estadoBueno:['bueno','buen estado','excelente'].includes(normalize(val(fields.estadoOriginal))),
    hoja:sh.name,fila:r.n});
   count++;
  }
  if(!count)ignored.push(sh.name);
 }
 if(!bienes.length)fail('No se reconocieron bienes. Verifica que haya columnas de Inventario y Descripción, y filas con datos.');
 if(bienes.length>500)fail('Máximo 500 bienes por archivo; divide la hoja en varios archivos.');
 return {bienes,hojasIgnoradas:ignored};
}

async function importExcel(req,db,user,preview){
 role(user,'administrador','inspector');
 let filename=fmt(req.headers.get('X-Filename'));
 try{filename=decodeURIComponent(filename);}catch{}
 if(!/\.(xlsx|csv)$/i.test(filename))fail('Selecciona un .xlsx o .csv. Los archivos .xls deben guardarse como .xlsx.');
 const raw=new Uint8Array(await req.arrayBuffer());const parsed=parseExcel(raw,filename);const current=await listDocs(db,'bienes');const used=new Set(current.map(x=>normalize(x.numeroInventario)));
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
async function responsibleForPublicAsset(db,b,area=null){
 // Primero, consultar la asignación ACTUAL; después, campos históricos de
 // importaciones. No se publican identidad, teléfono, correo ni documentos.
 const areaId=fmt(b.areaId),personaId=fmt(b.personaId);
 const a=area||(areaId?await getDoc(db,'areas',areaId):null);
 const directName=[b.nombreResponsable,b.responsableNombre,b.encargadoNombre,
   b.nombreEncargado,b.personaNombre,b.responsable,b.encargado]
   .find(v=>typeof v==='string'&&fmt(v)&&fmt(v).length<=180&&!/(?:\d{5,}|@)/.test(fmt(v)));
 if(b.personaTipo==='empleado'){
  const emp=personaId?await getDoc(db,'empleados',personaId):null;
  if(emp&&fmt(emp.nombre))return {nombre:fmt(emp.nombre),cargo:'Empleado asignado'};
  if(directName)return {nombre:fmt(directName),cargo:'Responsable registrado en el inventario'};
  return {nombre:'Pendiente de verificar',cargo:'La asignación del empleado requiere actualización'};
 }
 if(b.personaTipo==='jefe'){
  if(fmt(a?.jefeNombre))return {nombre:fmt(a.jefeNombre),cargo:'Jefe del área'};
  if(directName)return {nombre:fmt(directName),cargo:'Jefatura registrada en el inventario'};
  return {nombre:'Pendiente de verificar',cargo:'Falta registrar el jefe del área'};
 }
 // Los bienes antiguos importados pueden guardar el encargado solo en texto.
 if(directName)return {nombre:fmt(directName),cargo:'Responsable registrado en el inventario'};
 // En importaciones Excel oficiales se cargaba el inventario al jefe de área.
 const fromOfficialExcel=[b.revisionOrigen,b.fuenteImportacion,b.origenImportacion].some(v=>String(v||'').toLowerCase().includes('excel'))||
  Boolean(b.fuenteImportacionExcel||b.hojaExcel||b.importadoPorExcel);
 if(fromOfficialExcel&&fmt(a?.jefeNombre))return {nombre:fmt(a.jefeNombre),cargo:'Jefatura del área (importación Excel)'};
 return {nombre:'Sin responsable asignado',cargo:''};
}
function publicFichaHTML(b,responsible,token,areaName){
 // Lista blanca de CAMPOS publicos: datos del objeto y NOMBRE del encargado.
 // No mostrar números de identidad, contacto, costos, documentos ni historial.
 const fields=[
  ['Número de inventario',b.numeroInventario],
  ['Descripción',b.descripcion],
  ['Área / ubicación',areaName],
  ['Marca',b.marca],['Modelo',b.modelo],['Serie',b.numeroSerie],['Color',b.color],
  ['Responsable actual del bien',responsible.nombre],
  ...(responsible.cargo?[['Tipo de asignación',responsible.cargo]]:[]),
  ['Situación del bien',b.descargado?'Descargado · Fuera de servicio':'Activo'],
  ['Estado físico',b.descargado?'Fuera de servicio':b.estadoBueno===true?'Registrado como bueno':'Sin confirmar']
 ];
 const photo=/^\/imagenes\/[a-f0-9]{32}\.(?:png|jpg|webp|gif)$/.test(fmt(b.fotoURL));
 const rows=fields.filter(([,v])=>v!==undefined&&v!==null&&v!=='').map(([k,v])=>'<div class="pair"><dt>'+publicHtmlEscape(k)+'</dt><dd>'+publicHtmlEscape(v)+'</dd></div>').join('');
 return `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex,nofollow,noarchive"><title>Ficha pública - ${publicHtmlEscape(b.numeroInventario)}</title><style>
 :root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#f6f8fb;color:#1d2c3d;font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}header{display:flex;align-items:center;gap:14px;border-bottom:1px solid #d7e2ec;padding:15px 18px;background:#ffffff;color:#17324f;font-size:14px;flex-wrap:wrap}.wrap{max-width:820px;margin:32px auto;padding:0 16px}.card{background:#fff;border:1px solid #dbe4ee;border-radius:20px;overflow:hidden;padding:25px;box-shadow:0 18px 42px rgba(12,45,87,.06)}small{color:#64758b}.eyebrow{color:#0B4DA2;text-transform:uppercase;letter-spacing:.1em;font-weight:800;font-size:12px}h1{font-size:clamp(23px,5vw,34px);line-height:1.15;margin:10px 0 18px;color:#0b2c4e}.photo{display:block;max-height:350px;max-width:100%;object-fit:contain;border-radius:14px;margin:0 auto 20px;background:#f5f8fc;border:1px solid #e3ebf3}.pair{display:grid;grid-template-columns:minmax(135px,1fr) minmax(0,2fr);gap:12px;padding:13px 0;border-top:1px solid #e3ebf3}dt{color:#64758b}dd{margin:0;overflow-wrap:anywhere;font-weight:700;color:#17324f}.note{margin:18px 0 0;color:#64758b;font-size:13px}.mark{color:#0B4DA2;font-weight:900;margin-right:9px}.brandline{display:flex;align-items:center;gap:8px;min-width:0}.hospital{font-size:12px;color:#64758b}.govimg{height:48px;width:auto;max-width:min(50vw,430px);object-fit:contain;display:block}.bnmark{height:44px;width:auto;display:block}@media(max-width:480px){header{padding:12px 14px;gap:10px}.wrap{margin:18px auto}.card{padding:18px}.pair{grid-template-columns:1fr;gap:2px}.govimg{height:34px;max-width:47vw}.bnmark{height:32px}}
 </style></head><body><header><img class="govimg" src="/icons/gobierno-salud-v42.png" alt="Gobierno de Honduras - Secretaría de Salud"><img class="bnmark" src="/icons/bn-logo.png" alt="BN"><div class="brandline"><strong>Bienes Nacionales</strong><span class="hospital">Hospital Leonardo Martínez Valenzuela</span></div></header><main class="wrap"><article class="card"><div class="eyebrow">Consulta de inventario · Solo lectura</div><h1>${publicHtmlEscape(b.descripcion||'Bien inventariado')}</h1>${photo?`<img class="photo" src="/api/public/foto/${token}" alt="Fotografía del bien" loading="lazy">`:''}<dl>${rows}</dl><p class="note">Esta ficha pública muestra el nombre del responsable asignado actualmente. No da acceso a editar el inventario ni muestra identidad, teléfono, correo, valores de adquisición o historial. Los nombres están visibles para cualquier persona que tenga el QR.</p></article></main></body></html>`;
}
async function publicFicha(req,db,token){
 if(req.method!=='GET'&&req.method!=='HEAD')fail('Método no permitido.',405);
 if(!/^[a-f0-9]{32}$/.test(token))fail('Ficha no encontrada.',404);
 const row=await sql(db,`SELECT d.data FROM public_qr p JOIN docs d ON d.collection='bienes' AND d.id=p.asset_id WHERE p.token=? LIMIT 1`,token);
 if(!row)fail('Ficha no encontrada.',404);
 const bien=JSON.parse(row.data);
 const area=fmt(bien.areaId)?await getDoc(db,'areas',fmt(bien.areaId)):null;
 const responsible=await responsibleForPublicAsset(db,bien,area);
 const body=publicFichaHTML(bien,responsible,token,fmt(area?.nombre)||fmt(bien.ubicacionSiafi)||'Área por confirmar');
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
// Compatibilidad: las etiquetas impresas en las primeras versiones llevan
// /index.html#/bien/NUMERO. La parte # no llega al servidor: el index.html
// redirige a esta ruta. Solo se sirve la ficha pública (lista blanca).
// Advertencia institucional: un número SIAFI conocido permite abrir esta ficha.
async function publicLegacyRedirect(req,db,codigo,originUrl){
 if(req.method!=='GET'&&req.method!=='HEAD')fail('Método no permitido.',405);
 let numero;
 try{numero=decodeURIComponent(codigo);}catch{fail('Código de QR inválido.',400);}
 if(!numero||numero.length>100||/[\u0000-\u001f<>]/.test(numero))fail('Código de QR inválido.',400);
 const link=await publicQrLink(db,numero,originUrl);
 return new Response(null,{status:302,headers:{
  'location':link,'cache-control':'no-store','x-robots-tag':'noindex,nofollow',
  'x-content-type-options':'nosniff','referrer-policy':'no-referrer'
 }});
}

async function route(req,env){
 const url=new URL(req.url),path=url.pathname,method=req.method,db=env.DB;
 if(!db)fail('Falta vincular la base D1 con nombre DB en Cloudflare.',503);
 await initialize(db);origin(req);
 if(path==='/api/health')return json({ok:true,db:'d1'});
 // La ficha publica se resuelve ANTES de comprobar una sesion. No expone /api/doc ni /api/list.
 if(path.startsWith('/api/public/ficha/'))return publicFicha(req,db,path.slice('/api/public/ficha/'.length));
 if(path.startsWith('/api/public/foto/'))return publicFichaPhoto(req,db,path.slice('/api/public/foto/'.length));
 if(path.startsWith('/api/public/legado/'))return publicLegacyRedirect(req,db,path.slice('/api/public/legado/'.length),url.origin);
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
