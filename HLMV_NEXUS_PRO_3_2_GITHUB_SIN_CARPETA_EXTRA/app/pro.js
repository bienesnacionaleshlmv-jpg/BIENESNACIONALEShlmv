/* Bienes Nacionales · Funciones añadidas sin sustituir el motor del inventario existente. */
(function(){
  if(!document.documentElement.dataset?.theme)document.documentElement.setAttribute('data-theme','dark');
  document.addEventListener('keydown', e=>{
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase()==='k') {e.preventDefault();openCommandSearch();}
    if(e.key==='Escape'){closeSidebar();}
  });
})();
function toggleSidebar(){document.body.classList.toggle('sidebar-open');}
function closeSidebar(){document.body.classList.remove('sidebar-open');}
function updateSidebarState(){
  closeSidebar();
  const page=(location.hash.slice(2).split('/')[0]||'inventario');
  document.querySelectorAll('.side-link[data-route]').forEach(el=>el.classList.toggle('active',el.dataset.route===page || (page==='bien'&&el.dataset.route==='buscar') || (page==='area'&&el.dataset.route==='areas')));
  updateMobileNav();
}
function openCommandSearch(){
  openModal(`<h3>Buscar en el inventario</h3><p class="tool-note">Busca por número SIAFI, descripción, serie, nombre o identidad del responsable.</p>
    <div class="field"><label>¿Qué estás buscando?</label><input id="commandQuery" type="text" autocomplete="off" placeholder="Ej. Monitor, HLMV-123, nombre o identidad" onkeydown="if(event.key==='Enter')submitCommandSearch()"></div>
    <div class="modal-actions"><button class="btn secondary" onclick="closeModal()">Cancelar</button><button class="btn" onclick="submitCommandSearch()">Buscar bienes</button></div>`);
  document.getElementById('commandQuery')?.focus();
}
function submitCommandSearch(){
  const q=document.getElementById('commandQuery')?.value.trim()||'';
  closeModal();
  window.__proSearchTerm=q;
  const samePage=location.hash==='#/buscar';
  location.hash='#/buscar';
  if(samePage)render();
}
async function createAssetFlow(){
  try{
    const areas=await fetchAreas();
    if(!areas.length){toast('Primero agrega un área del hospital.');openAreaForm();return;}
    openModal(`<h3>Registrar un bien</h3><p class="tool-note">Selecciona el área donde estará registrado el bien.</p><div class="field"><label>Área de ubicación</label><select id="quickArea">${areas.map(a=>`<option value="${esc(a.id)}">${esc(a.nombre)}</option>`).join('')}</select></div><div class="modal-actions"><button class="btn secondary" onclick="closeModal()">Cancelar</button><button class="btn" onclick="openNewAssetInArea()">Continuar →</button></div>`);
  }catch(e){toast(e.message);}
}
async function openNewAssetInArea(){
  const areaId=document.getElementById('quickArea')?.value;
  if(!areaId)return;
  closeModal();
  location.hash='#/area/'+encodeURIComponent(areaId);
  await renderAreaDetail(document.getElementById('app'),areaId);
  openBienForm();
}
let PRO_SEARCH_DATA=null;
async function getProData(){
  const [areas,bienes,employees]=await Promise.all([fetchAreas(),fetchAllBienes(),DB.collection('empleados').get()]);
  const people=employees.docs.map(d=>({id:d.id,...d.data()}));
  return {areas,bienes,people,areaById:Object.fromEntries(areas.map(a=>[a.id,a])),personById:Object.fromEntries(people.map(p=>[p.id,p]))};
}
/* Bienes Nacionales 2.5: clasificación VIRTUAL de objetos a partir de la descripción.
   No cambia la descripción original, el SIAFI, el área, la persona ni el estado.
   Mismo objeto base (escritorio de 1 o 3 gavetas) = una sola familia. */
function proObjectName(description){
  const clean=proNormalize(description).toUpperCase().replace(/[^A-Z0-9 ]/g,' ').replace(/\s+/g,' ').trim();
  if(!clean)return 'SIN CLASIFICAR';
  const rules=[
    [/^AIRES? ACONDICIONADOS?\b/,'AIRE ACONDICIONADO'],
    [/^BOMBAS? DE INFUSION\b/,'BOMBA DE INFUSIÓN'],
    [/^BOMBAS?\b/,'BOMBA'],
    [/^PORTA EXPEDIENTES?\b/,'PORTA EXPEDIENTES'],
    [/^SILLAS? DE RUEDAS\b/,'SILLA DE RUEDAS'],
    [/^CAMILLAS?\b/,'CAMILLA'],
    [/^CAMAS?\b/,'CAMA'],
    [/^ATRIL(?:ES)?\b/,'ATRIL'],
    [/^TECLADOS?\b/,'TECLADO'],
    [/^ESCRITORIOS?\b/,'ESCRITORIO'],
    [/^MONITOR(?:ES)?\b/,'MONITOR'],
    [/^LOCKERS?\b/,'LOCKER'],
    [/^UPS\b/,'UPS'],
    [/^CPU\b/,'CPU'],
    [/^SILLON(?:ES)?\b/,'SILLÓN'],
    [/^SILLAS?\b/,'SILLA'],
    [/^MESAS?\b/,'MESA'],
    [/^ARMARIOS?\b/,'ARMARIO'],
    [/^ESTANTES?\b/,'ESTANTE'],
    [/^PIZARRAS?\b/,'PIZARRA'],
    [/^BANCOS?\b/,'BANCO'],
    [/^LAMPARAS?\b/,'LÁMPARA'],
    [/^IMPRESORAS?\b/,'IMPRESORA'],
    [/^ARCHIVOS?\b/,'ARCHIVO'],
    [/^CARROS?\b/,'CARRO'],
    [/^CARRITOS?\b/,'CARRITO'],
    [/^SOFAS?\b/,'SOFÁ'],
    [/^MUEBLES?\b/,'MUEBLE'],
    [/^DESFRIBILADOR(?:ES)?\b|^DESFIBRILADOR(?:ES)?\b/,'DESFIBRILADOR'],
    [/^BIOMBOS?\b/,'BIOMBO'],
    [/^ULTRASONIDOS?\b/,'ULTRASONIDO'],
    [/^CAMAROTES?\b/,'CAMAROTE'],
    [/^BACINETES?\b/,'BACINETE']
  ];
  for(const [pattern,label] of rules)if(pattern.test(clean))return label;
  // Para nombres nuevos desconocidos se conserva la denominación completa.
  // Así no se unen accidentalmente familias distintas.
  return clean;
}
function proObjectGroups(bienes){
  const groups=new Map();
  for(const bien of bienes){
    const name=proObjectName(bien.descripcion);
    const key=proNormalize(name).toUpperCase();
    if(!groups.has(key))groups.set(key,{key,name,bienes:[],variantes:new Set(),areas:new Set()});
    const group=groups.get(key);
    group.bienes.push(bien);
    group.variantes.add(String(bien.descripcion||'Sin descripción').trim());
    group.areas.add(bien.areaId||'');
  }
  return [...groups.values()].sort((a,b)=>b.bienes.length-a.bienes.length||a.name.localeCompare(b.name,'es'));
}
function proOpenObjectGroup(key){
  window.__proTypeChoice=key;
  window.__proAreaChoice=document.getElementById('proObjectArea')?.value||'';
  if(location.hash==='#/buscar')render();else location.hash='#/buscar';
}
let PRO_OBJECT_DATA=null;
async function renderObjectGroups(app){
  app.innerHTML='<div class="wrap inv-wrap"><div class="pro-empty">Agrupando bienes por tipo de objeto…</div></div>';
  const d=PRO_OBJECT_DATA=await getProData();
  const groups=proObjectGroups(d.bienes);
  const largest=groups[0];
  app.innerHTML=`<div class="wrap inv-wrap pro-search-page">
    <div class="pro-pagehead"><div><div class="pro-kicker">CLASIFICACIÓN DE INVENTARIO</div><h1>Bienes por tipo de objeto</h1><p class="pro-subtitle">Agrupa automáticamente atriles, teclados, escritorios y demás objetos. Conserva cada ficha SIAFI por separado.</p></div><div class="pro-pageactions"><button class="btn secondary" onclick="location.hash='#/buscar'">⌕ Buscador general</button><button class="btn" onclick="location.hash='#/importar'">⇧ Agregar por Excel</button><button class="btn secondary" onclick="location.hash='#/importar-pdf'">▣ Agregar por PDF</button></div></div>
    <div class="pro-stat-grid pro-type-stats"><div class="pro-stat"><div class="pro-stat-top">Tipos de objetos</div><div class="pro-stat-value">${groups.length}</div><div class="pro-stat-note">Familias encontradas</div></div><div class="pro-stat"><div class="pro-stat-top">Bienes clasificados</div><div class="pro-stat-value">${d.bienes.length}</div><div class="pro-stat-note">Sin modificar sus fichas</div></div><div class="pro-stat"><div class="pro-stat-top">Tipo más frecuente</div><div class="pro-stat-value pro-type-feature">${esc(largest?.name||'—')}</div><div class="pro-stat-note">${largest?.bienes.length||0} unidades</div></div></div>
    <section class="pro-panel pro-filter-panel"><div class="pro-filter-heading"><div><span class="pro-filter-eyebrow">AGRUPACIÓN AUTOMÁTICA</span><h2>Buscar por nombre del objeto</h2><p>Selecciona una familia para ver todos sus bienes, sus áreas y responsables.</p></div><button class="btn secondary small" onclick="proResetObjects()">↻ Limpiar</button></div>
      <div class="pro-type-filter-grid"><div class="pro-main-search"><span class="pro-search-symbol">⌕</span><input id="proObjectQuery" type="search" placeholder="Ej.: atril, teclado, escritorio…" oninput="proFilterObjects()" aria-label="Buscar tipos de bienes"></div><div class="field"><label for="proObjectArea">Área</label><select id="proObjectArea" onchange="proFilterObjects()"><option value="">Todas las áreas</option>${[...d.areas].sort((a,b)=>a.nombre.localeCompare(b.nombre,'es')).map(a=>`<option value="${esc(a.id)}">${esc(a.nombre)}</option>`).join('')}</select></div><div class="field"><label for="proObjectSort">Ordenar</label><select id="proObjectSort" onchange="proFilterObjects()"><option value="count">Mayor cantidad primero</option><option value="name">Nombre A–Z</option></select></div></div>
      <p class="pro-muted">Nota: variantes como “ESCRITORIO DE 1 GAVETA” y “ESCRITORIO DE 3 GAVETAS” se cuentan como <b>ESCRITORIO</b>. La descripción original se mantiene en cada ficha.</p></section>
    <div class="result-line"><strong id="proObjectCount">${groups.length} tipos</strong><span>Abre una tarjeta para ver el detalle en el buscador</span></div>
    <div id="proObjectGrid" class="pro-object-grid"></div>
  </div>`;
  proFilterObjects();
}
function proResetObjects(){
  const q=document.getElementById('proObjectQuery');if(q)q.value='';
  for(const id of ['proObjectArea','proObjectSort']){const el=document.getElementById(id);if(el)el.selectedIndex=0;}
  proFilterObjects();
}
function proFilterObjects(){
  if(!PRO_OBJECT_DATA)return;
  const d=PRO_OBJECT_DATA;
  const q=proNormalize(document.getElementById('proObjectQuery')?.value||'');
  const area=document.getElementById('proObjectArea')?.value||'';
  const sort=document.getElementById('proObjectSort')?.value||'count';
  const groups=proObjectGroups(d.bienes).map(g=>({...g,visibles:area?g.bienes.filter(b=>b.areaId===area):g.bienes})).filter(g=>g.visibles.length&&(!q||proNormalize(g.name).includes(q)||[...g.variantes].some(v=>proNormalize(v).includes(q))));
  groups.sort(sort==='name'?(a,b)=>a.name.localeCompare(b.name,'es'):(a,b)=>b.visibles.length-a.visibles.length||a.name.localeCompare(b.name,'es'));
  const count=document.getElementById('proObjectCount');if(count)count.textContent=`${groups.length} tipos · ${groups.reduce((n,g)=>n+g.visibles.length,0)} bienes`;
  const el=document.getElementById('proObjectGrid');if(!el)return;
  el.innerHTML=groups.length?groups.map(g=>{
    const subtypes=[...g.variantes].filter(Boolean).sort((a,b)=>a.localeCompare(b,'es'));
    const places=new Set(g.visibles.map(b=>b.areaId).filter(Boolean));
    return `<button type="button" class="pro-object-card" onclick="proOpenObjectGroup('${esc(g.key)}')" aria-label="Ver ${g.visibles.length} bienes tipo ${esc(g.name)}"><span class="pro-object-overline">TIPO DE OBJETO</span><span class="pro-object-title">${esc(g.name)}</span><span class="pro-object-number">${g.visibles.length}<small> bienes</small></span><span class="pro-object-meta">${places.size} ${places.size===1?'área':'áreas'} · ${subtypes.length} ${subtypes.length===1?'descripción':'descripciones'}</span><span class="pro-object-samples">${esc(subtypes.slice(0,2).join(' · '))}</span><span class="pro-object-arrow">Ver inventario ↗</span></button>`;
  }).join(''):'<div class="pro-empty">No hay tipos de bienes con esos filtros.</div>';
}

/* Buscador avanzado Bienes Nacionales: filtros combinables, periodo rápido y responsable. */
let PRO_QUICK_PERIOD='all';
let PRO_SELECTED=new Set();
let PRO_VISIBLE=[];
async function renderAdvancedSearch(app){
  app.innerHTML='<div class="wrap inv-wrap"><div class="pro-empty">Cargando información del inventario…</div></div>';
  const d=PRO_SEARCH_DATA=await getProData();
  const term=window.__proSearchTerm||'';
  const typeChoice=window.__proTypeChoice||'';
  const areaChoice=window.__proAreaChoice||'';
  window.__proSearchTerm='';window.__proTypeChoice='';window.__proAreaChoice='';
  PRO_QUICK_PERIOD='all';PRO_SELECTED.clear();PRO_VISIBLE=[];
  const options=[];
  const seen=new Set();
  d.people.forEach(p=>{
    if(p.nombre?.trim()&&!seen.has('n:'+p.nombre.trim())){options.push(`<option value="${esc(p.nombre.trim())}" label="${esc(p.identidad||'Empleado')}"></option>`);seen.add('n:'+p.nombre.trim());}
    if(p.identidad?.trim()&&!seen.has('i:'+p.identidad.trim())){options.push(`<option value="${esc(p.identidad.trim())}" label="${esc(p.nombre||'Empleado')}"></option>`);seen.add('i:'+p.identidad.trim());}
  });
  d.areas.forEach(a=>{
    if(a.jefeNombre?.trim()&&!seen.has('n:'+a.jefeNombre.trim())){options.push(`<option value="${esc(a.jefeNombre.trim())}" label="Jefatura: ${esc(a.nombre)}"></option>`);seen.add('n:'+a.jefeNombre.trim());}
    if(a.jefeIdentidad?.trim()&&!seen.has('i:'+a.jefeIdentidad.trim())){options.push(`<option value="${esc(a.jefeIdentidad.trim())}" label="Jefatura: ${esc(a.nombre)}"></option>`);seen.add('i:'+a.jefeIdentidad.trim());}
  });
  app.innerHTML=`<div class="wrap inv-wrap pro-search-page">
    <div class="pro-pagehead"><div><div class="pro-kicker">EXPLORADOR DE INVENTARIO</div><h1>Buscador de bienes</h1><p class="pro-subtitle">Busca por tipo de objeto, fecha, lugar, registros recientes y persona a cargo. Combina los filtros.</p></div><div class="pro-pageactions"><button class="btn secondary" onclick="location.hash='#/objetos'">▦ Ver tipos de bienes</button><button class="btn secondary" onclick="exportGeneralExcel()">↓ Inventario Excel</button><button class="btn" onclick="createAssetFlow()">＋ Registrar bien</button></div></div>
    <section class="pro-panel pro-filter-panel" aria-label="Buscador de inventario">
      <div class="pro-filter-heading"><div><span class="pro-filter-eyebrow">BÚSQUEDA INTELIGENTE</span><h2>Encuentra lo que necesitas</h2><p>Los resultados se actualizan automáticamente al escribir o seleccionar un filtro.</p></div><button type="button" class="btn secondary small" onclick="resetProFilters()">↻ Limpiar todo</button></div>
      <div class="pro-main-search"><span class="pro-search-symbol" aria-hidden="true">⌕</span><label class="pro-sr-only" for="proQuery">Buscar por número de inventario, descripción o serie</label><input id="proQuery" type="search" autocomplete="off" value="${esc(term)}" placeholder="Número SIAFI, descripción, serie, color…" oninput="filterProAssets()"></div>
      <div class="filter-grid pro-primary-filters">
        <div class="field"><label for="proArea">Lugar / área de ubicación</label><select id="proArea" onchange="filterProAssets()"><option value="">Todas las áreas</option>${[...d.areas].sort((a,b)=>a.nombre.localeCompare(b.nombre,'es')).map(a=>`<option value="${esc(a.id)}" ${a.id===areaChoice?'selected':''}>${esc(a.nombre)}</option>`).join('')}</select></div>
        <div class="field"><label for="proPerson">Persona a cargo</label><input id="proPerson" type="search" list="proPersonOptions" autocomplete="off" placeholder="Nombre o identidad del responsable" oninput="filterProAssets()"><datalist id="proPersonOptions">${options.join('')}</datalist></div>
        <div class="field"><label for="proDateField">Fecha que deseas consultar</label><select id="proDateField" onchange="filterProAssets()"><option value="registro">Fecha de registro</option><option value="adquisicion">Fecha de adquisición</option></select></div>
        <div class="field"><label for="proOrder">Ordenar resultados</label><select id="proOrder" onchange="filterProAssets()"><option value="recent">Más recientes primero</option><option value="older">Más antiguos primero</option><option value="name">Descripción A–Z</option><option value="price">Mayor valor primero</option></select></div>
      </div>
      <div class="pro-recent-filter"><div class="pro-filter-caption">REGISTROS RECIENTES</div><div class="pro-period-buttons" role="group" aria-label="Periodo rápido"><button type="button" class="pro-period active" data-days="all" aria-pressed="true" onclick="setProQuickPeriod('all')">Todos</button><button type="button" class="pro-period" data-days="today" aria-pressed="false" onclick="setProQuickPeriod('today')">Hoy</button><button type="button" class="pro-period" data-days="7" aria-pressed="false" onclick="setProQuickPeriod('7')">Últimos 7 días</button><button type="button" class="pro-period" data-days="30" aria-pressed="false" onclick="setProQuickPeriod('30')">Últimos 30 días</button><button type="button" class="pro-period" data-days="90" aria-pressed="false" onclick="setProQuickPeriod('90')">Últimos 90 días</button></div></div>
      <div class="filter-grid pro-secondary-filters">
        <div class="field pro-type-select-field"><label for="proType">Tipo de objeto</label><select id="proType" onchange="filterProAssets()"><option value="">Todos los tipos</option>${proObjectGroups(d.bienes).sort((a,b)=>a.name.localeCompare(b.name,'es')).map(g=>`<option value="${esc(g.key)}" ${typeChoice===g.key?'selected':''}>${esc(g.name)} (${g.bienes.length})</option>`).join('')}</select></div>
        <div class="field"><label for="proFrom">Desde la fecha</label><input id="proFrom" type="date" onchange="proManualDateFilter()"></div>
        <div class="field"><label for="proTo">Hasta la fecha</label><input id="proTo" type="date" onchange="proManualDateFilter()"></div>
        <div class="field"><label for="proState">Estado del bien</label><select id="proState" onchange="filterProAssets()"><option value="">Cualquier estado</option><option value="active">Activos</option><option value="discharged">Descargados</option><option value="good">Funciona</option><option value="bad">Estado físico sin confirmar</option></select></div>
        <div class="field"><label for="proMin">Valor mínimo (L)</label><input id="proMin" type="number" min="0" step="0.01" placeholder="Desde" oninput="filterProAssets()"></div>
        <div class="field"><label for="proMax">Valor máximo (L)</label><input id="proMax" type="number" min="0" step="0.01" placeholder="Hasta" oninput="filterProAssets()"></div>
      </div>
    </section>
    <div class="result-line pro-result-bar"><div><strong id="proCount" aria-live="polite">${d.bienes.length} bienes registrados</strong><span id="proFilterDetail"> · Mostrando todos los registros</span></div><button type="button" class="btn secondary small" onclick="resetProFilters()">Quitar filtros</button></div>
    <section class="pro-panel bn-selection-bar" aria-label="Acciones sobre bienes seleccionados">
      <div><h3>Gestión de bienes</h3><p class="pro-muted" id="proReviewCount">Ningún bien seleccionado</p></div>
      <div class="row-actions"><button class="btn secondary small" type="button" onclick="proSelectAll(true)">Seleccionar resultados</button><button class="btn secondary small" type="button" onclick="proSelectAll(false)">Quitar selección</button>${IS_ADMIN?`<button class="btn danger-solid small" type="button" onclick="proDeleteSelected()">Eliminar seleccionados</button>`:''}<button class="btn secondary small" type="button" onclick="exportGeneralExcel()">Exportar Excel</button><button class="btn secondary small" type="button" onclick="exportGeneralWord()">Exportar Word</button></div>
    </section>
    <div class="table-wrap pro-results-wrap"><table class="result-table"><thead><tr><th class="chk-col"><input type="checkbox" id="proAllCheck" onchange="proSelectAll(this.checked)" aria-label="Seleccionar todos los resultados filtrados"></th><th>Bien</th><th>N.º SIAFI</th><th>Lugar / área</th><th>Persona a cargo</th><th id="proDateHeader">Fecha de registro</th><th>Valor</th><th>Estado físico</th><th>Situación</th><th>Acciones</th></tr></thead><tbody id="proResults"></tbody></table></div>
  </div>`;
  filterProAssets();
}
function proNormalize(s){return String(s||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLocaleLowerCase('es');}
function proResponsible(b,d){
  if(b.personaTipo==='empleado')return d.personById[b.personaId]?.nombre||'No localizado';
  if(b.personaTipo==='jefe')return d.areaById[b.areaId]?.jefeNombre||'Jefatura';
  return 'Sin asignar';
}
function proLocalDate(d){
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
}
function proAssetDate(b,field){
  if(field==='adquisicion')return String(b.fechaAdquisicion||'').slice(0,10);
  const raw=String(b.creadoEn||'');
  if(!raw)return '';
  // Los registros guardan la fecha ISO en UTC: mostrar el día local del usuario.
  if(/(?:Z|[+-]\d{2}:\d{2})$/i.test(raw)){
    const date=new Date(raw);
    if(!Number.isNaN(date.getTime()))return proLocalDate(date);
  }
  return raw.slice(0,10);
}
function setProQuickPeriod(period){
  PRO_QUICK_PERIOD=String(period);
  ['proFrom','proTo'].forEach(id=>{const e=document.getElementById(id);if(e)e.value='';});
  filterProAssets();
}
function proManualDateFilter(){
  PRO_QUICK_PERIOD='all';
  filterProAssets();
}
function filterProAssets(){
  const d=PRO_SEARCH_DATA;
  if(!d||!document.getElementById('proResults'))return;
  const val=id=>document.getElementById(id)?.value||'';
  const query=proNormalize(val('proQuery').trim());
  const personTerm=proNormalize(val('proPerson').trim());
  const area=val('proArea'),objectType=val('proType'),state=val('proState'),order=val('proOrder')||'recent';
  const min=val('proMin'),max=val('proMax'),from=val('proFrom'),to=val('proTo');
  const dateField=val('proDateField')||'registro';
  const today=new Date();
  let periodStart='';
  if(PRO_QUICK_PERIOD==='today')periodStart=proLocalDate(today);
  else if(['7','30','90'].includes(PRO_QUICK_PERIOD)){
    const since=new Date(today.getFullYear(),today.getMonth(),today.getDate());
    since.setDate(since.getDate()-(Number(PRO_QUICK_PERIOD)-1));
    periodStart=proLocalDate(since);
  }
  const periodEnd=PRO_QUICK_PERIOD!=='all'?proLocalDate(today):'';
  const out=d.bienes.filter(b=>{
    const responsible=proResponsible(b,d);
    const person=d.personById[b.personaId];
    const areaInfo=d.areaById[b.areaId];
    const identity=b.personaTipo==='jefe'?areaInfo?.jefeIdentidad:person?.identidad;
    const haystack=[b.numeroInventario,b.numeroInventarioOriginal,b.numeroFicha,b.descripcion,b.marca,b.modelo,b.numeroSerie,b.color,b.ubicacionSiafi,b.sectorOperativo,b.fuenteImportacionPDF,areaInfo?.nombre,responsible,identity].join(' ');
    if(query&&!proNormalize(haystack).includes(query)){
      const normalizedGroup=proNormalize(proObjectName(b.descripcion));
      if(query.includes(' ')||proNormalize(proObjectName(query))!==normalizedGroup)return false;
    }
    if(area&&area!==b.areaId)return false;
    if(objectType&&proNormalize(proObjectName(b.descripcion)).toUpperCase()!==objectType)return false;
    if(personTerm&&!proNormalize([responsible,identity].join(' ')).includes(personTerm))return false;
    if(state==='active'&&b.descargado)return false;
    if(state==='discharged'&&!b.descargado)return false;
    if((state==='good'||state==='bad')&&Boolean(b.estadoBueno)!==(state==='good'))return false;
    const priceRaw=b.precio;
    const price=Number(priceRaw);
    if(min!==''&&(priceRaw==null||priceRaw===''||!Number.isFinite(price)||price<Number(min)))return false;
    if(max!==''&&(priceRaw==null||priceRaw===''||!Number.isFinite(price)||price>Number(max)))return false;
    const date=proAssetDate(b,dateField);
    if(from&&(!date||date<from))return false;
    if(to&&(!date||date>to))return false;
    if(periodStart&&(!date||date<periodStart||date>periodEnd))return false;
    return true;
  });
  if(order==='name')out.sort((a,b)=>String(a.descripcion||'').localeCompare(String(b.descripcion||''),'es'));
  else if(order==='price')out.sort((a,b)=>Number(b.precio||0)-Number(a.precio||0));
  else if(order==='older')out.sort((a,b)=>proAssetDate(a,dateField).localeCompare(proAssetDate(b,dateField))||String(a.creadoEn||'').localeCompare(String(b.creadoEn||'')));
  else out.sort((a,b)=>proAssetDate(b,dateField).localeCompare(proAssetDate(a,dateField))||String(b.creadoEn||'').localeCompare(String(a.creadoEn||'')));
  const label=dateField==='adquisicion'?'Fecha de adquisición':'Fecha de registro';
  const dateHeader=document.getElementById('proDateHeader');if(dateHeader)dateHeader.textContent=label;
  const count=document.getElementById('proCount');if(count)count.textContent=`${out.length.toLocaleString('es-HN')} de ${d.bienes.length.toLocaleString('es-HN')} bienes`;
  const detail=document.getElementById('proFilterDetail');
  const hasFilters=Boolean(query||personTerm||area||objectType||state||min!==''||max!==''||from||to||periodStart);
  if(detail)detail.textContent=hasFilters?' · Filtrado en tiempo real':' · Mostrando todos los registros';
  document.querySelectorAll('.pro-period[data-days]').forEach(btn=>{
    const active=btn.dataset.days===PRO_QUICK_PERIOD;
    btn.classList.toggle('active',active);
    btn.setAttribute('aria-pressed',String(active));
  });
  PRO_VISIBLE=out;
  const allowed=new Set(out.map(b=>b.id));
  PRO_SELECTED=new Set([...PRO_SELECTED].filter(id=>allowed.has(id)));
  const tbody=document.getElementById('proResults');
  tbody.innerHTML=out.length?out.map(b=>`<tr>
    <td class="chk-col"><input type="checkbox" value="${esc(b.id)}" ${PRO_SELECTED.has(b.id)?'checked':''} onchange="proSelectOne(this.value,this.checked)" aria-label="Seleccionar ${esc(b.numeroInventario)}"></td>
    <td><b>${esc(b.descripcion)}</b><div class="muted">Tipo: ${esc(proObjectName(b.descripcion))} · ${esc(b.numeroSerie||'Sin serie')}${b.ubicacionSiafi?' · SIAFI: '+esc(b.ubicacionSiafi):''}</div></td>
    <td><a href="#/bien/${encodeURIComponent(b.numeroInventario)}">${esc(b.numeroInventario)}</a>${b.siafiDuplicado?`<div class="muted">SIAFI repetido: ${esc(b.numeroInventarioOriginal||'')}</div>`:b.sinSIAFI?`<div class="muted">Número SIAFI pendiente</div>`:''}</td>
    <td>${esc(d.areaById[b.areaId]?.nombre||'—')}</td>
    <td>${esc(proResponsible(b,d))}</td>
    <td class="pro-date-cell">${esc(proAssetDate(b,dateField)||'—')}</td>
    <td>${b.precio!==undefined&&b.precio!==null&&b.precio!=='' ? 'L '+Number(b.precio).toLocaleString('es-HN',{minimumFractionDigits:2,maximumFractionDigits:2}) : '—'}</td>
    <td>${b.descargado?'Fuera de servicio':b.estadoBueno?'Funciona':'Sin confirmar'}</td>
    <td><span class="bn-status ${b.descargado?'out':'active'}">${b.descargado?'Descargado':'Activo'}</span></td>
    <td><div class="row-actions"><a class="btn secondary small" href="#/bien/${encodeURIComponent(b.numeroInventario)}">Ver ficha ↗</a>${IS_ADMIN?`<button class="btn secondary small" type="button" onclick="bnOpenDescargo('${b.id}')">${b.descargado?'Reactivar':'Descargo'}</button><button class="btn danger small" type="button" onclick="confirmDeleteBien('${b.id}','${b.areaId||''}')">Eliminar</button>`:''}</div></td>
    </tr>`).join(''):'<tr><td colspan="10"><div class="pro-empty"><strong>No hay bienes que coincidan.</strong><div style="margin-top:8px">Prueba otra fecha, lugar o persona a cargo, o selecciona «Quitar filtros».</div></div></td></tr>';
  window.__proFilteredBienes=out;
  proUpdateSelectionCount();
}

function proUpdateSelectionCount(){
  const t=document.getElementById('proReviewCount');
  if(t)t.textContent=PRO_SELECTED.size?`${PRO_SELECTED.size} seleccionado(s) de ${PRO_VISIBLE.length} en el filtro actual`:'Ningún bien seleccionado';
  const c=document.getElementById('proAllCheck');
  if(c){c.checked=PRO_VISIBLE.length>0&&PRO_SELECTED.size===PRO_VISIBLE.length;c.indeterminate=PRO_SELECTED.size>0&&PRO_SELECTED.size<PRO_VISIBLE.length;}
}
function proSelectOne(id,checked){if(checked)PRO_SELECTED.add(id);else PRO_SELECTED.delete(id);proUpdateSelectionCount();}
function proSelectAll(checked){PRO_SELECTED=checked?new Set(PRO_VISIBLE.map(x=>x.id)):new Set();document.querySelectorAll('#proResults input[type=checkbox]').forEach(c=>{c.checked=checked;});proUpdateSelectionCount();}
async function proDeleteSelected(){
 if(!IS_ADMIN){toast('Solo el administrador puede eliminar bienes.');return;}
 const ids=[...PRO_SELECTED];
 if(!ids.length){toast('Selecciona los bienes que deseas eliminar.');return;}
 openConfirm(`¿Eliminar definitivamente ${ids.length} bienes seleccionados? Esta operación no se puede deshacer. Los QR de estos bienes dejarán de funcionar.`,async()=>{
  const btn=document.getElementById('confirmActionBtn');
  try{
   let removed=0;
   for(let i=0;i<ids.length;i+=25){
    const result=await requestJSON('/api/bienes/eliminar',payload({ids:ids.slice(i,i+25)}));
    removed+=result.eliminados;
   }
   closeModal();
   PRO_SELECTED.clear();
   toast(`${removed} bienes eliminados correctamente.`);
   await renderAdvancedSearch(document.getElementById('app'));
  }catch(e){
   if(btn){btn.disabled=false;btn.textContent='Reintentar';}
   toast('No se completó la eliminación: '+e.message+'. Actualiza el buscador antes de reintentar.');
  }
 },'Eliminar definitivamente');
}
function resetProFilters(){
  ['proQuery','proPerson','proMin','proMax','proFrom','proTo'].forEach(id=>{const e=document.getElementById(id);if(e)e.value='';});
  ['proArea','proType','proState','proOrder','proDateField'].forEach(id=>{const e=document.getElementById(id);if(e)e.selectedIndex=0;});
  PRO_QUICK_PERIOD='all';
  filterProAssets();
}
async function renderResponsables(app){
  app.innerHTML='<div class="wrap inv-wrap"><div class="pro-empty">Cargando responsables…</div></div>';
  const d=await getProData();
  // Una persona que dirige varias áreas aparece una sola vez.
  const people=[];const grouped=new Map();
  for(const area of d.areas){
    if(!String(area.jefeNombre||'').trim())continue;
    const key=area.jefePersonaId||('jefe:'+proNormalize(area.jefeNombre).replace(/[^a-z0-9]/g,''));
    let g=grouped.get(key);
    if(!g){g={id:key,nombre:area.jefeNombre,identidad:area.jefeIdentidad||'',jefe:true,areas:[],bienes:[]};grouped.set(key,g);people.push(g);}
    g.areas.push(area.nombre);
    g.bienes.push(...d.bienes.filter(b=>b.areaId===area.id&&b.personaTipo==='jefe'));
  }
  for(const emp of d.people){
    people.push({id:emp.id,nombre:emp.nombre,identidad:emp.identidad||'',jefe:false,areas:[d.areaById[emp.areaId]?.nombre||'—'],bienes:d.bienes.filter(b=>b.personaTipo==='empleado'&&b.personaId===emp.id)});
  }
  people.sort((a,b)=>a.nombre.localeCompare(b.nombre,'es'));
  app.innerHTML=`<div class="wrap inv-wrap">
    <div class="pro-pagehead"><div><div class="pro-kicker">PERSONAL Y RESPONSABILIDAD</div><h1>Responsables de bienes</h1><p class="pro-subtitle">Los jefes de varias áreas se muestran una sola vez. Los Excel institucionales se asocian a las jefaturas.</p></div><div class="pro-pageactions"><button class="btn" onclick="location.hash='#/areas'">Administrar áreas ↗</button></div></div>
    <div class="pro-stat-grid" style="grid-template-columns:repeat(3,minmax(0,1fr))"><div class="pro-stat"><div class="pro-stat-top">Personas únicas</div><div class="pro-stat-value">${people.length}</div></div><div class="pro-stat"><div class="pro-stat-top">Jefaturas</div><div class="pro-stat-value">${grouped.size}</div></div><div class="pro-stat"><div class="pro-stat-top">Bienes vinculados</div><div class="pro-stat-value">${people.reduce((s,p)=>s+p.bienes.length,0)}</div></div></div>
    <div class="pro-panel"><div class="field"><label>Buscar por nombre o identidad</label><input id="peopleSearch" type="text" placeholder="Nombre o número de identidad" oninput="filterProPeople()"></div></div>
    <div class="result-line" id="peopleCount">${people.length} personas</div><div class="table-wrap"><table><thead><tr><th>Persona</th><th>Función</th><th>Identidad</th><th>Área(s)</th><th>Bienes</th><th></th></tr></thead><tbody id="peopleResults"></tbody></table></div>
  </div>`;
  window.__proPeople={list:people};filterProPeople();
}
function filterProPeople(){
  const dataset=window.__proPeople;const body=document.getElementById('peopleResults');if(!body||!dataset)return;
  const q=(document.getElementById('peopleSearch')?.value||'').trim();
  const filtered=dataset.list.filter(p=>proNormalize(p.nombre+' '+p.identidad+' '+p.areas.join(' ')).includes(proNormalize(q)));
  document.getElementById('peopleCount').textContent=`${filtered.length} de ${dataset.list.length} personas`;
  body.innerHTML=filtered.length?filtered.map(p=>`<tr><td><b>${esc(p.nombre)}</b></td><td>${p.jefe?'Jefe de área':'Empleado'}</td><td>${esc(p.identidad||'—')}</td><td>${p.areas.map(esc).join(', ')}</td><td><span class="asset-badge">${p.bienes.length} bienes</span></td><td><button class="btn secondary small" onclick="showAssignedGoods('${esc(p.id)}')">Ver bienes</button></td></tr>`).join(''):'<tr><td colspan="6"><div class="pro-empty">No se encontraron responsables.</div></td></tr>';
}
function showAssignedGoods(id){
  const p=window.__proPeople?.list?.find(x=>x.id===id);if(!p)return;
  openModal(`<h3>${esc(p.nombre)}</h3><p class="tool-note">${p.jefe?'Jefatura':'Empleado'} · ${esc(p.areas.join(', '))}</p><p><b>${p.bienes.length}</b> bienes asignados</p><div class="history-box">${p.bienes.length?p.bienes.map(b=>`<div><a href="#/bien/${encodeURIComponent(b.numeroInventario)}" onclick="closeModal()">${esc(b.numeroInventario)}</a> · ${esc(b.descripcion)}</div>`).join(''):'No tiene bienes asignados.'}</div><div class="modal-actions"><button class="btn secondary" onclick="closeModal()">Cerrar</button></div>`);
}
async function renderReportes(app){
  app.innerHTML='<div class="wrap inv-wrap"><div class="pro-empty">Preparando reportes…</div></div>';
  const d=await getProData();
  const total=d.bienes.length,good=d.bienes.filter(x=>!x.descargado).length;
  const amount=d.bienes.reduce((s,x)=>s+(Number(x.precio)||0),0);
  const groups=d.areas.map(a=>({...a,count:d.bienes.filter(b=>b.areaId===a.id).length})).sort((a,b)=>b.count-a.count).slice(0,8);
  const max=Math.max(1,...groups.map(g=>g.count));
  let audit=[];
  try{const a=await requestJSON('/api/audit');audit=a.events.slice(0,7);}catch(e){console.warn(e);}
  app.innerHTML=`<div class="wrap inv-wrap"><div class="pro-pagehead"><div><div class="pro-kicker">DATOS Y DOCUMENTOS</div><h1>Reportes y análisis</h1><p class="pro-subtitle">Resumen del inventario, descarga documental y movimientos recientes.</p></div><div class="pro-pageactions"><button class="btn secondary" onclick="exportGeneralExcel()">↓ Excel</button><button class="btn" onclick="exportGeneralWord()">↓ Word</button></div></div>
    <div class="pro-stat-grid"><div class="pro-stat"><div class="pro-stat-top">Bienes <span class="pro-stat-icon">▣</span></div><div class="pro-stat-value">${total}</div></div><div class="pro-stat"><div class="pro-stat-top">Activos <span class="pro-stat-icon">✓</span></div><div class="pro-stat-value">${good}</div></div><div class="pro-stat"><div class="pro-stat-top">Descargados <span class="pro-stat-icon">↘</span></div><div class="pro-stat-value">${d.bienes.filter(x=>x.descargado).length}</div></div><div class="pro-stat"><div class="pro-stat-top">Valor registrado <span class="pro-stat-icon">L</span></div><div class="pro-stat-value" style="font-size:23px">L ${amount.toLocaleString('es-HN',{maximumFractionDigits:0})}</div></div></div>
    <div class="pro-columns"><section class="pro-panel"><div class="pro-panel-header"><div><h3>Distribución por área</h3><p>Bienes registrados por unidad hospitalaria</p></div></div>
    ${groups.length?groups.map(g=>`<div style="margin:17px 0"><div style="display:flex;justify-content:space-between;gap:10px;font-size:12px;margin-bottom:8px"><span>${esc(g.nombre)}</span><b>${g.count}</b></div><div style="height:9px;border-radius:12px;background:#e8eef5;overflow:hidden"><div style="height:100%;width:${Math.round(g.count/max*100)}%;background:linear-gradient(90deg,#087e79,#0c4674);border-radius:12px"></div></div></div>`).join(''):'<div class="pro-empty">No hay áreas para mostrar.</div>'}
    </section><section class="pro-panel"><div class="pro-panel-header"><div><h3>Actividad reciente</h3><p>Últimos movimientos registrados</p></div><button class="btn secondary small" onclick="openHistory()">Historial ↗</button></div>${audit.length?audit.map(a=>`<div class="pro-asset-item"><div class="asset-avatar">↻</div><div class="asset-details"><b>${esc(a.action)} · ${esc(a.collection||'')}</b><small>${esc(a.details||a.document_id||'')} · ${esc(a.date?.slice(0,16).replace('T',' ')||'')}</small></div></div>`).join(''):'<div class="pro-empty">Todavía no hay movimientos.</div>'}</section></div>
    <div class="pro-section-head"><div><h2>Exportaciones y seguridad</h2><p>Los archivos se generan desde tu base de datos</p></div></div><div class="row-actions"><button class="btn secondary" onclick="exportGeneralExcel()">Descargar inventario Excel</button><button class="btn secondary" onclick="exportGeneralWord()">Descargar inventario Word</button><button class="btn secondary" onclick="downloadBackup()">Descargar copia de seguridad</button><button class="btn secondary" onclick="openHistory()">Ver historial</button></div>
  </div>`;
}



/* Bienes Nacionales 2.7: importador PDF de recibos SIAFI, vista previa y validación. */
let NEXUS_PDF_FILE=null;
let NEXUS_PDF_PLAN=null;
async function nexusUploadPDF(endpoint,file){
  const mode=document.getElementById('nexusPDFGrouping')?.value||'bloque';
  const response=await fetch(endpoint,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/pdf','X-Filename':encodeURIComponent(file.name),'X-PDF-Agrupacion':mode},body:file});
  const data=await response.json().catch(()=>({error:'Respuesta del servidor no válida.'}));
  if(!response.ok)throw Error(data.error||`Error HTTP ${response.status}`);
  return data;
}
function renderImportPDF(app){
  NEXUS_PDF_PLAN=null;
  app.innerHTML=`<div class="wrap inv-wrap pro-search-page">
    <div class="pro-pagehead"><div><div class="pro-kicker">DOCUMENTOS SIAFI · IMPORTACIÓN MASIVA</div><h1>▣ Agregar por PDF</h1><p class="pro-subtitle">Importa recibos SIAFI de asignación de bienes con ficha, inventario, descripción, marca, serie, color, costo, oficina original y responsable. Vista previa antes de guardar.</p></div><div class="pro-pageactions"><button class="btn secondary" onclick="downloadBackup()">↓ Respaldo</button><button class="btn secondary" onclick="location.hash='#/buscar'">Explorar bienes →</button></div></div>
    <div class="pro-columns" style="align-items:start">
      <section class="pro-panel">
        <div class="pro-panel-header"><div><h3>Seleccionar recibo PDF</h3><p>Formato SIAFI R_BNU_RECIBO_BIENES · texto seleccionable</p></div></div>
        <label for="nexusPDFFile" class="nexus-upload-zone"><span style="font-size:36px;color:#9bf00b">▣</span><strong>Elegir archivo PDF de Bienes Nacionales</strong><small>Hasta 30 MB · soporta documentos de varias páginas.</small></label>
        <input id="nexusPDFFile" type="file" accept=".pdf,application/pdf" style="width:100%;margin-top:12px" onchange="nexusPDFSelected(this)">
        <div class="field" style="margin-top:18px"><label for="nexusPDFGrouping">¿Cómo clasificar los bienes dentro del programa?</label>
          <select id="nexusPDFGrouping" onchange="NEXUS_PDF_PLAN=null;document.getElementById('nexusPDFResult').innerHTML='';">
            <option value="bloque">Bloque Quirúrgico (conservando oficina original SIAFI)</option>
            <option value="ubicaciones">Cada oficina del PDF como un área distinta</option>
          </select>
          <p class="pro-muted">La agrupación no modifica la ubicación declarada en SIAFI; si la agrupas como Bloque Quirúrgico, la ubicación física queda pendiente de comprobación.</p>
        </div>
        <button class="btn" id="nexusPDFPreviewBtn" disabled onclick="nexusPDFPreview()">Analizar el PDF</button>
      </section>
      <section class="pro-panel"><div class="pro-panel-header"><div><h3>Validaciones automáticas</h3><p>Evita importar datos incorrectos</p></div></div>
        <div class="nexus-import-steps"><div><b>01</b><span>Extrae fichas, SIAFI completo y costos por página</span></div><div><b>02</b><span>Detecta bienes ya existentes y SIAFI repetidos</span></div><div><b>03</b><span>Separa registros de otras instituciones y posibles errores</span></div><div><b>04</b><span>Importa solo tras tu confirmación</span></div></div>
        <div class="nexus-import-alert">El PDF SIAFI identifica a un <b>responsable de bienes</b>, pero no certifica que sea jefe de área. Por seguridad, no se asignan jefaturas automáticamente. Los bienes importados quedarán <b>Revisados documentalmente</b>; esto no certifica su estado físico.</div>
      </section>
    </div>
    <div id="nexusPDFResult" style="margin-top:22px"></div>
    <section class="pro-panel" style="margin-top:18px"><h3>¿Y si un PDF es una imagen escaneada?</h3><p class="pro-muted">Este lector importa recibos SIAFI con texto seleccionable. Para los PDF escaneados se necesitará OCR y verificación manual; no se inventarán datos que no puedan leerse.</p></section>
  </div>`;
}
function nexusPDFSelected(el){
  NEXUS_PDF_FILE=el.files?.[0]||null;NEXUS_PDF_PLAN=null;
  const btn=document.getElementById('nexusPDFPreviewBtn');if(btn)btn.disabled=!NEXUS_PDF_FILE;
  document.getElementById('nexusPDFResult').innerHTML=NEXUS_PDF_FILE?`<p class="pro-muted">Seleccionaste: <b>${esc(NEXUS_PDF_FILE.name)}</b> · ${(NEXUS_PDF_FILE.size/1024).toFixed(0)} KB</p>`:'';
}
async function nexusPDFPreview(){
  const file=NEXUS_PDF_FILE;
  if(!file)return toast('Selecciona un PDF SIAFI.');
  if(!file.name.toLowerCase().endsWith('.pdf')||file.size>30*1024*1024){toast('Selecciona un PDF de máximo 30 MB.');return;}
  const container=document.getElementById('nexusPDFResult');
  container.innerHTML='<section class="pro-panel"><div class="pro-empty">Analizando páginas y conciliando números SIAFI…</div></section>';
  try{
    const plan=NEXUS_PDF_PLAN=await nexusUploadPDF('/api/import/pdf/preview',file);
    const rows=plan.filas.slice(0,45);
    container.innerHTML=`<section class="pro-panel"><div class="pro-panel-header"><div><h3>Vista previa: ${esc(file.name)}</h3><p>${plan.paginas} páginas · ${plan.total} bienes encontrados · ${plan.responsables.length} responsable(s)</p></div></div>
    <div class="pro-stat-grid nexus-import-stats"><div class="pro-stat"><div class="pro-stat-top">En el PDF</div><div class="pro-stat-value">${plan.total}</div></div><div class="pro-stat"><div class="pro-stat-top">Nuevos</div><div class="pro-stat-value">${plan.nuevos}</div></div><div class="pro-stat"><div class="pro-stat-top">Ya registrados</div><div class="pro-stat-value">${plan.yaImportados}</div></div><div class="pro-stat"><div class="pro-stat-top">Pendientes / externos</div><div class="pro-stat-value">${plan.porRevisar+plan.externos+plan.conflictos}</div></div></div>
    <div class="row-actions" style="margin:18px 0"><span class="asset-badge">Valor de nuevos bienes: L ${Number(plan.importeNuevo).toLocaleString('es-HN',{minimumFractionDigits:2})}</span></div>
    ${plan.externos?`<div class="nexus-import-alert">Atención: <b>${plan.externos} registro(s)</b> pertenece(n) a una institución distinta al Hospital Leonardo Martínez. Se apartarán para revisión, no se cargarán como bienes hospitalarios.</div>`:''}
    <div class="pro-muted" style="margin:8px 0">Oficinas del documento: ${Object.entries(plan.ubicaciones).map(([name,count])=>`${esc(name)} (${count})`).join(' · ')}</div>
    <div class="table-wrap pro-results-wrap"><table class="result-table"><thead><tr><th>Estado</th><th>Ficha</th><th>Número SIAFI</th><th>Descripción</th><th>Oficina original</th><th>Valor</th><th>Pág.</th></tr></thead><tbody>${rows.map(r=>`<tr><td><span class="asset-badge ${r.estadoImportacion==='nuevo'?'':'bad'}">${esc(({nuevo:'Nuevo',externo:'Otra entidad',pendiente:'Por verificar',conflicto:'Duplicado',ya_importado:'Ya registrado'})[r.estadoImportacion]||r.estadoImportacion)}</span></td><td>${esc(r.numeroFicha)}</td><td>${esc(r.numeroInventario)}</td><td>${esc(r.descripcion)}</td><td>${esc(r.oficinaOriginal)}</td><td>${r.precio===null?'—':'L '+Number(r.precio).toLocaleString('es-HN',{minimumFractionDigits:2})}</td><td>${r.paginaPDF}</td></tr>`).join('')}</tbody></table></div>
    <p class="pro-muted">Se muestran 45 de ${plan.total} bienes. Los bienes válidos se registrarán con su respaldo documental; el estado físico no se determinará automáticamente y no se marcará como «Bueno» automáticamente.</p>
    <div class="row-actions"><button class="btn" id="nexusPDFCommitBtn" ${plan.nuevos?'':'disabled'} onclick="nexusPDFCommit()">Confirmar e importar ${plan.nuevos} bienes</button><button class="btn secondary" onclick="nexusPDFPreview()">Volver a analizar</button></div>
    </section>`;
  }catch(e){container.innerHTML=`<section class="pro-panel"><div class="nexus-import-alert">${esc(e.message)}</div></section>`;toast(e.message);}
}
async function nexusPDFCommit(){
  if(!NEXUS_PDF_FILE||!NEXUS_PDF_PLAN||!NEXUS_PDF_PLAN.nuevos)return;
  const btn=document.getElementById('nexusPDFCommitBtn');if(btn){btn.disabled=true;btn.textContent='Importando…';}
  try{
    const info=await nexusUploadPDF('/api/import/pdf/commit',NEXUS_PDF_FILE);
    NEXUS_PDF_PLAN=null;
    document.getElementById('nexusPDFResult').innerHTML=`<section class="pro-panel"><h2>✓ Importación completada</h2><p class="pro-subtitle"><b>${info.importados}</b> bienes nuevos incorporados, <b>${info.yaImportados}</b> ya existentes, <b>${info.externos+info.conflictos+info.pendientes}</b> incidencias documentales/externalidades que requieren atención. Los bienes nuevos conservaron su respaldo documental.</p><div class="row-actions"><button class="btn" onclick="location.hash='#/buscar'">Consultar los bienes →</button><button class="btn secondary" onclick="downloadBackup()">Descargar respaldo</button><button class="btn secondary" onclick="renderImportPDF(document.getElementById('app'))">Importar otro PDF</button></div></section>`;
    toast(info.importados+' bienes incorporados sin duplicar SIAFI.');
  }catch(e){toast(e.message);if(btn){btn.disabled=false;btn.textContent='Reintentar importación';}}
}

/* Bienes Nacionales 2.2 — Excel institucional: vista previa e importación segura. */
let NEXUS_EXCEL_FILE=null;
let NEXUS_EXCEL_PLAN=null;
async function nexusUploadExcel(endpoint,file){
  const response=await fetch(endpoint,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','X-Filename':encodeURIComponent(file.name)},body:file});
  const data=await response.json().catch(()=>({error:'Respuesta del servidor no válida.'}));
  if(!response.ok)throw Error(data.error||`Error HTTP ${response.status}`);
  return data;
}
async function renderImportExcel(app){
  NEXUS_EXCEL_PLAN=null;
  app.innerHTML=`<div class="wrap inv-wrap pro-search-page">
    <div class="pro-pagehead"><div><div class="pro-kicker">CARGA MASIVA • BIENES NACIONALES</div><h1>＋ Agregar por Excel</h1><p class="pro-subtitle">Carga prefichas del hospital u hojas Excel compatibles. El sistema reconoce números SIAFI, descripción, marca, modelo, serie, color, área y responsable.</p></div><div class="pro-pageactions"><button class="btn secondary" onclick="downloadBackup()">↓ Respaldo</button><button class="btn secondary" onclick="location.hash='#/buscar'">Explorar inventario →</button></div></div>
    <div class="pro-columns" style="align-items:start">
      <section class="pro-panel"><div class="pro-panel-header"><div><h3>Selecciona el archivo</h3><p>Formato .xlsx · hasta 12 MB</p></div></div>
        <label for="nexusExcelFile" class="nexus-upload-zone"><span style="font-size:36px;color:#9bf00b">⇧</span><strong>Seleccionar Excel desde la computadora</strong><small>Conserva la estructura original, incluso con varias hojas y encabezados institucionales.</small></label>
        <input id="nexusExcelFile" type="file" accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" style="width:100%;margin-top:10px" onchange="nexusExcelSelected(this)">
        <p class="pro-muted" style="margin:14px 0">No se modifica ningún registro durante la vista previa.</p>
        <button id="nexusExcelPreviewButton" class="btn" onclick="nexusExcelPreview()" disabled>Analizar el Excel</button>
      </section>
      <section class="pro-panel"><div class="pro-panel-header"><div><h3>Protección de registros</h3><p>Validación antes de guardar</p></div></div>
        <div class="nexus-import-steps"><div><b>01</b><span>Revisar hojas, columnas y responsables</span></div><div><b>02</b><span>Identificar números SIAFI repetidos</span></div><div><b>03</b><span>Confirmar la carga en una sola operación</span></div></div>
        <p class="pro-muted">Los bienes sin un número válido reciben un código interno <b>PEND-</b>, claramente distinto del número SIAFI real. Nunca se borran ni modifican bienes existentes durante una importación. Los registros importados conservarán su <b>respaldo documental</b>, sin eliminar alertas por SIAFI faltante o duplicado.</p>
      </section>
    </div>
    <div id="nexusExcelResult" style="margin-top:22px"></div>
    <div id="nexusExcelConflicts" style="margin-top:22px"></div>
  </div>`;
  nexusLoadConflicts();
}
function nexusExcelSelected(el){
  NEXUS_EXCEL_FILE=el.files?.[0]||null;NEXUS_EXCEL_PLAN=null;
  const btn=document.getElementById('nexusExcelPreviewButton');if(btn)btn.disabled=!NEXUS_EXCEL_FILE;
  document.getElementById('nexusExcelResult').innerHTML=NEXUS_EXCEL_FILE?`<p class="pro-muted">Archivo seleccionado: <strong>${esc(NEXUS_EXCEL_FILE.name)}</strong> (${(NEXUS_EXCEL_FILE.size/1024).toFixed(0)} KB)</p>`:'';
}
async function nexusExcelPreview(){
  const file=NEXUS_EXCEL_FILE;
  if(!file)return toast('Selecciona un archivo Excel.');
  if(!file.name.toLowerCase().endsWith('.xlsx')||file.size>12*1024*1024){toast('Selecciona un .xlsx de máximo 12 MB.');return;}
  const container=document.getElementById('nexusExcelResult');
  container.innerHTML='<div class="pro-panel"><div class="pro-empty">Analizando hojas y comprobando números de inventario…</div></div>';
  try{
    const plan=NEXUS_EXCEL_PLAN=await nexusUploadExcel('/api/import/preview',file);
    const rows=plan.filas.slice(0,50);
    container.innerHTML=`<div class="pro-panel">
      <div class="pro-panel-header"><div><h3>Vista previa · ${esc(file.name)}</h3><p>Se encontraron ${plan.total} registros en ${plan.areas.length} áreas. ${plan.yaImportados||0} ya se habían cargado. Vista de las primeras 50 filas.</p></div></div>
      <div class="pro-stat-grid nexus-import-stats"><div class="pro-stat"><div class="pro-stat-top">Filas detectadas</div><div class="pro-stat-value">${plan.total}</div></div><div class="pro-stat"><div class="pro-stat-top">Nuevos para agregar</div><div class="pro-stat-value">${plan.nuevos}</div></div><div class="pro-stat"><div class="pro-stat-top">Repetidos</div><div class="pro-stat-value">${plan.duplicados}</div></div><div class="pro-stat"><div class="pro-stat-top">SIAFI por verificar</div><div class="pro-stat-value">${plan.sinSIAFI}</div></div></div>
      ${plan.ignoradas.length?`<p class="pro-muted" style="margin:14px 0">Hojas sin bienes importables: ${plan.ignoradas.map(x=>esc(x.hoja)).join(' · ')}</p>`:''}
      ${plan.duplicados?`<div class="nexus-import-alert"><strong>Atención: ${plan.duplicados} registro(s) repetido(s).</strong> Los repetidos dentro del mismo Excel se conservarán con código PEND-DUP para revisión; otros conflictos se apartan. Nunca se sobrescriben fichas existentes.</div>`:''}
      <div class="table-wrap pro-results-wrap"><table class="result-table"><thead><tr><th>Estado</th><th>Inventario</th><th>Descripción</th><th>Área</th><th>Responsable</th><th>Hoja / fila</th></tr></thead><tbody>${rows.map(x=>`<tr><td><span class="asset-badge ${x.estadoImportacion==='duplicado'||x.estadoImportacion==='nuevo_pendiente'?'bad':''}">${x.estadoImportacion==='duplicado'?'Conflicto':x.estadoImportacion==='nuevo_pendiente'?'Duplicado / revisar':x.estadoImportacion==='ya_importado'?'Ya registrado':x.pendienteNumero?'Pendiente SIAFI':'Nuevo'}</span></td><td>${esc(x.numeroInventario)}</td><td>${esc(x.descripcion)}</td><td>${esc(x.area)}</td><td>${esc(x.responsable||'—')}</td><td>${esc(x.hoja)} / ${x.fila}</td></tr>`).join('')}</tbody></table></div>
      <div class="row-actions" style="margin-top:21px"><button id="nexusExcelCommitBtn" class="btn" onclick="nexusExcelCommit()" ${plan.nuevos?'':'disabled'}>Confirmar e importar ${plan.nuevos} bienes</button><button class="btn secondary" onclick="nexusExcelPreview()">Revisar nuevamente</button></div>
      <p class="pro-muted">El nombre responsable de estas prefichas se asocia al jefe del área, usando una identidad maestra cuando coincide el nombre completo. Si el área ya tiene otra jefatura, se requiere verificación; no se sobrescribe automáticamente.</p>
    </div>`;
  }catch(e){container.innerHTML=`<div class="pro-panel"><div class="nexus-import-alert">${esc(e.message)}</div></div>`;toast(e.message);}
}
async function nexusExcelCommit(){
  if(!NEXUS_EXCEL_FILE||!NEXUS_EXCEL_PLAN||!NEXUS_EXCEL_PLAN.nuevos)return;
  const btn=document.getElementById('nexusExcelCommitBtn');if(btn){btn.disabled=true;btn.textContent='Guardando bienes…';}
  try{
    const data=await nexusUploadExcel('/api/import/commit',NEXUS_EXCEL_FILE);
    NEXUS_EXCEL_PLAN=null;
    document.getElementById('nexusExcelResult').innerHTML=`<div class="pro-panel"><div class="pro-pagehead"><div><div class="pro-kicker">IMPORTACIÓN COMPLETADA</div><h2>${data.importados} bienes incorporados</h2><p class="pro-subtitle">${data.areasCreadas} áreas nuevas · ${data.responsablesCreados} jefes únicos nuevos · ${data.duplicados} SIAFI repetidos · ${data.jefaturasPorVerificar||0} jefaturas por verificar.</p></div></div><div class="row-actions"><button class="btn" onclick="location.hash='#/buscar'">Ver bienes importados →</button><button class="btn secondary" onclick="downloadBackup()">Descargar respaldo</button><button class="btn secondary" onclick="renderImportExcel(document.getElementById('app'))">Importar otro Excel</button></div></div>`;
    toast(`${data.importados} bienes importados correctamente.`);nexusLoadConflicts();
  }catch(e){toast(e.message);if(btn){btn.disabled=false;btn.textContent='Intentar nuevamente';}}
}
async function nexusLoadConflicts(){
  const el=document.getElementById('nexusExcelConflicts');if(!el)return;
  try{
    const r=await requestJSON('/api/import/review');
    const items=r.pendientes||[];
    el.innerHTML=`<section class="pro-panel"><div class="pro-panel-header"><div><h3>Duplicados pendientes de revisión</h3><p>Registros conservados para comprobarlos manualmente sin sobrescribir el inventario.</p></div><span class="asset-badge ${items.length?'bad':''}">${items.length}</span></div>
      ${items.length?`<div class="table-wrap pro-results-wrap"><table class="result-table"><thead><tr><th>Inventario</th><th>Descripción</th><th>Área del Excel</th><th>Archivo</th><th>Motivo</th></tr></thead><tbody>${items.slice(0,50).map(x=>`<tr><td>${esc(x.numeroOriginal||x.numeroInventario)}</td><td>${esc(x.descripcion)}</td><td>${esc(x.area)}</td><td>${esc(x.archivo)}</td><td>${esc(x.motivo)}</td></tr>`).join('')}</tbody></table></div>`:'<p class="pro-muted">No hay conflictos registrados.</p>'}
    </section>`;
  }catch(e){el.innerHTML='';}
}


/* Bienes Nacionales · Parche 3.4: fotografías de celular optimizadas antes de enviarlas a D1.
   No cambia las rutas, la base, los permisos ni los bienes ya registrados.
   El servidor Cloudflare actual admite un máximo de 750 000 bytes por imagen. */
(function(){
  'use strict';
  const MAX_ORIGINAL = 50 * 1024 * 1024;
  const MAX_FINAL = 600 * 1024; // margen respecto a los 750 000 bytes permitidos en el Worker.
  const SUPPORTED_DIRECT = new Set(['image/jpeg','image/png','image/webp','image/gif']);

  async function preparePhotoForUpload(file){
    if(!file || typeof file.size !== 'number') throw Error('Selecciona una fotografía válida.');
    if(file.size > MAX_ORIGINAL) throw Error('La fotografía supera 50 MB. Selecciona una imagen más pequeña.');
    if(file.size <= MAX_FINAL && SUPPORTED_DIRECT.has(file.type)) return file;
    if(!file.type.startsWith('image/') && !/\.(jpe?g|png|webp|gif|heic|heif)$/i.test(file.name||'')){
      throw Error('Selecciona una imagen JPEG, PNG, WebP o una foto compatible del teléfono.');
    }
    if(typeof toast==='function')toast('Optimizando la fotografía para guardarla…');

    let bitmap=null, img=null, srcURL=null, width=0, height=0;
    try{
      // createImageBitmap aplica la orientación EXIF en navegadores compatibles.
      if(typeof createImageBitmap==='function'){
        try{
          bitmap=await createImageBitmap(file,{imageOrientation:'from-image'});
          width=bitmap.width;height=bitmap.height;
        }catch(_){ bitmap=null; }
      }
      if(!bitmap){
        srcURL=URL.createObjectURL(file);
        img=await new Promise((resolve,reject)=>{
          const el=new Image();
          el.onload=()=>resolve(el);
          el.onerror=()=>reject(Error('El navegador no puede abrir esta foto. Configura la cámara para usar JPEG o convierte la imagen a JPG.'));
          el.src=srcURL;
        });
        width=img.naturalWidth;height=img.naturalHeight;
      }
      if(!width||!height)throw Error('La fotografía no tiene dimensiones válidas.');

      const canvas=document.createElement('canvas');
      const ctx=canvas.getContext('2d',{alpha:false});
      if(!ctx)throw Error('Este navegador no permite comprimir fotografías.');
      for(const maxSide of [1600,1280,1000,800,640]){
        const ratio=Math.min(1,maxSide/Math.max(width,height));
        canvas.width=Math.max(1,Math.round(width*ratio));
        canvas.height=Math.max(1,Math.round(height*ratio));
        ctx.fillStyle='#ffffff';
        ctx.fillRect(0,0,canvas.width,canvas.height);
        ctx.drawImage(bitmap||img,0,0,canvas.width,canvas.height);
        for(const quality of [0.84,0.72,0.60,0.48,0.36]){
          const output=await new Promise(resolve=>canvas.toBlob(resolve,'image/jpeg',quality));
          if(!output)throw Error('No se pudo convertir la foto a JPEG en este dispositivo.');
          if(output.size<=MAX_FINAL){
            canvas.width=0;canvas.height=0;
            return output;
          }
        }
      }
      throw Error('Esta fotografía no pudo reducirse lo suficiente. Intenta tomarla con una resolución menor.');
    }finally{
      if(bitmap && typeof bitmap.close==='function')bitmap.close();
      if(srcURL)URL.revokeObjectURL(srcURL);
    }
  }

  // Sustituye el cargador original (7 MB) sin alterar el resto de la interfaz.
  window.uploadPhoto=async function(file,folder){
    try{
      const selected=await preparePhotoForUpload(file);
      const b64=await new Promise((resolve,reject)=>{
        const reader=new FileReader();
        reader.onload=()=>resolve(String(reader.result).split(',')[1]);
        reader.onerror=()=>reject(Error('No se pudo leer la foto optimizada.'));
        reader.readAsDataURL(selected);
      });
      const response=await requestJSON('/api/photo',payload({data:b64,folder}));
      return response.url;
    }catch(error){
      // Los formularios existentes ocultan parte del mensaje del servidor.
      // Mostrarlo evita que los usuarios pierdan el motivo del fallo.
      alert('No se pudo guardar la fotografía.\n\n'+(error?.message||'Inténtalo otra vez.'));
      throw error;
    }
  };
})();
