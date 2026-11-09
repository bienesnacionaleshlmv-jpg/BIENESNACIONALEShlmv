/* NEXUS PRO 2.6 | Preferencias visuales locales. Sin acceso a SQLite ni al inventario. */
(function(){
'use strict';
const KEY='hlmv_bn_institucional_appearance_v1';
const DEFAULTS=Object.freeze({theme:'light',accent:'blue',text:'normal',density:'comfortable',menu:'expanded'});
const ALLOWED={theme:['light'],accent:['green','blue','purple','orange','cyan'],text:['normal','large'],density:['comfortable','compact'],menu:['expanded','compact']};
let preview={...DEFAULTS};
function valid(raw){
  const result={...DEFAULTS};
  if(raw&&typeof raw==='object')for(const k of Object.keys(DEFAULTS))if(ALLOWED[k].includes(raw[k]))result[k]=raw[k];
  return result;
}
function saved(){try{return valid(JSON.parse(localStorage.getItem(KEY)||'{}'));}catch(_){return {...DEFAULTS};}}
function apply(settings){
  const v=valid(settings),root=document.documentElement;
  root.dataset.theme=v.theme;
  root.dataset.nexusTheme=v.theme;
  root.dataset.nexusAccent=v.accent;
  root.dataset.nexusText=v.text;
  root.dataset.nexusDensity=v.density;
  root.dataset.nexusMenu=v.menu;
  // Change the Chrome/PWA toolbar color to match the selected mode.
  const meta=document.querySelector('meta[name="theme-color"]');
  if(meta)meta.content='#ffffff';
}
function updateOptions(){
  document.querySelectorAll('#nexusAppearanceDialog [data-nexus-setting]').forEach(button=>{
    const yes=preview[button.dataset.nexusSetting]===button.dataset.nexusValue;
    button.setAttribute('aria-pressed',String(yes));
    button.classList.toggle('selected',yes);
  });
}
function dialog(){return document.getElementById('nexusAppearanceDialog');}
function cancel(){
  apply(saved());
  dialog()?.close();
}
function save(){
  try{localStorage.setItem(KEY,JSON.stringify(valid(preview)));}
  catch(_){if(typeof toast==='function')toast('Este navegador no pudo guardar la preferencia.');return;}
  apply(preview);dialog()?.close();
  if(typeof toast==='function')toast('Apariencia guardada en esta computadora.');
}
window.nexusOpenAppearance=function(){
  const el=dialog();if(!el)return;
  preview=saved();apply(preview);updateOptions();
  if(!el.open)el.showModal();
};
window.nexusCancelAppearance=cancel;
window.nexusSaveAppearance=save;
window.nexusResetAppearance=function(){preview={...DEFAULTS};apply(preview);updateOptions();};
document.addEventListener('click',event=>{
  const target=event.target.closest?.('#nexusAppearanceDialog [data-nexus-setting]');
  if(!target)return;
  const k=target.dataset.nexusSetting,value=target.dataset.nexusValue;
  if(!(k in ALLOWED)||!ALLOWED[k].includes(value))return;
  preview[k]=value;apply(preview);updateOptions();
});
const appearance=dialog();
if(appearance){
  appearance.addEventListener('cancel',e=>{e.preventDefault();cancel();});
  appearance.addEventListener('click',e=>{if(e.target===appearance)cancel();});
}
// Restore the saved theme even after reloading the app.
apply(saved());
// Enable icon-only navigation without hiding accessible link names.
document.querySelectorAll('#shellSidebar .side-link').forEach(link=>{
  const name=link.querySelector('span')?.textContent?.trim();
  if(name){link.setAttribute('aria-label',name);link.setAttribute('title',name);}
});
})();
