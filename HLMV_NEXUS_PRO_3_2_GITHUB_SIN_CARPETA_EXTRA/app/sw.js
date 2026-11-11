// HLMV PWA: SOLO interfaz. Nunca almacenar respuestas privadas en caché.
const SHELL='hlmv-bienes-nacionales-compacto-v51-opcion4';
const ASSETS=['/','/manifest.webmanifest','/icons/bn-icon-v42-32.png','/icons/bn-icon-v42-192.png','/icons/bn-icon-v42-512.png','/pro.css','/pro.js','/customize.css','/customize.js','/minimal.css','/institucional.css','/compacto.css','/icons/bn-logo.png','/icons/gobierno-salud-v42.png'];
self.addEventListener('install', event=>{
 // Una imagen institucional ausente no debe bloquear la actualización del panel.
 event.waitUntil(caches.open(SHELL).then(async cache=>{
   await Promise.allSettled(ASSETS.map(async path=>{
     const response=await fetch(path,{cache:'reload'});
     if(response.ok) await cache.put(path,response);
   }));
 }).then(()=>self.skipWaiting()));
});
self.addEventListener('activate', event=>{
 event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==SHELL).map(k=>caches.delete(k)))).then(()=>self.clients.claim()));
});
self.addEventListener('fetch',event=>{
 const url=new URL(event.request.url);
 if(event.request.method!=='GET'||url.origin!==self.location.origin)return;
 if(url.pathname.startsWith('/api/')||url.pathname.startsWith('/imagenes/'))return;
 if(!ASSETS.includes(url.pathname))return;
 event.respondWith(fetch(event.request).then(response=>{
   if(response.ok){const copy=response.clone();caches.open(SHELL).then(cache=>cache.put(event.request,copy));}
   return response;
 }).catch(()=>caches.match(event.request)));
});
