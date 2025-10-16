const CACHE_NAME = "bnvd-cache-v1";
const urlsToCache = [
  "/",
  "/static/css/style.css",
  "/static/js/main.js",
  "/static/images/192/bnvd-logo.png",
  "/static/images/512/bnvd-logo.png",
  "/busca",
  "/recentes",
  "/sobre"
];

self.addEventListener("install", function (event) {
  console.log("[BNVD PWA] Service Worker instalando...");
  event.waitUntil(
    caches.open(CACHE_NAME).then(function (cache) {
      console.log("[BNVD PWA] Cache aberto");
      return cache.addAll(urlsToCache).catch(function(error) {
        console.error("[BNVD PWA] Erro ao cachear URLs:", error);
      });
    })
  );
  self.skipWaiting();
});

self.addEventListener("activate", function(event) {
  console.log("[BNVD PWA] Service Worker ativado");
  event.waitUntil(
    caches.keys().then(function(cacheNames) {
      return Promise.all(
        cacheNames.map(function(cacheName) {
          if (cacheName !== CACHE_NAME) {
            console.log("[BNVD PWA] Removendo cache antigo:", cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  return self.clients.claim();
});

self.addEventListener("fetch", function (event) {
  if (event.request.method !== "GET") return;
  
  const url = new URL(event.request.url);
  
  if (url.origin !== location.origin && !url.hostname.includes('jsdelivr.net') && !url.hostname.includes('cdnjs.cloudflare.com')) {
    return;
  }

  event.respondWith(
    caches.match(event.request).then(function(response) {
      if (response) {
        console.log("[BNVD PWA] Servindo do cache:", event.request.url);
        return response;
      }

      return fetch(event.request).then(function(response) {
        if (!response || response.status !== 200 || response.type === 'error') {
          return response;
        }

        if (url.pathname.startsWith('/static/') || 
            url.hostname.includes('jsdelivr.net') || 
            url.hostname.includes('cdnjs.cloudflare.com')) {
          const responseToCache = response.clone();
          caches.open(CACHE_NAME).then(function(cache) {
            cache.put(event.request, responseToCache);
          });
        }

        return response;
      }).catch(function(error) {
        console.log("[BNVD PWA] Erro ao buscar:", event.request.url, error);
        
        if (event.request.mode === 'navigate') {
          return caches.match('/');
        }
        
        return new Response('Offline - conteúdo não disponível', {
          status: 503,
          statusText: 'Service Unavailable',
          headers: new Headers({
            'Content-Type': 'text/plain'
          })
        });
      });
    })
  );
});
