// Service Worker — Identidade Soberana PWA (Otimizado para Core Web Vitals & Mobile)
const CACHE_NAME = "is-cache-v4";
const OFFLINE_URL = "/";

const PRECACHE_ASSETS = [
  "/",
  "/manifest.webmanifest",
  "/favicon.svg",
  "/icons/icon-192.png",
  "/icons/icon-512.png"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(PRECACHE_ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      )
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") return;

  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;

  // Cache-First para assets imutáveis com hash (/_astro/), ícones e SVGs
  if (url.pathname.startsWith("/_astro/") || url.pathname.startsWith("/icons/") || url.pathname.endsWith(".svg")) {
    event.respondWith(
      caches.match(event.request).then((cached) => {
        if (cached) return cached;
        return fetch(event.request).then((res) => {
          if (res && res.status === 200) {
            const clone = res.clone();
            caches.open(CACHE_NAME).then((c) => c.put(event.request, clone));
          }
          return res;
        });
      })
    );
    return;
  }

  // Network-First com timeout rápido (2000ms) para páginas HTML e search JSON (melhora 3G/4G no celular)
  event.respondWith(
    new Promise((resolve) => {
      let settled = false;
      const timer = setTimeout(async () => {
        const cached = await caches.match(event.request);
        if (cached && !settled) {
          settled = true;
          resolve(cached);
        }
      }, 2000);

      fetch(event.request)
        .then((networkResponse) => {
          clearTimeout(timer);
          if (networkResponse && networkResponse.status === 200) {
            const responseToCache = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, responseToCache));
          }
          if (!settled) {
            settled = true;
            resolve(networkResponse);
          }
        })
        .catch(async () => {
          clearTimeout(timer);
          if (settled) return;
          const cachedResponse = await caches.match(event.request);
          if (cachedResponse) {
            resolve(cachedResponse);
          } else if (event.request.headers.get("accept")?.includes("text/html")) {
            resolve(caches.match(OFFLINE_URL));
          } else {
            resolve(new Response("", { status: 504 }));
          }
        });
    })
  );
});
