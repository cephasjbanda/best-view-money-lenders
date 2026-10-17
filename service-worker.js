const CACHE = "best-view-shell-v1";
const SHELL = ["/app", "/manifest.webmanifest", "/static/icon.svg"];
self.addEventListener("install", event => {
  event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(SHELL)));
  self.skipWaiting();
});
self.addEventListener("activate", event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener("fetch", event => {
  const url = new URL(event.request.url);
  // Do not cache API responses, authentication routes, or any customer/payment data.
  if (url.origin !== self.location.origin || url.pathname.startsWith("/login") ||
      url.pathname.startsWith("/logout") || url.pathname.startsWith("/me") ||
      url.pathname.startsWith("/customers") || url.pathname.startsWith("/loans") ||
      url.pathname.startsWith("/users") || url.pathname.startsWith("/branches") ||
      url.pathname.startsWith("/dashboard") || url.pathname.startsWith("/audit") ||
      url.pathname.startsWith("/admin")) return;
  if (event.request.method !== "GET") return;
  event.respondWith(fetch(event.request).catch(() => caches.match(event.request)));
});
