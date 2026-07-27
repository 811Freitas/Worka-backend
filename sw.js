// Worka PWA — Service Worker
// Cache offline + Face ID support

var CACHE = 'worka-v1';
var ASSETS = [
  '/Worka-backend/worka-app.html',
  '/Worka-backend/worka.html',
  '/Worka-backend/manifest.json',
  'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Syne:wght@700;800&display=swap'
];

// Instalar e fazer cache
self.addEventListener('install', function(e) {
  console.log('[SW] Instalando...');
  e.waitUntil(
    caches.open(CACHE).then(function(cache) {
      return cache.addAll(ASSETS).catch(function(err) {
        console.log('[SW] Cache parcial:', err);
      });
    })
  );
  self.skipWaiting();
});

// Ativar e limpar caches antigos
self.addEventListener('activate', function(e) {
  console.log('[SW] Ativando...');
  e.waitUntil(
    caches.keys().then(function(keys) {
      return Promise.all(
        keys.filter(function(k) { return k !== CACHE; }).map(function(k) {
          return caches.delete(k);
        })
      );
    })
  );
  self.clients.claim();
});

// Interceptar requisições — Network first, cache fallback
self.addEventListener('fetch', function(e) {
  // Não interceptar requisições ao backend ou APIs externas
  if (e.request.url.includes('onrender.com') ||
      e.request.url.includes('api.resend.com') ||
      e.request.url.includes('supabase.co') ||
      e.request.url.includes('api.x.ai') ||
      e.request.url.includes('maps.google.com')) {
    return;
  }

  e.respondWith(
    fetch(e.request).then(function(response) {
      // Salvar no cache
      if (response.ok && e.request.method === 'GET') {
        var clone = response.clone();
        caches.open(CACHE).then(function(cache) {
          cache.put(e.request, clone);
        });
      }
      return response;
    }).catch(function() {
      // Offline — usar cache
      return caches.match(e.request).then(function(cached) {
        if (cached) return cached;
        // Página offline padrão
        return new Response(
          '<html><body style="font-family:sans-serif;text-align:center;padding:40px;background:#0a2e1a;color:white"><h2>Worka</h2><p>Sem conexão com a internet.</p><p>Algumas funções podem estar indisponíveis.</p></body></html>',
          { headers: { 'Content-Type': 'text/html' } }
        );
      });
    })
  );
});

// Push notifications
self.addEventListener('push', function(e) {
  var data = e.data ? e.data.json() : {};
  var title = data.title || 'Worka';
  var options = {
    body: data.body || 'Nova notificação',
    icon: '/Worka-backend/icon-192.png',
    badge: '/Worka-backend/icon-192.png',
    vibrate: [200, 100, 200],
    data: { url: data.url || '/Worka-backend/worka-app.html' },
    actions: [
      { action: 'open', title: 'Abrir' },
      { action: 'close', title: 'Fechar' }
    ]
  };
  e.waitUntil(self.registration.showNotification(title, options));
});

// Click na notificação
self.addEventListener('notificationclick', function(e) {
  e.notification.close();
  if (e.action === 'open' || !e.action) {
    var url = e.notification.data.url || '/Worka-backend/worka-app.html';
    e.waitUntil(clients.openWindow(url));
  }
});
