// Worka PWA — Service Worker
// Cache offline + push notifications
//
// NOTA: este cabeçalho dizia "Face ID support", mas nunca houve
// nenhuma implementação de biometria no projeto — não existe WebAuthn,
// navigator.credentials nem tabela de credenciais em lugar nenhum do
// código. O comentário foi removido para não sugerir uma proteção que
// o sistema não tem. Login biométrico continua sendo uma feature em
// aberto (exige WebAuthn + tabela de credenciais no banco).

// Cache bumped para v3: os caminhos abaixo mudaram de
// "/Worka-backend/..." para relativos. Sem trocar o nome do cache, os
// navegadores que já instalaram o SW antigo continuariam servindo as
// URLs velhas (404) do cache para sempre.
var CACHE = 'worka-v3';
// Ícone usado em notificações push — mesmo SVG inline do manifest.json.
// Não referenciamos um arquivo /icon-192.png porque ele nunca existiu
// neste repositório (o app sempre usou apenas ícones SVG inline no
// manifest); a referência antiga aqui sempre resultava em 404 e a
// notificação caía sem ícone.
var NOTIFICATION_ICON = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 192 192'%3E%3Crect width='192' height='192' fill='%230a2e1a' rx='40'/%3E%3Ctext x='50%25' y='58%25' font-family='Georgia,serif' font-size='90' font-weight='900' fill='%233dd669' text-anchor='middle' dominant-baseline='middle'%3EW%3C/text%3E%3C/svg%3E";
// Caminhos RELATIVOS de propósito: o site agora é servido na raiz do
// domínio próprio (workap.com.br), onde "/Worka-backend/..." não
// existe e dava 404 em tudo — quebrando cache offline e PWA. Relativo
// funciona tanto na raiz do domínio quanto em
// 811freitas.github.io/Worka-backend/, sem precisar escolher um dos dois.
// (worka.html virou index.html no repositório.)
var ASSETS = [
  'worka-app.html',
  'index.html',
  'manifest.json',
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
    icon: NOTIFICATION_ICON,
    badge: NOTIFICATION_ICON,
    vibrate: [200, 100, 200],
    data: { url: data.url || 'worka-app.html' },
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
    var url = e.notification.data.url || 'worka-app.html';
    e.waitUntil(clients.openWindow(url));
  }
});
