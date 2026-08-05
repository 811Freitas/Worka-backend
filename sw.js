// Worka PWA — Service Worker
// Cache offline + push notifications
//
// NOTA: este cabeçalho dizia "Face ID support", mas nunca houve
// nenhuma implementação de biometria no projeto — não existe WebAuthn,
// navigator.credentials nem tabela de credenciais em lugar nenhum do
// código. O comentário foi removido para não sugerir uma proteção que
// o sistema não tem. Login biométrico continua sendo uma feature em
// aberto (exige WebAuthn + tabela de credenciais no banco).

// Cache bumped para v4: entraram os arquivos de assets/ (a logo de
// verdade). Sem trocar o nome do cache, quem já tem o SW instalado
// continuaria servindo do cache a versão sem logo — inclusive o
// ícone SVG improvisado das notificações.
var CACHE = 'worka-v4';
// Ícone das notificações push. Era um SVG inline com a letra "W" em
// Georgia, improviso de quando não havia arte nenhuma no repositório.
// Agora existe a logo real.
var NOTIFICATION_ICON = 'assets/icon-192.png';
var NOTIFICATION_BADGE = 'assets/favicon-32.png';
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
  'assets/logo-worka-192.png',
  'assets/logo-marca-96.png',
  'assets/icon-192.png',
  'assets/favicon-32.png',
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
    badge: NOTIFICATION_BADGE,
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
