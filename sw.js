// Workap PWA — Service Worker
// Cache offline + push notifications
//
// NOTA: este cabeçalho dizia "Face ID support", mas nunca houve
// nenhuma implementação de biometria no projeto — não existe WebAuthn,
// navigator.credentials nem tabela de credenciais em lugar nenhum do
// código. O comentário foi removido para não sugerir uma proteção que
// o sistema não tem. Login biométrico continua sendo uma feature em
// aberto (exige WebAuthn + tabela de credenciais no banco).

// Cache bumped para v13: entraram a loja online (venda sem pagamento,
// com carrinho que vira pedido para a equipe) e o segundo plano. Sem
// trocar o nome do cache, quem já abriu o app continuaria vendo a
// versão de antes.
var CACHE = 'workap-v13';
// Ícone das notificações push: só o símbolo, sem a palavra "workap".
var NOTIFICATION_ICON = 'assets/icon-192.png';
var NOTIFICATION_BADGE = 'assets/favicon-32.png';
// Caminhos RELATIVOS de propósito: o site agora é servido na raiz do
// domínio próprio (workap.com.br), onde "/Worka-backend/..." não
// existe e dava 404 em tudo — quebrando cache offline e PWA. Relativo
// funciona tanto na raiz do domínio quanto em
// 811freitas.github.io/Worka-backend/, sem precisar escolher um dos dois.
// (worka.html virou index.html no repositório.)
var ASSETS = [
  // O app agora mora em /app/ (arquivo app/index.html) para o endereço
  // não terminar em ".html". Cacheado pelo endereço da PASTA, que é o
  // que o navegador realmente pede — 'app/index.html' e 'app/' são
  // chaves de cache diferentes.
  'app/',
  // A vitrine pública também entra no cache: quem abre o link da loja
  // muitas vezes está na rua, em rede ruim.
  'loja/',
  // './' e 'index.html' são a MESMA página, mas endereços diferentes
  // para o cache. Quem abre workap.com.br pede './'; sem essa entrada,
  // a home não ficava disponível offline mesmo com o arquivo em cache.
  './',
  'index.html',
  'manifest.json',
  // O símbolo virou SVG único: as páginas apontam para ele em vez de
  // manter um PNG por tamanho. Os PNGs abaixo continuam porque
  // notificação push e favicon de navegador antigo não aceitam SVG.
  'assets/simbolo.svg',
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
//
// Só mexe no que é DESTA origem, mais a folha de estilo das fontes que
// entra no cache offline de propósito. Antes a regra era uma lista de
// domínios a ignorar ("onrender.com", "supabase.co"...): funcionava por
// coincidência, porque acertava o endereço do backend de hoje. No dia
// em que a API mudar de domínio — ou for testada em outro endereço — o
// service worker passa a interceptar e a CACHEAR respostas de API, e o
// app começa a mostrar dados velhos sem ninguém entender por quê.
//
// Inverter a regra (só o que é meu) elimina a classe inteira do
// problema: qualquer API, em qualquer domínio, passa direto.
self.addEventListener('fetch', function(e) {
  var mesmaOrigem = e.request.url.indexOf(self.location.origin) === 0;
  var fonteDoCache = e.request.url.indexOf('https://fonts.googleapis.com/') === 0 ||
                     e.request.url.indexOf('https://fonts.gstatic.com/') === 0;
  if (!mesmaOrigem && !fonteDoCache) return;

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
          '<html><body style="font-family:sans-serif;text-align:center;padding:40px;background:#0a2e1a;color:white"><h2>Workap</h2><p>Sem conexão com a internet.</p><p>Algumas funções podem estar indisponíveis.</p></body></html>',
          { headers: { 'Content-Type': 'text/html' } }
        );
      });
    })
  );
});

// Push notifications
self.addEventListener('push', function(e) {
  var data = e.data ? e.data.json() : {};
  var title = data.title || 'Workap';
  var options = {
    body: data.body || 'Nova notificação',
    icon: NOTIFICATION_ICON,
    badge: NOTIFICATION_BADGE,
    vibrate: [200, 100, 200],
    data: { url: data.url || 'app/' },
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
    var url = e.notification.data.url || 'app/';
    e.waitUntil(clients.openWindow(url));
  }
});
