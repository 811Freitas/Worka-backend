// Workap PWA — Service Worker
// Cache offline + push notifications
//
// NOTA (corrigida): esta nota dizia que biometria "nunca foi
// implementada". Isso ficou verdadeiro por um tempo e hoje está
// errado — existem as rotas /webauthn/registrar/* e /webauthn/login/*,
// a tabela webauthn_credentials, e o app usa as duas. Entrada por
// Face ID/digital É uma funcionalidade real e está na lista de venda
// do site; deixar a nota como estava faria a próxima pessoa remover
// da vitrine um recurso que o produto tem.

// v34: entrou IA — resumo diario do dono por e-mail e botao "escrever
// com IA" no mural, com teto de gasto por empresa. Sem chave, some.
// v33: entrou a aba de Anotacoes (memoria do dono sobre a equipe, com
// lembrete que avisa no dia) e o aviso de periodo aquisitivo de ferias,
// 30 dias antes de cada aniversario de admissao.
// v32: a vitrine ganhou a lista das 50 funcionalidades do Pro, e a
// jornada/banco de horas passou a exigir o plano Pro de verdade —
// era vendida como Pro e funcionava no Completo.
// v31: o Pro passou a ser anunciado como 89,99 e o valor enviado a
// Cakto desconta os 99 centavos que ela acrescenta — o cliente fecha
// exatamente no preco do site.
// v30: o teste gratis passou a BLOQUEAR de verdade quando acaba —
// tela de assinatura no app, e o e-mail de fim de trial ganhou botao
// de pagar e WhatsApp de vendas.
// v29: a cobranca que libera plano ja nasce com um link de criar
// senha, de uso unico, para o dono mandar junto no WhatsApp.
// v28: quem paga um link de venda sem ter conta agora recebe e-mail
// para criar a senha, e a tela final para de dizer "trial" para quem
// comprou.
// v27: o preco saiu do topo do site — no lugar entrou a linha de
// garantias (7 dias / sem cartao / cancela quando quiser). O valor
// continua na secao de planos.
// v26: aba Integracoes no painel Owner — Pixel da Meta e WhatsApp
// passam a ser campos, e o site le do servidor em vez de deploy.
// v25: o cadastro passou a ENVIAR a origem (UTM) que ja capturava —
// o aviso de trial e de venda agora dizem de qual anuncio veio.
// v24: SEO — description, canonical, dados estruturados e o nome no
// H1. Entraram robots.txt e sitemap.xml.
// v23: o cadastro passou a EXIGIR telefone e CPF/CNPJ — os campos ja
// existiam na tela, mas nao eram conferidos nem enviados.
// v22: a Stripe saiu; o pagamento é da Cakto. A vitrine voltou a
// prometer Pix, porque a assinatura mensal agora é cobrada no Pix,
// boleto ou cartão. O botão do portal de cobrança saiu do app.
// v21: checkout personalizado (logo, descrição do plano, aviso sob o
// botão) e tela de confirmação para quem volta de um link de cobrança.
// v20: o pagamento voltou para a Stripe. Mudaram os textos do checkout
// no site ("via PIX" virou "no cartão", porque a assinatura mensal é
// cobrada no cartão) e entrou o botão do portal de cobrança no app.
// v19: link de pagamento passou a liberar plano (aba Cobranças).
// v18: aba Cobrancas no painel Owner (links de pagamento).
// v17: o pagamento passou da Stripe para a AbacatePay — o botão
// de assinatura e a tela de cancelamento mudaram.
// v16: entrou a Central de Suporte (menu e telas novas no app).
// v15: o pagamento saiu do PIX na própria página e passou para a
// Stripe. Sem trocar o nome do cache, quem já tinha visitado o site
// continuava recebendo o HTML antigo — com a tela de QR Code e um botão
// chamando a rota /pix, que não existe mais no servidor. Era isso que
// fazia o botão de pagamento "não funcionar" logo depois da troca, só
// para quem já conhecia o site. Em aba anônima parecia tudo certo.
//
// REGRA: mexeu em index.html, app/index.html ou neste arquivo, sobe o
// número. É de graça, e o bug que evita é invisível em teste.
var CACHE = 'workap-v34';
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
