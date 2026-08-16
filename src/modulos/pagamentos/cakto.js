"use strict";

/**
 * CAKTO — gateway de pagamento
 * ════════════════════════════════════════════════════════════
 * ⚠️  ESTE MÓDULO NÃO FOI CONFERIDO CONTRA UMA CONTA CAKTO REAL.
 *
 * É o mesmo desenho usado pelo Workap (autenticação OAuth2, webhook
 * autenticado por segredo na URL, tradução de erro campo a campo) —
 * portado de propósito, para que as duas plataformas fiquem fáceis de
 * manter juntas. Mas o Workap descobriu boa parte deste formato batendo
 * numa conta real, sem acesso à documentação (docs.cakto.com.br estava
 * bloqueada na rede onde aquele código foi escrito), e diz isso na cara
 * dura no próprio arquivo. Aqui não houve sequer essa batida — o código
 * está pronto para configurar, não pronto para confiar.
 *
 * ANTES de qualquer cliente pagar de verdade por aqui:
 *   1. preencher CAKTO_CLIENT_ID / CAKTO_CLIENT_SECRET / CAKTO_WEBHOOK_SECRET;
 *   2. rodar uma cobrança de R$ 1 ponta a ponta;
 *   3. conferir no log ("cakto_token_ok") qual formato de autenticação
 *      a Cakto aceitou de verdade, e simplificar caktoToken() para usar
 *      só esse — a escada de tentativas é andaime, não é para ficar.
 *
 * Sem as três variáveis de ambiente, cada função aqui rejeita cedo, com
 * uma mensagem clara — nunca finge que funcionou.
 * ════════════════════════════════════════════════════════════
 */

var https = require("https");
var crypto = require("crypto");
var config = require("../../config");

var CAKTO = {
  host: "api.cakto.com.br",

  token:        "/public_api/token/",
  criarProduto: "/public_api/products/",
  criarOferta:  "/public_api/offers/",

  // Onde procurar o link de pagamento na resposta — o nome exato do
  // campo não está confirmado, por isso a lista.
  camposDeUrl: ["checkout_url", "payment_link", "link", "url", "offer_url"],

  frequenciaMensal: "monthly",
  // Ver o mesmo campo no Workap: "one_time"/"subscription" foram
  // recusados — quem classifica é `type` (o que é vendido), e quem
  // decide a recorrência é `recurrence_frequency`. "digital" é o
  // palpite inicial, a confirmar com uma cobrança real.
  tipoProduto: "digital",

  // Só estes eventos liberam ou derrubam o acesso. Qualquer outro é
  // ignorado — reagir a "checkout iniciado" abriria a conta para quem
  // só olhou a tela de pagamento.
  eventosPagos:      ["purchase_approved", "purchase_approved_recurrence", "subscription_renewed"],
  eventosCancelados: ["purchase_refunded", "purchase_chargeback", "subscription_canceled"]
};

function configurado() {
  return !!(config.CAKTO_CLIENT_ID && config.CAKTO_CLIENT_SECRET);
}

/** Traduz o erro no formato Django (campo → lista de motivos) para uma linha legível. */
function mensagemDeErro(json, raw) {
  if (json && typeof json === "object") {
    if (!json.detail && !json.message && !json.error) {
      var partes = Object.keys(json).map(function (campo) {
        var v = json[campo];
        return campo + ": " + (Array.isArray(v) ? v.join(" ") : String(v));
      });
      if (partes.length) return partes.join(" · ").slice(0, 400);
    }
    var direto = json.detail || json.message || json.error;
    if (direto) return typeof direto === "string" ? direto : JSON.stringify(direto).slice(0, 400);
  }
  return (raw || "").slice(0, 300) || "sem corpo na resposta";
}

function requisicaoCrua(metodo, caminho, corpo, token, opcoes) {
  opcoes = opcoes || {};
  return new Promise(function (resolve, reject) {
    var dados = null;
    var headers = { "Accept": "application/json" };

    // O endpoint de token fala formulário; o resto da API fala JSON —
    // ver a nota em caktoToken() sobre por que isto não é opcional.
    if (corpo && opcoes.formulario) {
      dados = Object.keys(corpo)
        .filter(function (k) { return corpo[k] !== undefined && corpo[k] !== null; })
        .map(function (k) { return encodeURIComponent(k) + "=" + encodeURIComponent(String(corpo[k])); })
        .join("&");
      headers["Content-Type"] = "application/x-www-form-urlencoded";
    } else if (corpo) {
      dados = JSON.stringify(corpo);
      headers["Content-Type"] = "application/json";
    }

    if (opcoes.basic) headers["Authorization"] = "Basic " + opcoes.basic;
    else if (token) headers["Authorization"] = "Bearer " + token;
    if (dados) headers["Content-Length"] = Buffer.byteLength(dados);

    var req = https.request({
      hostname: CAKTO.host, port: 443, path: caminho, method: metodo, headers: headers
    }, function (res) {
      var raw = "";
      res.on("data", function (c) { raw += c; });
      res.on("end", function () {
        var json = null;
        try { json = JSON.parse(raw); } catch (e) { /* corpo não-JSON */ }
        if (res.statusCode >= 400) {
          var erro = new Error("Cakto " + res.statusCode + ": " + mensagemDeErro(json, raw));
          erro.status = res.statusCode;
          return reject(erro);
        }
        resolve(json || {});
      });
    });
    req.on("error", reject);
    req.setTimeout(15000, function () { req.destroy(new Error("Cakto: tempo esgotado")); });
    req.end(dados);
  });
}

var tokenCache = { valor: null, expiraEm: 0 };

/**
 * Autentica e devolve o token Bearer, com cache.
 *
 * A escada de tentativas existe porque, sem a documentação confirmada,
 * não dá para saber de antemão qual formato de POST /token/ a Cakto
 * aceita. Custa uma chamada extra só quando falha, e só na renovação
 * (a cada ~30 min) — nunca por cobrança.
 */
async function token() {
  if (!configurado()) {
    throw new Error("Pagamento não configurado (CAKTO_CLIENT_ID/CAKTO_CLIENT_SECRET ausentes)");
  }
  if (tokenCache.valor && Date.now() < tokenCache.expiraEm) return tokenCache.valor;

  var basic = Buffer.from(config.CAKTO_CLIENT_ID + ":" + config.CAKTO_CLIENT_SECRET).toString("base64");
  var idSecret = { client_id: config.CAKTO_CLIENT_ID, client_secret: config.CAKTO_CLIENT_SECRET };
  var tentativas = [
    { nome: "form sem grant_type",      corpo: idSecret, opcoes: { formulario: true } },
    { nome: "form client_credentials",  corpo: Object.assign({ grant_type: "client_credentials" }, idSecret),
      opcoes: { formulario: true } },
    { nome: "basic client_credentials", corpo: { grant_type: "client_credentials" },
      opcoes: { formulario: true, basic: basic } },
    { nome: "json sem grant_type",      corpo: idSecret, opcoes: {} }
  ];

  var r = null, usado = null, falhas = [];
  for (var t of tentativas) {
    try {
      r = await requisicaoCrua("POST", CAKTO.token, t.corpo, null, t.opcoes);
      usado = t.nome;
      break;
    } catch (e) {
      falhas.push(t.nome + ": " + e.message);
      // 400/401 é "não gostou do formato" — vale tentar o próximo.
      // Qualquer outra falha (rede, 500) é problema deles, e insistir
      // só atrasaria a resposta.
      if (e.status !== 401 && e.status !== 400) throw e;
    }
  }
  if (!r) throw new Error("Cakto recusou todos os formatos de autenticação — " + falhas.join(" | "));

  var achado = r.access_token || r.token || r.accessToken;
  if (!achado) {
    throw new Error("Cakto: resposta sem access_token (" + usado + ") — campos recebidos: " +
                    Object.keys(r).join(",").slice(0, 200));
  }

  console.log("[cakto] autenticou com o formato:", usado);

  var segundos = Number(r.expires_in) > 0 ? Number(r.expires_in) : 1800;
  tokenCache = { valor: achado, expiraEm: Date.now() + (segundos - 60) * 1000 };
  return achado;
}

async function requisicao(metodo, caminho, corpo) {
  var t = await token();
  try {
    return await requisicaoCrua(metodo, caminho, corpo, t);
  } catch (e) {
    if (e.status === 401) {
      tokenCache = { valor: null, expiraEm: 0 };
      return requisicaoCrua(metodo, caminho, corpo, await token());
    }
    throw e;
  }
}

/** Procura um link cakto.com.br em qualquer profundidade da resposta. */
function urlDaCobranca(resposta) {
  if (!resposta || typeof resposta !== "object") return null;
  var achado = null;

  (function varrer(no, profundidade) {
    if (achado || !no || profundidade > 6) return;
    if (typeof no === "string") {
      if (/^https?:\/\/[^\s"]*cakto[^\s"]*$/i.test(no)) achado = no;
      return;
    }
    if (Array.isArray(no)) { for (var item of no) varrer(item, profundidade + 1); return; }
    if (typeof no !== "object") return;

    for (var campo of CAKTO.camposDeUrl) {
      if (typeof no[campo] === "string" && /^https?:\/\//.test(no[campo])) { achado = no[campo]; return; }
    }
    for (var chave of Object.keys(no)) varrer(no[chave], profundidade + 1);
  })(resposta, 0);

  return achado;
}

/**
 * Cria a cobrança mensal recorrente para uma conta e devolve o link de
 * pagamento (ou lança, com a mensagem de erro da própria Cakto).
 *
 * `referencia` é gravado na descrição do produto para que o link volte
 * a ser identificável olhando o painel da Cakto — não é o mecanismo que
 * liga o pagamento de volta à conta (isso é feito por e-mail, no
 * webhook; ver rotas.js).
 */
async function criarCobrancaMensal(opcoes) {
  var corpo = {
    name: opcoes.nome,
    description: opcoes.descricao || opcoes.nome,
    type: CAKTO.tipoProduto,
    recurrence_frequency: CAKTO.frequenciaMensal,
    price: opcoes.precoCentavos
  };

  var criado = await requisicao("POST", CAKTO.criarProduto, corpo);
  var link = urlDaCobranca(criado);
  if (link) return link;

  // A documentação indexada pelo Workap diz que criar produto gera
  // oferta e checkout junto; se o link não veio na resposta da criação,
  // ele existe do outro lado — na oferta.
  var idProduto = criado && (criado.id || criado.product_id);
  if (idProduto) {
    var oferta = await requisicao("GET", CAKTO.criarOferta + "?product=" + encodeURIComponent(idProduto), null)
      .catch(function () { return null; });
    var linkDaOferta = oferta && urlDaCobranca(oferta);
    if (linkDaOferta) return linkDaOferta;
  }

  throw new Error("Cakto criou o produto mas não devolveu link de pagamento — confira o painel deles.");
}

/**
 * Confere que o aviso veio mesmo da Cakto.
 *
 * A Cakto não documenta uma assinatura HMAC para o webhook (mesma
 * lacuna que o Workap encontrou). A prova de identidade aqui é um
 * segredo que só o Zapfy conhece, embutido na URL cadastrada no painel
 * deles: https://SEU-DOMINIO/webhook/cakto?s=<CAKTO_WEBHOOK_SECRET>.
 * Mais fraco que HMAC — quem intercepta a URL uma vez pode repetir o
 * aviso — por isso a comparação é em tempo constante e o evento é
 * deduplicado por id (ver pagamentos_eventos na migration 004).
 */
function webhookValido(query, headers) {
  if (!config.CAKTO_WEBHOOK_SECRET) return false;
  var candidato = (query && (query.s || query.secret)) ||
                  (headers && headers["x-webhook-secret"]) || "";
  if (!candidato) return false;

  var a = Buffer.from(String(candidato), "utf8");
  var b = Buffer.from(config.CAKTO_WEBHOOK_SECRET, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function eventoPago(tipo, status) {
  return CAKTO.eventosPagos.indexOf(tipo) !== -1 || status === "paid";
}

function eventoCancelado(tipo, status) {
  return CAKTO.eventosCancelados.indexOf(tipo) !== -1 ||
         status === "refunded" || status === "canceled";
}

module.exports = {
  CAKTO, configurado, criarCobrancaMensal, webhookValido, eventoPago, eventoCancelado
};
