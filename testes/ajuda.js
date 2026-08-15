"use strict";

/**
 * Ferramentas da suíte: registro de casos, verificações e um cliente
 * HTTP mínimo.
 *
 * Sem framework de teste de propósito. O projeto tem quatro dependências
 * e nenhuma etapa de build; acrescentar um runner com plugins para rodar
 * 60 verificações seria a maior dependência da árvore existindo só para
 * imprimir ✓ e ✗.
 */

var http = require("http");

var casos = [];

/** Registra um caso. Chamado no topo de cada arquivo .teste.js. */
function teste(grupo, nome, fn) {
  casos.push({ grupo: grupo, nome: nome, fn: fn });
}

function todos() { return casos; }

// ════════════════════════════════════════
// VERIFICAÇÕES
// ════════════════════════════════════════
// Cada uma lança com uma mensagem que diz o que se esperava E o que
// veio. Um "assertion failed" sem os dois valores obriga a reproduzir o
// teste na mão para descobrir o que aconteceu.

class FalhaDeTeste extends Error {}

function verdade(condicao, mensagem) {
  if (!condicao) throw new FalhaDeTeste(mensagem || "esperava verdadeiro");
}

function igual(obtido, esperado, mensagem) {
  if (obtido !== esperado) {
    throw new FalhaDeTeste((mensagem ? mensagem + " — " : "") +
      "esperava " + JSON.stringify(esperado) + ", veio " + JSON.stringify(obtido));
  }
}

function contem(texto, trecho, mensagem) {
  var t = String(texto == null ? "" : texto);
  if (t.indexOf(trecho) === -1) {
    throw new FalhaDeTeste((mensagem ? mensagem + " — " : "") +
      "esperava encontrar " + JSON.stringify(trecho) + " em " + JSON.stringify(t.slice(0, 200)));
  }
}

function naoContem(texto, trecho, mensagem) {
  var t = String(texto == null ? "" : texto);
  if (t.indexOf(trecho) !== -1) {
    throw new FalhaDeTeste((mensagem ? mensagem + " — " : "") +
      "NÃO esperava encontrar " + JSON.stringify(trecho));
  }
}

/** Espera que a função lance. Usado para conferir validações. */
async function lanca(fn, mensagem) {
  try {
    await fn();
  } catch (e) {
    return e;
  }
  throw new FalhaDeTeste(mensagem || "esperava que lançasse, mas não lançou");
}

// ════════════════════════════════════════
// CLIENTE HTTP
// ════════════════════════════════════════
/**
 * Chama o servidor de teste por HTTP de verdade, em 127.0.0.1.
 *
 * Não chama as funções das rotas direto de propósito: por fora, o pedido
 * passa pelo roteamento, pelos cabeçalhos, pelo parser de corpo, pelo
 * rate limit e pelo portão de autenticação — que é exatamente onde mora
 * o defeito mais caro possível, a rota que esqueceu de exigir login.
 */
function criarCliente(porta) {
  function pedir(metodo, caminho, corpo, token, cabecalhosExtra) {
    return new Promise(function (resolver, rejeitar) {
      var dados = corpo === undefined || corpo === null ? null : JSON.stringify(corpo);
      var cabecalhos = Object.assign({}, cabecalhosExtra || {});
      if (dados) {
        cabecalhos["Content-Type"] = "application/json";
        cabecalhos["Content-Length"] = Buffer.byteLength(dados);
      }
      if (token) cabecalhos["Authorization"] = "Bearer " + token;

      var req = http.request({
        hostname: "127.0.0.1", port: porta, path: caminho, method: metodo, headers: cabecalhos
      }, function (res) {
        var cru = "";
        res.on("data", function (c) { cru += c; });
        res.on("end", function () {
          var json = null;
          try { json = JSON.parse(cru); } catch (e) { /* resposta de texto puro (webhook) */ }
          resolver({ status: res.statusCode, corpo: json, texto: cru, cabecalhos: res.headers });
        });
      });
      req.on("error", rejeitar);
      req.setTimeout(15000, function () { req.destroy(new Error("tempo esgotado em " + caminho)); });
      if (dados) req.write(dados);
      req.end();
    });
  }

  return {
    get:    function (c, t) { return pedir("GET", c, null, t); },
    post:   function (c, b, t, h) { return pedir("POST", c, b, t, h); },
    put:    function (c, b, t) { return pedir("PUT", c, b, t); },
    delete: function (c, t) { return pedir("DELETE", c, null, t); },
    cru:    pedir
  };
}

/**
 * Cria uma conta nova e devolve o token dela.
 *
 * Cada caso usa uma conta própria, com e-mail sorteado. É o que permite
 * rodar a suíte inteira sem limpar o banco entre casos — e, de quebra, é
 * a checagem contínua de que os dados de uma conta não escorrem para a
 * outra, porque todas as contas dos testes convivem no mesmo banco.
 */
async function criarConta(cliente, prefixo) {
  var email = (prefixo || "teste") + "-" + Date.now() + "-" +
              Math.random().toString(36).slice(2, 8) + "@exemplo.com";

  var r = await cliente.post("/api/cadastro", {
    nome: "Dona da Loja",
    empresa: "Loja " + (prefixo || "Teste"),
    email: email,
    senha: "senha-de-teste-123"
  });

  if (r.status !== 201) {
    throw new FalhaDeTeste("não consegui criar a conta de teste: " +
      r.status + " " + JSON.stringify(r.corpo));
  }
  return { token: r.corpo.token, email: email, senha: "senha-de-teste-123", conta: r.corpo.conta };
}

/**
 * Conecta o WhatsApp de uma conta de ponta a ponta: cadastra as
 * credenciais e faz a Meta "verificar" o webhook.
 *
 * Percorre o mesmo caminho do cliente real — inclusive a chamada GET no
 * webhook com o hub.challenge — para que os testes que dependem de uma
 * conexão pronta não a fabriquem direto no banco. Fabricar no banco
 * passaria por cima justamente do passo que costuma quebrar.
 */
var contadorNumero = 0;

async function conectarWhatsapp(ctx, token, phoneId) {
  // Cada conta recebe um número PRÓPRIO, sorteado, e registrado na Meta
  // falsa na hora. Reaproveitar um número fixo entre os casos esbarraria
  // na regra real da plataforma — um phone_number_id pertence a uma só
  // conta, porque é por ele que o webhook descobre o dono da mensagem.
  if (!phoneId) {
    contadorNumero++;
    phoneId = String(900000000000000 + contadorNumero);
  }
  if (!ctx.meta.numeros[phoneId]) {
    ctx.meta.numeros[phoneId] = {
      display_phone_number: "+55 11 9" + String(contadorNumero).padStart(4, "0") + "-0000",
      verified_name: "Loja Teste " + contadorNumero
    };
  }

  var cliente = ctx.cliente;
  var r = await cliente.post("/api/whatsapp/conexao", {
    phone_number_id: phoneId,
    token: "token-bom",
    app_secret: "segredo-do-app"
  }, token);

  if (r.status !== 200) {
    throw new FalhaDeTeste("conexão falhou: " + r.status + " " + JSON.stringify(r.corpo));
  }

  var verify = r.corpo.verify_token;
  var v = await cliente.get("/webhook?hub.mode=subscribe&hub.verify_token=" +
                            encodeURIComponent(verify) + "&hub.challenge=desafio123");
  if (v.status !== 200 || v.texto !== "desafio123") {
    throw new FalhaDeTeste("verificação do webhook falhou: " + v.status + " " + v.texto);
  }

  return Object.assign({}, r.corpo, { phone_number_id: phoneId });
}

/**
 * Monta o payload de webhook que a Meta manda quando alguém escreve.
 *
 * Com a mesma forma do real (entry → changes → value → messages), porque
 * é essa forma que o extrator do sistema desembrulha. Um payload
 * simplificado testaria um caminho que não existe em produção.
 */
var contadorWamid = 0;
function webhookMensagem(phoneId, de, texto, nome) {
  contadorWamid++;
  return {
    object: "whatsapp_business_account",
    entry: [{
      id: "waba-teste",
      changes: [{
        field: "messages",
        value: {
          messaging_product: "whatsapp",
          metadata: { display_phone_number: "5511900000000", phone_number_id: phoneId },
          contacts: [{ profile: { name: nome || "Cliente Teste" }, wa_id: de }],
          messages: [{
            from: de,
            id: "wamid.entrada" + contadorWamid,
            timestamp: String(Math.floor(Date.now() / 1000)),
            type: "text",
            text: { body: texto }
          }]
        }
      }]
    }]
  };
}

/** Webhook de toque em botão — o formato que a Meta usa, diferente de texto. */
function webhookBotao(phoneId, de, rotulo) {
  contadorWamid++;
  return {
    object: "whatsapp_business_account",
    entry: [{
      id: "waba-teste",
      changes: [{
        field: "messages",
        value: {
          messaging_product: "whatsapp",
          metadata: { phone_number_id: phoneId },
          contacts: [{ profile: { name: "Cliente Teste" }, wa_id: de }],
          messages: [{
            from: de,
            id: "wamid.entrada" + contadorWamid,
            timestamp: String(Math.floor(Date.now() / 1000)),
            type: "interactive",
            interactive: { type: "button_reply", button_reply: { id: "op_0", title: rotulo } }
          }]
        }
      }]
    }]
  };
}

/** Assinatura X-Hub-Signature-256, como a Meta calcula. */
function assinar(corpo, segredo) {
  var crypto = require("crypto");
  return "sha256=" + crypto.createHmac("sha256", segredo)
    .update(JSON.stringify(corpo), "utf8").digest("hex");
}

module.exports = {
  teste, todos, FalhaDeTeste,
  verdade, igual, contem, naoContem, lanca,
  criarCliente, criarConta, conectarWhatsapp,
  webhookMensagem, webhookBotao, assinar
};
