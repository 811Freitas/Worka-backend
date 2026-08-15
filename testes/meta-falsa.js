"use strict";

/**
 * Uma Meta de mentira.
 *
 * Servidor HTTP que responde como a Graph API responde. A suíte aponta
 * GRAPH_HOST para cá e, a partir daí, TODO o caminho real é exercitado:
 * o cliente da Cloud API monta o payload de verdade, faz a requisição de
 * verdade, e o sistema trata a resposta de verdade.
 *
 * A alternativa — substituir o módulo cloud-api por um dublê — testaria
 * o teste. O formato do payload enviado à Meta, que é onde os erros
 * moram (botão com mais de 3 opções, campo com nome errado), passaria
 * batido.
 *
 * Além de responder, ela GUARDA tudo que recebeu. É assim que os casos
 * verificam "o bot respondeu com estes três botões" olhando o que
 * chegaria à Meta, e não uma variável interna do sistema.
 */

var http = require("http");

function criarMetaFalsa() {
  var estado = {
    // Mensagens que o sistema mandou. A lista que os testes leem.
    enviadas: [],
    // Tokens aceitos. Qualquer outro leva ao erro 190 (token inválido),
    // que é o mesmo código que a Meta usa — e é o que o sistema traduz
    // para "gere um token permanente".
    tokensValidos: new Set(["token-bom"]),
    numeros: {
      "111222333444555": { display_phone_number: "+55 11 90000-0000", verified_name: "Loja Teste" }
    },
    // Ligado por um teste para simular instabilidade da Meta (erro 500),
    // que o sistema deve tratar como passageiro — sem derrubar a conexão.
    forcarInstabilidade: false,
    porta: null
  };

  var servidor = http.createServer(function (req, res) {
    var corpo = "";
    req.on("data", function (c) { corpo += c; });
    req.on("end", function () {
      var url = new URL(req.url, "http://local");
      var partes = url.pathname.split("/").filter(Boolean);   // [versao, phoneId, 'messages'?]
      var autorizacao = req.headers.authorization || "";
      var token = autorizacao.replace(/^Bearer\s+/, "");

      function responder(status, obj) {
        res.writeHead(status, { "Content-Type": "application/json" });
        res.end(JSON.stringify(obj));
      }

      if (estado.forcarInstabilidade) {
        return responder(500, { error: { message: "Internal server error", code: 1 } });
      }

      if (!estado.tokensValidos.has(token)) {
        return responder(401, {
          error: {
            message: "Error validating access token: Session has expired",
            type: "OAuthException", code: 190
          }
        });
      }

      var phoneId = partes[1];
      if (!estado.numeros[phoneId]) {
        return responder(404, {
          error: { message: "Unsupported get request. Object does not exist", code: 100 }
        });
      }

      // POST /{phoneId}/messages
      if (req.method === "POST" && partes[2] === "messages") {
        var payload = {};
        try { payload = JSON.parse(corpo); } catch (e) { /* payload inválido cai na checagem abaixo */ }

        // Marcar como lida não é envio de mensagem: entra pelo mesmo
        // endereço, e sem esta separação os recibos poluiriam a lista
        // que os testes conferem.
        if (payload.status === "read") return responder(200, { success: true });

        if (!payload.messaging_product || !payload.to) {
          return responder(400, { error: { message: "(#100) Missing parameter", code: 100 } });
        }
        // A Meta recusa mais de 3 botões. Reproduzido aqui de propósito:
        // é o erro que um menu com 4 opções causaria em produção, e o
        // teste tem que pegar isso.
        if (payload.type === "interactive" &&
            payload.interactive.type === "button" &&
            payload.interactive.action.buttons.length > 3) {
          return responder(400, { error: { message: "(#131009) Parameter value is not valid", code: 131009 } });
        }

        var waId = "wamid.saida" + (estado.enviadas.length + 1);
        estado.enviadas.push({ para: payload.to, payload: payload, wa_id: waId });
        return responder(200, {
          messaging_product: "whatsapp",
          contacts: [{ wa_id: payload.to }],
          messages: [{ id: waId }]
        });
      }

      // GET /{phoneId}
      if (req.method === "GET") {
        return responder(200, Object.assign(
          { id: phoneId, quality_rating: "GREEN" }, estado.numeros[phoneId]
        ));
      }

      responder(404, { error: { message: "Unknown route", code: 100 } });
    });
  });

  estado.iniciar = function () {
    return new Promise(function (resolver) {
      servidor.listen(0, "127.0.0.1", function () {
        estado.porta = servidor.address().port;
        resolver(estado.porta);
      });
    });
  };

  estado.parar = function () {
    return new Promise(function (resolver) { servidor.close(resolver); });
  };

  /** Só o texto de cada mensagem enviada — o formato mais usado nos casos. */
  estado.textos = function () {
    return estado.enviadas.map(function (m) {
      var p = m.payload;
      if (p.type === "text") return p.text.body;
      if (p.type === "interactive") return p.interactive.body.text;
      return "";
    });
  };

  estado.limpar = function () {
    estado.enviadas = [];
    estado.forcarInstabilidade = false;
  };

  return estado;
}

module.exports = { criarMetaFalsa };
