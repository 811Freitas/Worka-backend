"use strict";

/**
 * Cliente da WhatsApp Cloud API (Graph API da Meta).
 *
 * Único lugar do projeto que fala com a Meta. Todo o resto do sistema
 * conhece "enviarTexto" e "verificarNumero" — não conhece URL, versão da
 * API nem formato de payload. Quando a Meta mudar alguma coisa (e ela
 * muda), o conserto é aqui, uma vez.
 */

var https = require("https");
var http = require("http");
var crypto = require("crypto");
var config = require("../../config");

/**
 * Chamada crua à Graph API.
 *
 * Resolve SEMPRE — nunca rejeita. Falha de rede vira
 * `{ status: 0, erro: "..." }`, porque quem chama está no meio de
 * responder a um cliente e precisa decidir o que fazer, não receber uma
 * exceção para propagar.
 */
function chamarGraph(metodo, caminho, corpo, token) {
  return new Promise(function (resolver) {
    var dados = corpo ? JSON.stringify(corpo) : null;
    var partesHost = String(config.GRAPH_HOST).split(":");
    var inseguro = config.GRAPH_PROTOCOLO === "http";
    var transporte = inseguro ? http : https;

    var cabecalhos = { "Authorization": "Bearer " + token };
    if (dados) {
      cabecalhos["Content-Type"] = "application/json";
      cabecalhos["Content-Length"] = Buffer.byteLength(dados);
    }

    var pedido = transporte.request({
      hostname: partesHost[0],
      port: partesHost[1] ? parseInt(partesHost[1], 10) : (inseguro ? 80 : 443),
      path: "/" + config.GRAPH_VERSAO + caminho,
      method: metodo,
      headers: cabecalhos
    }, function (resposta) {
      var cru = "";
      resposta.on("data", function (c) { cru += c; });
      resposta.on("end", function () {
        var json = null;
        try { json = JSON.parse(cru); } catch (e) { /* resposta não-JSON: fica no `cru` */ }
        resolver({ status: resposta.statusCode, json: json, cru: cru });
      });
    });

    pedido.on("error", function (e) {
      resolver({ status: 0, erro: e.message, json: null, cru: "" });
    });

    // Sem teto de tempo, uma chamada presa segura o processamento do
    // webhook até a Meta desistir e REENVIAR o evento — e aí a mesma
    // mensagem é respondida duas vezes.
    pedido.setTimeout(15000, function () {
      pedido.destroy();
      resolver({ status: 0, erro: "tempo esgotado ao falar com a Meta", json: null, cru: "" });
    });

    if (dados) pedido.write(dados);
    pedido.end();
  });
}

/**
 * Traduz o erro da Meta para uma frase que o dono da conta entende, e
 * diz se o problema é PERMANENTE (precisa de ação humana) ou passageiro.
 *
 * A distinção decide o comportamento do sistema: erro permanente marca a
 * conexão como quebrada e avisa o cliente; passageiro só registra e
 * tenta de novo depois. Tratar os dois igual produz ou alarme falso a
 * cada oscilação de rede, ou silêncio quando o token realmente morreu.
 */
function explicarErro(resposta) {
  if (resposta.status === 0) {
    return { permanente: false, mensagem: resposta.erro || "não foi possível falar com a Meta" };
  }

  var erro = (resposta.json && resposta.json.error) || {};
  var codigo = erro.code;
  var subcodigo = erro.error_subcode;

  // 190 = token inválido/expirado/revogado. É o erro nº 1 na prática:
  // quem gera um token TEMPORÁRIO no painel da Meta (o padrão da tela)
  // descobre 24h depois que o bot parou.
  if (codigo === 190 || resposta.status === 401) {
    return {
      permanente: true,
      mensagem: "O token de acesso foi recusado pela Meta (expirado ou revogado). " +
                "Gere um token PERMANENTE em business.facebook.com e cole de novo em Conexão."
    };
  }

  // 10 e 200-299 são a família de permissão: o token existe mas não pode
  // usar este número.
  if (codigo === 10 || (codigo >= 200 && codigo <= 299) || resposta.status === 403) {
    return {
      permanente: true,
      mensagem: "O token não tem permissão para este número. Confira se o usuário do sistema " +
                "tem acesso à conta do WhatsApp Business e às permissões whatsapp_business_messaging " +
                "e whatsapp_business_management."
    };
  }

  if (codigo === 100 || resposta.status === 404) {
    return {
      permanente: true,
      mensagem: "A Meta não encontrou este número (Phone Number ID). Confira o valor copiado " +
                "do painel — é o ID do número, não o número em si."
    };
  }

  // 131056 = muitas mensagens para o mesmo destinatário; 80007 = limite
  // da conta. Ambos passam sozinhos.
  if (codigo === 131056 || codigo === 80007 || resposta.status === 429) {
    return { permanente: false, mensagem: "Limite de envio da Meta atingido. Vai normalizar sozinho." };
  }

  if (resposta.status >= 500) {
    return { permanente: false, mensagem: "A Meta está com instabilidade (erro " + resposta.status + ")." };
  }

  return {
    permanente: false,
    mensagem: erro.message
      ? erro.message + (subcodigo ? " (subcódigo " + subcodigo + ")" : "")
      : "erro " + resposta.status + " ao falar com a Meta"
  };
}

/**
 * Confere, contra a Meta, se as credenciais valem AGORA.
 *
 * É o que o botão "Conectar" e o monitor de saúde usam. Sem esta
 * checagem, "conectado" significaria apenas "o cliente preencheu o
 * formulário" — e o primeiro sinal de que nada funciona seria a
 * reclamação de um consumidor que ficou sem resposta.
 */
async function verificarNumero(phoneNumberId, token) {
  var r = await chamarGraph(
    "GET",
    "/" + encodeURIComponent(phoneNumberId) + "?fields=display_phone_number,verified_name,quality_rating",
    null,
    token
  );

  if (r.status === 200 && r.json && r.json.id) {
    return {
      ok: true,
      numero: r.json.display_phone_number || null,
      nome: r.json.verified_name || null,
      qualidade: r.json.quality_rating || null
    };
  }

  return Object.assign({ ok: false }, explicarErro(r));
}

/**
 * Monta o corpo da mensagem.
 *
 * A Cloud API tem três formatos, e escolher o errado faz a mensagem ser
 * recusada em vez de entregue:
 *   - até 3 opções  → botões (`interactive.button`), o melhor visual;
 *   - 4 a 10 opções → lista (`interactive.list`), o único que aceita mais de 3;
 *   - nenhuma opção → texto puro.
 *
 * O menu numerado no texto acompanha a lista de propósito. Quem usa
 * WhatsApp Web ou uma versão antiga às vezes não vê o componente
 * interativo — e sem o número escrito, a pessoa fica olhando para uma
 * mensagem sem saída.
 */
function montarMensagem(para, texto, opcoes) {
  opcoes = opcoes || [];

  if (opcoes.length === 0) {
    return { messaging_product: "whatsapp", to: para, type: "text",
             text: { body: texto.slice(0, 4096), preview_url: false } };
  }

  if (opcoes.length <= 3) {
    return {
      messaging_product: "whatsapp", to: para, type: "interactive",
      interactive: {
        type: "button",
        body: { text: texto.slice(0, 1024) },
        action: {
          buttons: opcoes.map(function (op, i) {
            return {
              type: "reply",
              reply: {
                // O id volta no webhook quando a pessoa toca no botão.
                // Prefixado e com o índice para casar sem depender do
                // rótulo, que o cliente pode editar a qualquer momento.
                id: "op_" + i,
                title: op.rotulo.slice(0, 20)
              }
            };
          })
        }
      }
    };
  }

  var corpoNumerado = texto + "\n\n" + opcoes.map(function (op, i) {
    return (i + 1) + "️⃣ " + op.rotulo;
  }).join("\n");

  return {
    messaging_product: "whatsapp", to: para, type: "interactive",
    interactive: {
      type: "list",
      body: { text: corpoNumerado.slice(0, 1024) },
      action: {
        button: "Ver opções",
        sections: [{
          title: "Escolha",
          rows: opcoes.map(function (op, i) {
            return { id: "op_" + i, title: op.rotulo.slice(0, 24) };
          })
        }]
      }
    }
  };
}

/**
 * Envia uma mensagem. Devolve { ok, wa_id } ou { ok:false, permanente, mensagem }.
 */
async function enviar(conexao, para, texto, opcoes, token) {
  var corpo = montarMensagem(para, texto, opcoes);
  var r = await chamarGraph(
    "POST",
    "/" + encodeURIComponent(conexao.phone_number_id) + "/messages",
    corpo,
    token
  );

  if (r.status === 200 && r.json && r.json.messages && r.json.messages[0]) {
    return { ok: true, wa_id: r.json.messages[0].id };
  }
  return Object.assign({ ok: false }, explicarErro(r));
}

/**
 * Marca a mensagem recebida como lida (os dois tiques azuis).
 *
 * Cosmético, e ainda assim vale: sem isso a conversa fica com a mensagem
 * do cliente eternamente "entregue mas não lida" enquanto o bot já
 * respondeu — o que parece defeito. Falha aqui é ignorada de propósito:
 * é enfeite, não pode atrapalhar a resposta.
 */
function marcarLida(conexao, waId, token) {
  return chamarGraph("POST", "/" + encodeURIComponent(conexao.phone_number_id) + "/messages", {
    messaging_product: "whatsapp", status: "read", message_id: waId
  }, token).catch(function () { return null; });
}

/**
 * Confere a assinatura X-Hub-Signature-256 do webhook.
 *
 * Sem isto, a URL do webhook é um endereço público onde qualquer pessoa
 * pode POSTar "o cliente 5511... mandou tal mensagem" e fazer o bot
 * responder, gastar cota da Meta e sujar o histórico. A assinatura prova
 * que o corpo veio de quem tem o app secret.
 *
 * Exige o corpo CRU, byte a byte: JSON.parse + JSON.stringify muda
 * espaçamento e ordem de chaves, e o HMAC do texto reserializado nunca
 * confere. É por isso que o Express deste projeto guarda o corpo cru
 * na rota do webhook.
 */
function assinaturaValida(corpoCru, cabecalho, appSecret) {
  if (!appSecret) {
    // Sem app secret cadastrado não há como verificar. Devolver `true`
    // aqui seria transformar "não sei" em "está tudo bem" — a decisão de
    // aceitar mesmo assim é de quem chama, e ela é registrada no log.
    return null;
  }
  if (typeof cabecalho !== "string" || !cabecalho.startsWith("sha256=")) return false;

  var esperada = "sha256=" + crypto.createHmac("sha256", appSecret)
    .update(corpoCru, "utf8").digest("hex");

  var a = Buffer.from(esperada);
  var b = Buffer.from(cabecalho);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * Extrai o que interessa de um webhook de mensagem recebida.
 *
 * O payload da Meta é profundo (entry[].changes[].value.messages[]) e
 * cheio de campos opcionais. Desembrulhar aqui, uma vez, evita que o
 * resto do sistema tenha que se defender de `undefined` em cinco níveis.
 *
 * Devolve uma lista porque UM webhook pode trazer VÁRIAS mensagens —
 * acontece quando a Meta acumula durante uma instabilidade. Tratar só a
 * primeira perderia as outras, silenciosamente.
 */
function extrairMensagens(corpo) {
  var saida = [];
  var entradas = (corpo && corpo.entry) || [];

  for (var entrada of entradas) {
    for (var mudanca of (entrada.changes || [])) {
      var valor = mudanca.value || {};
      var metadados = valor.metadata || {};
      var perfis = valor.contacts || [];

      for (var msg of (valor.messages || [])) {
        var perfil = perfis.find(function (c) { return c.wa_id === msg.from; }) || perfis[0];

        saida.push({
          phone_number_id: metadados.phone_number_id || null,
          de: msg.from,
          wa_id: msg.id,
          tipo: msg.type,
          nome: (perfil && perfil.profile && perfil.profile.name) || null,
          // Toque em botão e escolha de lista chegam em lugares
          // diferentes do payload. Normalizados para texto aqui, o motor
          // trata os três casos como "a pessoa escreveu isto" — e é por
          // isso que o rótulo do botão casa com a opção do menu.
          texto: textoDaMensagem(msg),
          bruto: msg
        });
      }
    }
  }
  return saida;
}

function textoDaMensagem(msg) {
  if (msg.type === "text") return (msg.text && msg.text.body) || "";

  if (msg.type === "interactive") {
    var inter = msg.interactive || {};
    if (inter.button_reply) return inter.button_reply.title || "";
    if (inter.list_reply) return inter.list_reply.title || "";
    return "";
  }

  // Botão de template (formato antigo, ainda em uso).
  if (msg.type === "button") return (msg.button && msg.button.text) || "";

  // Áudio, imagem, documento, localização, figurinha. O motor é de
  // texto: devolver string vazia o levaria ao fallback ("não entendi"),
  // que é exatamente a resposta certa — e a mensagem original fica
  // gravada no histórico para o atendente humano ver.
  return "";
}

/** Recibos de entrega/leitura das mensagens que NÓS enviamos. */
function extrairStatus(corpo) {
  var saida = [];
  for (var entrada of ((corpo && corpo.entry) || [])) {
    for (var mudanca of (entrada.changes || [])) {
      for (var st of ((mudanca.value || {}).statuses || [])) {
        saida.push({
          wa_id: st.id,
          status: st.status,               // sent | delivered | read | failed
          erro: (st.errors && st.errors[0] && st.errors[0].title) || null
        });
      }
    }
  }
  return saida;
}

module.exports = {
  chamarGraph, verificarNumero, enviar, marcarLida, montarMensagem,
  assinaturaValida, extrairMensagens, extrairStatus, explicarErro
};
