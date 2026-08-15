/**
 * Histórico de conversas e atendimento humano.
 */

import { api, $, el, trocar, vazio, recado, quando, horaCurta, telefoneBonito, iniciais } from "./base.js";

var conversas = [];
var aberta = null;

export async function carregarConversas() {
  var busca = $("busca-conversas").value.trim();
  conversas = await api("GET", "/conversas?limite=60" + (busca ? "&busca=" + encodeURIComponent(busca) : ""));
  desenharLista();

  // Se a conversa aberta ainda está na lista, recarrega — é o que faz o
  // botão "Atualizar" trazer as mensagens novas sem fechar o que estava
  // sendo lido.
  if (aberta && conversas.some(function (c) { return c.id === aberta; })) {
    await abrirConversa(aberta);
  }
}

function desenharLista() {
  var lista = $("lista-conversas");

  if (!conversas.length) {
    trocar(lista, [el("li", {}, [vazio("💬", "Nenhuma conversa por aqui ainda.")])]);
    return;
  }

  trocar(lista, conversas.map(function (c) {
    return el("li", {
      classe: "item-clicavel" + (aberta === c.id ? " selecionado" : ""),
      aoClicar: function () { abrirConversa(c.id); }
    }, [
      el("div", { classe: "avatar", texto: iniciais(c.contato_nome || c.telefone) }),
      el("div", { classe: "item-corpo" }, [
        el("div", { classe: "item-titulo", texto: c.contato_nome || telefoneBonito(c.telefone) }),
        el("div", { classe: "item-linha", texto: (c.ultima_direcao === "saida" ? "→ " : "") + (c.ultima_mensagem || "") })
      ]),
      el("div", { estilo: "text-align:right;flex-shrink:0" }, [
        el("div", { classe: "fraco", texto: quando(c.ultima_interacao_em) }),
        c.status === "humano" ? el("span", { classe: "selo esperando", texto: "atendente" }) : null
      ])
    ]);
  }));
}

async function abrirConversa(id) {
  aberta = id;
  desenharLista();

  var dados = await api("GET", "/conversas/" + id);
  var c = dados.conversa;

  $("conversa-titulo").textContent = c.contato_nome || telefoneBonito(c.telefone);
  $("conversa-estado").textContent =
    telefoneBonito(c.telefone) + " · " +
    (c.status === "humano" ? "com atendente" : c.status === "encerrada" ? "encerrada" : "com o bot") +
    (c.bloco_chave ? " · em “" + c.bloco_chave + "”" : "");

  desenharAcoes(c);
  desenharMensagens(dados.mensagens);

  // Responder só faz sentido com a conversa nas mãos de uma pessoa: com
  // o bot no comando, a resposta manual e a automática sairiam
  // atropelando uma à outra na tela do cliente.
  $("forma-responder").classList.toggle("oculto", c.status !== "humano");
}

function desenharAcoes(c) {
  var acoes = [];

  if (c.status !== "humano") {
    acoes.push(el("button", { classe: "botao pequeno", texto: "Assumir conversa",
      aoClicar: function () { mudarEstado(c.id, "assumir", "Conversa assumida. O bot está calado."); } }));
  } else {
    acoes.push(el("button", { classe: "botao neutro pequeno", texto: "Devolver ao bot",
      aoClicar: function () { mudarEstado(c.id, "devolver", "Devolvida ao bot."); } }));
  }

  if (c.status !== "encerrada") {
    acoes.push(el("button", { classe: "botao discreto pequeno", texto: "Encerrar",
      aoClicar: function () { mudarEstado(c.id, "encerrar", "Conversa encerrada."); } }));
  }

  trocar($("acoes-conversa"), acoes);
}

async function mudarEstado(id, acao, aviso) {
  try {
    await api("POST", "/conversas/" + id + "/" + acao, {});
    await carregarConversas();
    await abrirConversa(id);
    recado(aviso, "bom");
  } catch (e) {
    recado(e.message, "ruim");
  }
}

function desenharMensagens(mensagens) {
  var caixa = $("mensagens");

  if (!mensagens.length) {
    trocar(caixa, [vazio("✉️", "Sem mensagens nesta conversa.")]);
    return;
  }

  trocar(caixa, mensagens.map(function (m) {
    var falhou = m.status === "falha";

    return el("div", {
      classe: "balao " + (m.direcao === "entrada" ? "deles" : "nossa") + (falhou ? " falhou" : ""),
      title: falhou ? (m.erro || "não entregue") : ""
    }, [
      // Anexo chega sem texto: dizer o tipo é melhor que um balão vazio,
      // que parece defeito da tela.
      document.createTextNode(m.texto || "[" + (m.tipo || "anexo") + "]"),
      el("div", { classe: "hora-balao",
        texto: horaCurta(m.criado_em) + (falhou ? " · não entregue" : "") })
    ]);
  }));

  caixa.scrollTop = caixa.scrollHeight;
}

$("forma-responder").addEventListener("submit", async function (e) {
  e.preventDefault();

  var texto = $("texto-resposta").value.trim();
  if (!texto || !aberta) return;

  var conversa = conversas.find(function (c) { return c.id === aberta; });
  if (!conversa) return;

  $("texto-resposta").value = "";

  try {
    await api("POST", "/whatsapp/enviar", { telefone: conversa.telefone, texto: texto });
    await abrirConversa(aberta);
  } catch (erro) {
    recado(erro.message, "ruim");
    // Devolve o texto ao campo: perder o que a pessoa escreveu porque o
    // envio falhou é obrigá-la a digitar tudo de novo, no pior momento.
    $("texto-resposta").value = texto;
  }
});

$("atualizar-conversas").addEventListener("click", function () {
  carregarConversas().catch(function (e) { recado(e.message, "ruim"); });
});

var esperaBusca = null;
$("busca-conversas").addEventListener("input", function () {
  // Espera a pessoa parar de digitar: uma consulta por tecla faria 20
  // requisições para achar um contato.
  clearTimeout(esperaBusca);
  esperaBusca = setTimeout(function () {
    carregarConversas().catch(function (e) { recado(e.message, "ruim"); });
  }, 350);
});
