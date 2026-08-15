/**
 * Ferramentas usadas por todas as telas: cliente da API, construção de
 * elementos e recados.
 */

// ════════════════════════════════════════
// SESSÃO
// ════════════════════════════════════════
// localStorage e não cookie: a API é sem estado e autentica por
// `Authorization: Bearer`. Um cookie de sessão exigiria proteção contra
// CSRF em toda rota que escreve — complexidade que só faria sentido se o
// token precisasse ser enviado pelo navegador automaticamente, que não é
// o caso aqui.
var CHAVE_TOKEN = "zapfy.token";

export function pegarToken() { return localStorage.getItem(CHAVE_TOKEN); }
export function guardarToken(t) { localStorage.setItem(CHAVE_TOKEN, t); }
export function limparToken() { localStorage.removeItem(CHAVE_TOKEN); }

// ════════════════════════════════════════
// API
// ════════════════════════════════════════
/**
 * Chama a API e devolve o corpo já em objeto.
 *
 * Lança em qualquer resposta que não seja 2xx, com a mensagem QUE O
 * SERVIDOR escreveu. É o que faz um erro de validação chegar ao usuário
 * como "Cole o token de acesso permanente" em vez de "erro 400".
 */
export async function api(metodo, caminho, corpo) {
  var opcoes = { method: metodo, headers: {} };

  var token = pegarToken();
  if (token) opcoes.headers["Authorization"] = "Bearer " + token;

  if (corpo !== undefined && corpo !== null) {
    opcoes.headers["Content-Type"] = "application/json";
    opcoes.body = JSON.stringify(corpo);
  }

  var resposta = await fetch("/api" + caminho, opcoes);

  var dados = null;
  try { dados = await resposta.json(); } catch (e) { /* 204 ou corpo vazio */ }

  if (resposta.status === 401) {
    // Token vencido ou revogado. Levar de volta para a entrada é a única
    // saída útil: qualquer outra tela vai continuar dando 401 em tudo.
    limparToken();
    location.reload();
    throw new Error("Sessão expirada");
  }

  if (!resposta.ok) {
    throw new Error((dados && dados.erro) || "Não consegui falar com o servidor.");
  }

  return dados;
}

// ════════════════════════════════════════
// DOM
// ════════════════════════════════════════
export function $(id) { return document.getElementById(id); }

/**
 * Cria um elemento.
 *
 * Texto entra SEMPRE por textContent, nunca por innerHTML. É a linha de
 * defesa que importa: mensagem de bot, nome de contato e texto de
 * conversa são escritos por terceiros, e nenhum deles pode virar HTML na
 * origem do painel.
 */
export function el(tag, atributos, filhos) {
  var no = document.createElement(tag);

  for (var chave in (atributos || {})) {
    var valor = atributos[chave];
    if (valor === null || valor === undefined || valor === false) continue;

    if (chave === "texto") no.textContent = valor;
    else if (chave === "classe") no.className = valor;
    else if (chave === "aoClicar") no.addEventListener("click", valor);
    else if (chave === "estilo") no.setAttribute("style", valor);
    else if (chave.indexOf("dados-") === 0) no.dataset[chave.slice(6)] = valor;
    else no.setAttribute(chave, valor);
  }

  for (var filho of (filhos || [])) {
    if (filho === null || filho === undefined || filho === false) continue;
    no.appendChild(typeof filho === "string" ? document.createTextNode(filho) : filho);
  }
  return no;
}

export function limpar(no) { while (no.firstChild) no.removeChild(no.firstChild); }

export function trocar(no, filhos) {
  limpar(no);
  for (var f of filhos) if (f) no.appendChild(f);
}

export function vazio(emoji, texto) {
  return el("div", { classe: "vazio" }, [
    el("span", { classe: "emoji", texto: emoji }),
    el("div", { texto: texto })
  ]);
}

// ════════════════════════════════════════
// RECADOS
// ════════════════════════════════════════
export function recado(texto, tipo) {
  var caixa = $("recados");
  var no = el("div", { classe: "recado " + (tipo || ""), texto: texto });
  caixa.appendChild(no);
  setTimeout(function () { no.remove(); }, tipo === "ruim" ? 6000 : 3500);
}

/**
 * Deixa o botão ocupado durante uma ação de rede e o restaura depois.
 *
 * Existe por um motivo concreto: um botão que fica igual por três
 * segundos é indistinguível de um botão quebrado, e a pessoa clica de
 * novo — disparando a ação duas vezes. Aqui ele fica desabilitado e diz
 * o que está acontecendo.
 */
export async function ocupado(botao, rotulo, acao) {
  if (!botao) return acao();

  var original = botao.textContent;
  botao.disabled = true;
  botao.textContent = rotulo || "Aguarde...";

  try {
    return await acao();
  } finally {
    botao.disabled = false;
    botao.textContent = original;
  }
}

// ════════════════════════════════════════
// FORMATOS
// ════════════════════════════════════════
export function quando(iso) {
  if (!iso) return "";
  var data = new Date(iso);
  var minutos = (Date.now() - data.getTime()) / 60000;

  if (minutos < 1) return "agora";
  if (minutos < 60) return Math.floor(minutos) + " min";
  if (minutos < 60 * 24) return Math.floor(minutos / 60) + "h";
  if (minutos < 60 * 24 * 7) return Math.floor(minutos / 1440) + "d";

  return data.toLocaleDateString("pt-BR", { day: "2-digit", month: "2-digit" });
}

export function horaCurta(iso) {
  if (!iso) return "";
  return new Date(iso).toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" });
}

export function dataHora(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("pt-BR", {
    day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit"
  });
}

/** Telefone só com dígitos vira algo legível: 5511987654321 → +55 11 98765-4321 */
export function telefoneBonito(numero) {
  var d = String(numero || "").replace(/\D/g, "");
  var m = /^(\d{2})(\d{2})(\d{4,5})(\d{4})$/.exec(d);
  return m ? "+" + m[1] + " " + m[2] + " " + m[3] + "-" + m[4] : (numero || "");
}

export function iniciais(texto) {
  var limpo = String(texto || "?").trim();
  return limpo.charAt(0).toUpperCase() || "?";
}

/** Rótulo e classe de cada estado de conexão, num lugar só. */
export var ESTADOS = {
  conectado:          { rotulo: "conectado",        classe: "ligado" },
  aguardando_webhook: { rotulo: "falta o webhook",  classe: "esperando" },
  pausado:            { rotulo: "pausado",          classe: "esperando" },
  erro:               { rotulo: "com problema",     classe: "erro" },
  desconectado:       { rotulo: "desconectado",     classe: "parado" }
};

export function pintarSelo(no, status) {
  if (!no) return;
  var estado = ESTADOS[status] || ESTADOS.desconectado;
  no.className = "selo " + estado.classe;
  no.textContent = estado.rotulo;
}
