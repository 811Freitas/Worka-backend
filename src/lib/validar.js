"use strict";

/**
 * Validação e normalização de tudo que entra pela API.
 *
 * A regra do arquivo: cada função devolve o valor LIMPO ou `null`. Nunca
 * "corrige" silenciosamente para um valor plausível — um telefone
 * inválido que vira um telefone válido diferente manda a mensagem para
 * um estranho.
 */

var LIMITES = {
  nome: 120,
  email: 254,
  mensagem: 4096,     // teto da Cloud API para corpo de texto
  chave: 40,
  titulo: 80,
  rotulo: 24,         // teto de um botão interativo na Cloud API
  gatilho: 40
};

/**
 * Texto livre.
 *
 * Note o que NÃO é feito aqui: escapar `<` e `>`. Este projeto não
 * remove HTML na entrada porque isso corromperia mensagens legítimas
 * ("promoção < R$ 50"). O escape acontece na SAÍDA, no painel, que usa
 * exclusivamente textContent — escapar nos dois lados é o caminho certo
 * para dado gravado com `&lt;` aparecendo literalmente na tela do
 * cliente.
 */
function texto(v, max) {
  if (typeof v !== "string") return null;
  var limpo = v.trim();
  if (limpo === "") return null;
  // Caracteres de controle (exceto \n e \t) não existem em texto digitado
  // por gente: são resto de copiar-colar ou tentativa de quebrar log.
  limpo = limpo.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  return limpo.slice(0, max || LIMITES.mensagem);
}

/** Igual a texto(), mas string vazia é resposta válida (campo opcional). */
function textoOpcional(v, max) {
  if (v === null || v === undefined) return "";
  if (typeof v !== "string") return null;
  return (texto(v, max) || "");
}

function email(v) {
  if (typeof v !== "string") return null;
  var limpo = v.trim().toLowerCase().slice(0, LIMITES.email);
  return /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/.test(limpo) ? limpo : null;
}

/**
 * Senha. Só piso de tamanho, sem exigência de símbolo/maiúscula.
 *
 * A regra "1 maiúscula, 1 número, 1 símbolo" é a que produz "Senha@123"
 * em massa. Comprimento é o que realmente importa, e é o que o NIST
 * recomenda desde 2017.
 */
function senha(v) {
  if (typeof v !== "string") return null;
  if (v.length < 8 || v.length > 200) return null;
  return v;
}

/**
 * Telefone no formato que a Cloud API usa: só dígitos, com DDI.
 *
 * O tratamento do 9º dígito brasileiro é o detalhe que decide se a
 * resposta chega. A Meta entrega o número do remetente BR sem o nono
 * dígito em celulares antigos ("5511987654321" vira "551187654321"), e
 * responder para o número tal como veio é o comportamento correto —
 * inventar um 9 manda para outro aparelho. Por isso aqui só normalizamos
 * a forma (tirar +, espaço, parênteses), nunca o conteúdo.
 */
function telefone(v) {
  if (typeof v !== "string" && typeof v !== "number") return null;
  var digitos = String(v).replace(/\D/g, "");
  // 8 é o mínimo plausível com DDI; 15 é o teto do padrão E.164.
  if (digitos.length < 8 || digitos.length > 15) return null;
  return digitos;
}

function uuid(v) {
  if (typeof v !== "string") return null;
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(v)
    ? v.toLowerCase() : null;
}

function booleano(v, padrao) {
  if (v === true || v === "true" || v === 1 || v === "1") return true;
  if (v === false || v === "false" || v === 0 || v === "0") return false;
  return padrao;
}

function inteiro(v, min, max, padrao) {
  var n = parseInt(v, 10);
  if (!Number.isFinite(n)) return padrao;
  if (n < min) return min;
  if (n > max) return max;
  return n;
}

function umDe(v, permitidos) {
  return permitidos.indexOf(v) === -1 ? null : v;
}

/**
 * Chave de bloco. Vira identificador dentro do fluxo, então só aceita o
 * que pode ser digitado e lido sem ambiguidade.
 */
function chave(v) {
  if (typeof v !== "string") return null;
  var limpo = v.trim().toLowerCase()
    .normalize("NFD").replace(/[\u0300-\u036f]/g, "")  // tira acento
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, LIMITES.chave);
  return limpo === "" ? null : limpo;
}

function horario(v) {
  if (typeof v !== "string") return null;
  var m = /^([01]\d|2[0-3]):([0-5]\d)$/.exec(v.trim());
  return m ? m[0] : null;
}

/**
 * Opções de um bloco de menu.
 *
 * O teto de 10 não é arbitrário: é o máximo de linhas que a Cloud API
 * aceita numa mensagem de lista. Aceitar 15 aqui produziria um bloco que
 * o cliente monta, salva, e que a Meta recusa na hora de enviar — erro
 * que aparece longe de onde foi causado.
 */
function opcoes(v) {
  if (!Array.isArray(v)) return null;
  if (v.length > 10) return null;

  var saida = [];
  for (var item of v) {
    if (!item || typeof item !== "object") return null;
    var rotulo = texto(item.rotulo, LIMITES.rotulo);
    if (!rotulo) return null;
    // `proxima` vazio é legítimo: uma opção pode só responder e voltar
    // ao início, sem apontar para bloco nenhum.
    var proxima = item.proxima ? chave(item.proxima) : null;
    saida.push({ rotulo: rotulo, proxima: proxima });
  }
  return saida;
}

function gatilhos(v) {
  if (v === null || v === undefined) return [];
  if (!Array.isArray(v)) return null;
  if (v.length > 20) return null;

  var saida = [];
  for (var g of v) {
    var limpo = texto(g, LIMITES.gatilho);
    if (limpo) saida.push(limpo.toLowerCase());
  }
  return saida;
}

/** Dias da semana (0=domingo). */
function dias(v) {
  if (!Array.isArray(v)) return null;
  var saida = [];
  for (var d of v) {
    var n = parseInt(d, 10);
    if (!Number.isFinite(n) || n < 0 || n > 6) return null;
    if (saida.indexOf(n) === -1) saida.push(n);
  }
  return saida.sort();
}

module.exports = {
  LIMITES, texto, textoOpcional, email, senha, telefone, uuid,
  booleano, inteiro, umDe, chave, horario, opcoes, gatilhos, dias
};
