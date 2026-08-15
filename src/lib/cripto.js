"use strict";

/**
 * Cifragem dos segredos dos clientes (token permanente da Meta e app
 * secret) antes de irem para o banco.
 *
 * AES-256-GCM, e não AES-CBC: o GCM autentica o texto cifrado. Sem
 * autenticação, alguém com acesso de escrita ao banco pode ALTERAR bytes
 * do token cifrado e o sistema decifraria lixo sem perceber. Com GCM, a
 * decifragem falha — que é o comportamento certo.
 *
 * O que isto protege de verdade: um dump de banco vazado, um backup
 * esquecido num bucket público, um SELECT feito por alguém com acesso de
 * leitura. Em todos esses casos o atacante leva texto embaralhado em vez
 * do poder de mandar mensagem em nome de todos os clientes.
 *
 * O que NÃO protege: quem já tem o servidor E a CRYPTO_KEY. Nada
 * guardado no servidor protege disso — por isso a chave mora só na
 * variável de ambiente do provedor de hospedagem, nunca no repositório.
 */

var crypto = require("crypto");
var config = require("../config");

var ALGORITMO = "aes-256-gcm";

/**
 * Deriva a chave de 32 bytes a partir de CRYPTO_KEY.
 *
 * scrypt e não um `Buffer.from(chave)` direto: a variável de ambiente é
 * texto que uma pessoa digitou/colou, de tamanho qualquer. O scrypt
 * transforma isso numa chave de tamanho exato e de derivação cara — o
 * que importa se alguém um dia definir CRYPTO_KEY como uma frase curta.
 *
 * Derivada uma vez e guardada: derivar por operação custa ~100ms, e
 * isso aconteceria em toda mensagem enviada.
 */
var chaveDerivada = null;
function chave() {
  if (!chaveDerivada) {
    // Sal fixo, e não aleatório por operação, porque a chave precisa ser
    // a MESMA entre reinícios do servidor — senão nada do que foi
    // cifrado ontem decifra hoje. O sigilo aqui vem da CRYPTO_KEY; o sal
    // só separa este uso de outros usos da mesma senha.
    chaveDerivada = crypto.scryptSync(config.CRIPTO_CHAVE, "zapfy.cripto.v1", 32);
  }
  return chaveDerivada;
}

/**
 * Cifra um texto. Devolve "iv:tag:conteudo", tudo em base64.
 *
 * O IV é aleatório a cada chamada e viaja junto: reusar IV em GCM é a
 * falha clássica que permite recuperar o texto original comparando duas
 * mensagens cifradas. Ele não é segredo — só não pode se repetir.
 */
function cifrar(texto) {
  if (texto === null || texto === undefined || texto === "") return null;

  var iv = crypto.randomBytes(12); // 12 bytes é o tamanho canônico do GCM
  var cifrador = crypto.createCipheriv(ALGORITMO, chave(), iv);
  var conteudo = Buffer.concat([cifrador.update(String(texto), "utf8"), cifrador.final()]);
  var tag = cifrador.getAuthTag();

  return [iv.toString("base64"), tag.toString("base64"), conteudo.toString("base64")].join(":");
}

/**
 * Decifra. Devolve null se o valor estiver ausente, malformado ou
 * adulterado — nunca lança.
 *
 * Não lançar é deliberado: quem chama está no meio de enviar uma
 * mensagem de cliente. Um throw aqui derrubaria o webhook inteiro (a
 * Meta reenviaria, e reenviaria de novo). Devolvendo null, o chamador
 * trata como "conexão sem credencial válida", marca a conexão com erro e
 * avisa o dono — que é a informação útil.
 */
function decifrar(valor) {
  if (typeof valor !== "string" || valor === "") return null;

  var partes = valor.split(":");
  if (partes.length !== 3) return null;

  try {
    var decifrador = crypto.createDecipheriv(ALGORITMO, chave(), Buffer.from(partes[0], "base64"));
    decifrador.setAuthTag(Buffer.from(partes[1], "base64"));
    return Buffer.concat([
      decifrador.update(Buffer.from(partes[2], "base64")),
      decifrador.final()
    ]).toString("utf8");
  } catch (e) {
    // Chave trocada, dado corrompido ou adulterado. Todos são "não
    // consigo recuperar isto", e a diferença não muda o que o chamador faz.
    return null;
  }
}

/**
 * Mostra só o fim de um segredo ("••••••••a3f9") para a tela de conexão
 * poder dizer "está configurado" sem devolver o token ao navegador.
 *
 * A API deste projeto NUNCA devolve um token da Meta, nem para o dono da
 * conta que o cadastrou: se ele volta ao navegador, volta também para
 * qualquer XSS, extensão ou aba de DevTools aberta numa lan house.
 */
function mascarar(texto) {
  if (!texto) return null;
  var t = String(texto);
  return "••••••••" + t.slice(-4);
}

/** Segredo aleatório em hex — verify_token do webhook, senhas de teste. */
function segredoAleatorio(bytes) {
  return crypto.randomBytes(bytes || 24).toString("hex");
}

module.exports = { cifrar, decifrar, mascarar, segredoAleatorio };
