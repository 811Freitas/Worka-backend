"use strict";

/**
 * Configuração — 100% via variáveis de ambiente.
 *
 * Nenhum segredo mora no código. Isso não é preciosismo: o repositório é
 * público, e uma chave commitada continua no histórico do Git para
 * sempre, mesmo depois de apagada do arquivo.
 */

require("dotenv").config();

/**
 * Lê uma variável cortando espaços e quebras de linha das pontas.
 *
 * Colar um valor no painel da Render/Railway arrasta com frequência um
 * espaço ou um "\n" invisível no fim. Um segredo com um caractere a mais
 * simplesmente não confere — e não sobra nenhuma pista do motivo. String
 * vazia vira `null` para que os testes de "está configurado?" não sejam
 * enganados por um campo preenchido com nada.
 */
function ler(nome, padrao) {
  var v = process.env[nome];
  if (typeof v !== "string") return padrao === undefined ? null : padrao;
  v = v.trim();
  if (v === "") return padrao === undefined ? null : padrao;
  return v;
}

function lerInteiro(nome, padrao) {
  var n = parseInt(ler(nome, ""), 10);
  return Number.isFinite(n) ? n : padrao;
}

var config = {
  AMBIENTE: ler("NODE_ENV", "development"),
  PORTA:    lerInteiro("PORT", 3000),

  // ── Banco ──────────────────────────────────────────────
  DATABASE_URL: ler("DATABASE_URL"),
  // Supabase, Neon e Render exigem TLS; um Postgres local normalmente
  // não tem certificado. Por isso é uma variável, e não uma constante:
  // sem ela, ou o desenvolvimento local quebra, ou a produção conecta
  // sem criptografia — e a segunda falha é silenciosa.
  DB_SSL: ler("DB_SSL", "") === "true",

  // ── Sessão ─────────────────────────────────────────────
  JWT_SEGREDO:   ler("JWT_SECRET"),
  JWT_DURACAO_H: lerInteiro("JWT_HORAS", 12),
  BCRYPT_ROUNDS: 12,

  // ── Cifragem dos tokens do WhatsApp ────────────────────
  // Chave separada do JWT de propósito. Trocar o segredo do JWT é uma
  // operação banal (desloga todo mundo e pronto); se ela também cifrasse
  // os tokens da Meta, a mesma troca tornaria ILEGÍVEIS as credenciais
  // de todos os clientes — e cada um teria que reconectar na mão.
  CRIPTO_CHAVE: ler("CRYPTO_KEY"),

  // ── Painel do dono da plataforma ───────────────────────
  // A conta administrativa do Zapfy mora AQUI, não no banco. Duas razões:
  //
  // 1. Ela não é um cliente. Colocá-la na tabela `usuarios` criaria uma
  //    linha que toda consulta multi-inquilino teria que aprender a
  //    ignorar — e bastaria uma esquecer para o owner aparecer como
  //    cliente numa listagem, ou um cliente virar owner por engano.
  // 2. Um vazamento do banco não entrega a chave-mestra da plataforma.
  //
  // OWNER_SENHA_HASH é o hash bcrypt, nunca a senha. Gere com:
  //   node -e "console.log(require('bcryptjs').hashSync('SUA_SENHA',12))"
  //
  // Sem as duas variáveis, /api/owner/login responde 503 — o painel
  // simplesmente não existe, em vez de existir com uma senha padrão.
  OWNER_EMAIL: (function () {
    var v = ler("OWNER_EMAIL");
    return v ? v.toLowerCase() : null;
  })(),
  OWNER_SENHA_HASH: ler("OWNER_SENHA_HASH"),

  // ── WhatsApp Cloud API ─────────────────────────────────
  // Versão da Graph API. Fixada, e não "a mais nova": a Meta muda
  // formato de payload entre versões, e um bot que muda de
  // comportamento sozinho num domingo é impossível de investigar.
  GRAPH_VERSAO: ler("GRAPH_VERSION", "v22.0"),
  GRAPH_HOST:   ler("GRAPH_HOST", "graph.facebook.com"),
  // Só existe para a suíte de testes apontar a Graph API para um
  // servidor falso em 127.0.0.1, que não tem certificado. Em produção
  // nunca é definida, e o padrão é https. Mantido explícito (em vez de
  // "se for localhost, use http") porque uma regra implícita dessas é
  // exatamente o tipo de coisa que um dia decide sozinha mandar o token
  // de um cliente em texto puro pela rede.
  GRAPH_PROTOCOLO: ler("GRAPH_PROTOCOL", "https"),

  // ── URL pública ────────────────────────────────────────
  // Usada para MOSTRAR ao cliente a URL de webhook que ele vai colar no
  // painel da Meta. Errada aqui = webhook apontando para lugar nenhum,
  // com a Meta reclamando de um endereço que o cliente copiou daqui.
  URL_PUBLICA: ler("PUBLIC_URL", "http://localhost:3000"),

  // ── Monitor de saúde ───────────────────────────────────
  MONITOR_MINUTOS: lerInteiro("MONITOR_MINUTOS", 15),
  MONITOR_LIGADO:  ler("MONITOR", "on") !== "off",

  // Origens liberadas no CORS. O painel é servido pelo próprio servidor,
  // então em produção normalmente não há origem cruzada nenhuma — a
  // lista existe para quem hospedar o front separado do back.
  ORIGENS: (ler("CORS_ORIGINS", "") || "")
    .split(",").map(function (s) { return s.trim(); }).filter(Boolean),

  // ── Pagamento (Cakto) ──────────────────────────────────
  // Deliberadamente OPCIONAL, fora de OBRIGATORIAS: sem estas três
  // variáveis, o módulo de pagamentos (src/modulos/pagamentos) responde
  // "não configurado" em vez de derrubar o servidor inteiro. É a
  // diferença entre lançar o produto sem cobrança pronta e não
  // conseguir lançar o produto.
  CAKTO_CLIENT_ID:      ler("CAKTO_CLIENT_ID"),
  CAKTO_CLIENT_SECRET:  ler("CAKTO_CLIENT_SECRET"),
  // Segredo que vai na URL do webhook cadastrada no painel da Cakto
  // (?s=...). Ver src/modulos/pagamentos/cakto.js para o porquê de não
  // ser HMAC.
  CAKTO_WEBHOOK_SECRET: ler("CAKTO_WEBHOOK_SECRET")
};

/**
 * Variáveis sem as quais o sistema não pode subir.
 *
 * Falhar aqui, alto e cedo, é melhor que subir e quebrar na primeira
 * pessoa que tentar entrar: sem JWT_SECRET o login emite tokens que
 * qualquer um forja, e sem CRYPTO_KEY os tokens da Meta seriam gravados
 * em texto puro.
 */
var OBRIGATORIAS = ["DATABASE_URL", "JWT_SECRET", "CRYPTO_KEY"];

config.conferir = function () {
  var faltando = OBRIGATORIAS.filter(function (nome) {
    return !ler(nome);
  });

  if (faltando.length) {
    console.error(
      "\n[FATAL] Variáveis de ambiente não definidas: " + faltando.join(", ") +
      "\n[FATAL] Copie .env.example para .env e preencha.\n" +
      "[FATAL] Para gerar segredos: node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"\n"
    );
    process.exit(1);
  }

  // Segredo curto é segredo adivinhável. 32 caracteres é o piso, não a
  // recomendação — o .env.example gera 64.
  if (config.JWT_SEGREDO.length < 32) {
    console.error("[FATAL] JWT_SECRET tem " + config.JWT_SEGREDO.length +
                  " caracteres. Use 32 ou mais.");
    process.exit(1);
  }
};

module.exports = config;
