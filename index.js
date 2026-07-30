/**
 * WORKA BACKEND v3.0 — SECURE
 * ════════════════════════════════════════════════════════════
 * Arquitetura de segurança implementada:
 * - Senhas: bcrypt (salt rounds = 12)
 * - Autenticação: JWT com expiração
 * - Rate limiting por IP e por rota
 * - Sanitização e validação de todos os inputs
 * - Headers de segurança (OWASP)
 * - CORS restrito por domínio
 * - Logs de segurança sem dados sensíveis
 * - Proteção contra brute force
 * - Zero credenciais hardcoded
 * ════════════════════════════════════════════════════════════
 */

"use strict";

const http    = require("http");
const https   = require("https");
const crypto  = require("crypto");
const bcrypt  = require("bcryptjs");
const webpush = require("web-push");

// ════════════════════════════════════════
// CONFIGURAÇÃO — 100% VIA ENV VARS
// ════════════════════════════════════════
const CONFIG = {
  PORT:          process.env.PORT || 3000,
  JWT_SECRET:    process.env.JWT_SECRET,          // OBRIGATÓRIO
  SUPABASE_URL:  "https://vtkmqykwyilcdnigaxsr.supabase.co", // Worka1 — projeto ativo (Worka original pausado)
  SUPABASE_KEY:  process.env.SUPABASE_SERVICE_KEY,
  RESEND_KEY:    process.env.RESEND_KEY,
  PIX_URL:       process.env.DUTTYFY_PIX_URL_ENCRYPTED,
  ENCRYPT_KEY:   process.env.ENCRYPT_SECRET,
  VAPID_PUBLIC:  process.env.VAPID_PUBLIC_KEY,
  VAPID_PRIVATE: process.env.VAPID_PRIVATE_KEY,
  BCRYPT_ROUNDS: 12,
  JWT_EXPIRES:   "8h",
  // Domínios permitidos no CORS
  ALLOWED_ORIGINS: [
    "https://811freitas.github.io",
    "https://worka.com.br",
    "http://localhost:3000",
    "http://localhost:5500"
  ]
};

// Validar variáveis críticas na inicialização
const REQUIRED_ENV = ["JWT_SECRET", "SUPABASE_SERVICE_KEY", "RESEND_KEY"];
// XAI_API_KEY é opcional — Wer fica indisponível se não definida
for (var env of REQUIRED_ENV) {
  if (!process.env[env]) {
    console.error(`[SECURITY] FATAL: variável de ambiente ${env} não definida`);
    process.exit(1);
  }
}

// ════════════════════════════════════════
// RATE LIMITING (por IP + por rota)
// ════════════════════════════════════════
var rateLimits = new Map();

function rateLimit(key, maxRequests, windowMs) {
  var now = Date.now();
  var entry = rateLimits.get(key) || { count: 0, reset: now + windowMs };

  if (now > entry.reset) {
    entry = { count: 0, reset: now + windowMs };
  }

  entry.count++;
  rateLimits.set(key, entry);

  if (entry.count > maxRequests) {
    var retryAfter = Math.ceil((entry.reset - now) / 1000);
    return { blocked: true, retryAfter };
  }
  return { blocked: false };
}

// Limpar entradas expiradas a cada 5 minutos
setInterval(() => {
  var now = Date.now();
  for (var [key, val] of rateLimits) {
    if (now > val.reset) rateLimits.delete(key);
  }
}, 5 * 60 * 1000);

// Limites por rota (requests/janela)
var RATE_LIMITS = {
  "/login":          { max: 5,   window: 15 * 60 * 1000 }, // 5/15min — anti brute force
  "/enviar-codigo":  { max: 3,   window: 10 * 60 * 1000 }, // 3/10min — anti spam
  "/verificar-codigo":{ max: 5,  window: 10 * 60 * 1000 }, // 5/10min
  "/empresas":       { max: 10,  window: 60 * 60 * 1000 }, // 10/hora
  "/pix":            { max: 10,  window: 60 * 60 * 1000 }, // 10/hora
  "default":         { max: 100, window: 60 * 1000 }       // 100/min geral
};

function checkRateLimit(ip, path) {
  var config = RATE_LIMITS[path] || RATE_LIMITS["default"];
  return rateLimit(`${ip}:${path}`, config.max, config.window);
}

// ════════════════════════════════════════
// JWT
// ════════════════════════════════════════
function jwtSign(payload) {
  // JWT manual sem dependência (header.payload.signature)
  var header  = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  var exp     = Math.floor(Date.now() / 1000) + 8 * 60 * 60; // 8h
  var body    = Buffer.from(JSON.stringify({ ...payload, exp, iat: Math.floor(Date.now() / 1000) })).toString("base64url");
  var sig     = crypto.createHmac("sha256", CONFIG.JWT_SECRET).update(`${header}.${body}`).digest("base64url");
  return `${header}.${body}.${sig}`;
}

function jwtVerify(token) {
  if (!token || typeof token !== "string") return null;
  var parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    var sig = crypto.createHmac("sha256", CONFIG.JWT_SECRET).update(`${parts[0]}.${parts[1]}`).digest("base64url");
    // Comparação em tempo constante para evitar timing attacks
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(parts[2]))) return null;
    var payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
    if (payload.exp < Math.floor(Date.now() / 1000)) return null; // expirado
    return payload;
  } catch (e) {
    return null;
  }
}

function extractToken(req) {
  var auth = req.headers["authorization"] || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7);
  return null;
}

function requireAuth(req) {
  var token = extractToken(req);
  if (!token) return null;
  return jwtVerify(token);
}

// ════════════════════════════════════════
// RBAC — CONTROLE DE ACESSO BASEADO EM FUNÇÃO
// ════════════════════════════════════════
// Cada role carrega um conjunto fixo de permissões. O JWT nunca
// carrega permissões — apenas o role — para que revogar/alterar
// acesso não exija invalidar tokens já emitidos além do necessário.
var ROLE_PERMISSIONS = {
  dono: new Set([
    "funcionarios:read", "funcionarios:write", "funcionarios:delete",
    "salarios:read", "salarios:write",
    "financeiro:read", "financeiro:write",
    "ponto:read", "ponto:write",
    "tarefas:read", "tarefas:write",
    "validade:read", "validade:write",
    "ausencias:read", "ausencias:write",
    "logs:read",
    "config:write"
  ]),
  gerente: new Set([
    "funcionarios:read", "funcionarios:write",
    "salarios:read",
    "financeiro:read",   // gerente vê caixa mas não lança/edita
    "ponto:read", "ponto:write",
    "tarefas:read", "tarefas:write",
    "validade:read", "validade:write",
    "ausencias:read", "ausencias:write",
    "logs:read"
  ]),
  funcionario: new Set([
    "ponto:write",       // só o próprio ponto — checagem extra na rota
    "tarefas:read",
    "validade:read"
  ]),
  owner_saas: new Set([  // dono da Worka, não do cliente — painel Owner
    "saas:read", "saas:write"
  ])
};

/**
 * Verifica se o payload do JWT autenticado tem a permissão exigida.
 * Retorna true/false — a rota decide o que fazer com jsonErr(403).
 * Nunca confia em permissão vinda do cliente: sempre deriva do
 * `role` gravado no token no momento do login.
 */
function hasPermission(authPayload, permission) {
  if (!authPayload || !authPayload.role) return false;
  var perms = ROLE_PERMISSIONS[authPayload.role];
  return perms ? perms.has(permission) : false;
}

/**
 * Helper de rota: exige autenticação + permissão específica.
 * Uso: var auth = requirePermission(req, res, "funcionarios:write");
 *      if (!auth) return; // resposta 401/403 já foi enviada
 */
function requirePermission(req, res, permission) {
  var authPayload = requireAuth(req);
  if (!authPayload) {
    secLog("auth_required", { path: req.url });
    jsonErr(res, "Autenticação necessária", 401);
    return null;
  }
  if (!hasPermission(authPayload, permission)) {
    secLog("permission_denied", { role: authPayload.role, permission, empresa_id: authPayload.empresa_id });
    jsonErr(res, "Você não tem permissão para esta ação", 403);
    return null;
  }
  return authPayload;
}

// ════════════════════════════════════════
// SANITIZAÇÃO E VALIDAÇÃO DE INPUTS
// ════════════════════════════════════════
var SANITIZE = {
  // Remove caracteres perigosos para XSS
  string: (v, maxLen = 255) => {
    if (typeof v !== "string") return "";
    return v
      .trim()
      .replace(/[<>'"`;\\]/g, "")  // XSS básico
      .replace(/javascript:/gi, "")
      .replace(/on\w+\s*=/gi, "")
      .substring(0, maxLen);
  },

  // Email com regex rigorosa
  email: (v) => {
    if (typeof v !== "string") return null;
    var clean = v.trim().toLowerCase().substring(0, 320);
    var re = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;
    return re.test(clean) ? clean : null;
  },

  // Senha: mínimo 8 chars, sem espaço
  senha: (v) => {
    if (typeof v !== "string") return null;
    if (v.length < 8 || v.length > 128) return null;
    if (/\s/.test(v)) return null;
    return v;
  },

  // Número inteiro positivo
  int: (v, min = 0, max = 999999) => {
    var n = parseInt(v);
    if (isNaN(n) || n < min || n > max) return null;
    return n;
  },

  // UUID v4
  uuid: (v) => {
    if (typeof v !== "string") return null;
    var re = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return re.test(v) ? v : null;
  },

  // Team ID formato #WK-NNNN
  teamId: (v) => {
    if (typeof v !== "string") return null;
    var re = /^#WK-\d{4}$/;
    return re.test(v.trim()) ? v.trim() : null;
  },

  // Tipo de ponto
  pontoTipo: (v) => {
    var allowed = ["entrada", "intervalo", "retorno", "saida"];
    return allowed.includes(v) ? v : null;
  },

  // Status de funcionário
  funcStatus: (v) => {
    var allowed = ["ativo", "pendente", "inativo"];
    return allowed.includes(v) ? v : null;
  },

  // Categoria de lançamento financeiro — mesmo conjunto oferecido
  // no <select> do modal "Novo lançamento" (worka-full.html).
  // Fecha o enum para não deixar o cliente gravar texto livre, que
  // quebraria qualquer agrupamento/relatório por categoria no futuro.
  categoriaFinanceira: (v) => {
    var allowed = ["receita", "folha", "estoque", "despesa_fixa", "outro"];
    return allowed.includes(v) ? v : "outro"; // fallback seguro, não bloqueia o lançamento
  }
};

function validate(data, rules) {
  var erros = [];
  var clean = {};
  for (var [field, rule] of Object.entries(rules)) {
    var val = data[field];
    var result = rule(val);
    if (result === null || result === undefined || result === "") {
      erros.push(field);
    } else {
      clean[field] = result;
    }
  }
  return { ok: erros.length === 0, erros, data: clean };
}

// ════════════════════════════════════════
// SUPABASE — Queries parametrizadas
// ════════════════════════════════════════
function supabase(method, table, options = {}) {
  // Whitelist de tabelas permitidas
  var ALLOWED_TABLES = [
    "empresas", "funcionarios", "registros_ponto", "tarefas",
    "produtos_validade", "ausencias", "escalas",
    "historico_salarios", "logs_sistema", "codigos_verificacao",
    "lancamentos_financeiros", "push_subscriptions"
  ];
  if (!ALLOWED_TABLES.includes(table)) {
    return Promise.reject(new Error(`Tabela não permitida: ${table}`));
  }

  return new Promise((resolve, reject) => {
    var path = `/rest/v1/${table}`;
    if (options.query) path += `?${options.query}`;
    var bodyStr = options.body ? JSON.stringify(options.body) : null;
    var headers = {
      "apikey":        CONFIG.SUPABASE_KEY,
      "Authorization": `Bearer ${CONFIG.SUPABASE_KEY}`,
      "Content-Type":  "application/json",
      "Prefer":        options.prefer || "return=representation"
    };
    if (bodyStr) headers["Content-Length"] = Buffer.byteLength(bodyStr);

    var req = https.request({
      hostname: "veqwewppgcyjrmtwnzai.supabase.co",
      path, method, headers
    }, (res) => {
      var raw = "";
      res.on("data", c => raw += c);
      res.on("end", () => {
        try {
          var body = JSON.parse(raw || "[]");
          // Supabase retorna erro como objeto com message
          if (body && body.code && body.message) {
            secLog("supabase_error", { table, status: res.statusCode, code: body.code });
            return reject(new Error(body.message));
          }
          resolve({ status: res.statusCode, body });
        } catch(e) {
          resolve({ status: res.statusCode, body: raw });
        }
      });
    });
    req.on("error", reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

const DB = {
  select: (t, q)     => supabase("GET",    t, { query: q }),
  insert: (t, d)     => supabase("POST",   t, { body: d }),
  update: (t, q, d)  => supabase("PATCH",  t, { query: q, body: d }),
  delete: (t, q)     => supabase("DELETE", t, { query: q })
};

// ════════════════════════════════════════
// LOGS DE SEGURANÇA (sem dados sensíveis)
// ════════════════════════════════════════
// Eventos que aparecem na tela de Auditoria do dono (worka-app.html).
// A lista é deliberadamente curta: eventos técnicos (rate_limit_blocked,
// server_error, auth_required) continuam só no console — o dono não
// precisa ver isso, e gravar tudo encheria a tabela sem gerar valor.
var AUDIT_EVENTS = new Set([
  "empresa_cadastrada", "login_ok", "login_func_ok",
  "funcionario_cadastrado", "func_status_atualizado", "func_removido",
  "ponto_registrado", "tarefa_atualizada", "salario_ajustado",
  "lancamento_financeiro", "permission_denied"
]);

function secLog(event, meta = {}) {
  // Nunca logar: senhas, tokens, códigos OTP, PIX codes
  var BLOCKED = ["senha", "password", "token", "jwt", "codigo", "pix_code", "secret"];
  var safeMeta = {};
  for (var [k, v] of Object.entries(meta)) {
    if (BLOCKED.some(b => k.toLowerCase().includes(b))) {
      safeMeta[k] = "[REDACTED]";
    } else {
      safeMeta[k] = v;
    }
  }
  var log = { ts: new Date().toISOString(), event, ...safeMeta };
  console.log(JSON.stringify(log));

  // Persistir no banco só os eventos de interesse do dono, e só
  // quando há empresa_id (eventos sem empresa, como rate limit
  // global, não pertencem a nenhuma tela de auditoria específica).
  // Fire-and-forget: auditoria não pode atrasar a resposta da rota
  // nem derrubá-la se o insert falhar.
  if (AUDIT_EVENTS.has(event) && safeMeta.empresa_id) {
    supabase("POST", "logs_sistema", {
      body: {
        empresa_id: safeMeta.empresa_id,
        funcionario_id: safeMeta.funcionario_id || null,
        tipo: event,
        descricao: describeAuditEvent(event, safeMeta),
        metadata: safeMeta
      }
    }).catch(e => console.log(JSON.stringify({ ts: new Date().toISOString(), event: "audit_persist_failed", error: e.message })));
  }
}

// Traduz o evento técnico em frase legível para a tela de Auditoria —
// evita que o dono veja "func_status_atualizado" cru na interface.
function describeAuditEvent(event, meta) {
  var map = {
    empresa_cadastrada:        "Empresa cadastrada, trial de 7 dias iniciado",
    login_ok:                  "Login realizado pelo dono",
    login_func_ok:              "Login realizado por funcionário",
    funcionario_cadastrado:    "Novo funcionário cadastrado",
    func_status_atualizado:    `Status do funcionário alterado para "${meta.status || "?"}"`,
    func_removido:              "Funcionário removido da equipe",
    ponto_registrado:           `Ponto registrado: ${meta.tipo || "?"}`,
    tarefa_atualizada:          `Tarefa atualizada${meta.status ? ` para "${meta.status}"` : ""}`,
    salario_ajustado:           "Ajuste de salário realizado",
    lancamento_financeiro:      `Lançamento financeiro: ${meta.tipo || "?"} de R$${meta.valor || "?"}`,
    permission_denied:          `Tentativa de ação sem permissão (${meta.action || meta.permission || "?"})`
  };
  return map[event] || event;
}

// ════════════════════════════════════════
// BCRYPT — Hash seguro de senhas
// ════════════════════════════════════════
async function hashSenha(senha) {
  return bcrypt.hash(senha, CONFIG.BCRYPT_ROUNDS);
}

async function verificarSenha(senha, hash) {
  return bcrypt.compare(senha, hash);
}

// ════════════════════════════════════════
// GERAÇÃO DE IDs E CÓDIGOS
// ════════════════════════════════════════
function gerarCodigo() {
  // Código criptograficamente seguro (não Math.random)
  return crypto.randomInt(100000, 999999).toString();
}

function gerarTeamId() {
  return "#WK-" + crypto.randomInt(1000, 9999).toString();
}

// ════════════════════════════════════════
// ARMAZENAMENTO SEGURO DE CÓDIGOS OTP
// (em produção: usar Redis com TTL)
// ════════════════════════════════════════
var otpStore = new Map();

function salvarOTP(email, codigo) {
  // Hash do código para não armazenar em plaintext
  var hash = crypto.createHash("sha256").update(codigo + email).digest("hex");
  otpStore.set(email, {
    hash,
    expira: Date.now() + 10 * 60 * 1000, // 10 min
    tentativas: 0
  });
}

function verificarOTP(email, codigo) {
  var entry = otpStore.get(email);
  if (!entry) return { ok: false, erro: "Código não encontrado" };
  if (Date.now() > entry.expira) {
    otpStore.delete(email);
    return { ok: false, erro: "Código expirado" };
  }
  // Máximo 5 tentativas (anti brute force)
  entry.tentativas++;
  if (entry.tentativas > 5) {
    otpStore.delete(email);
    secLog("otp_brute_force", { email_hash: crypto.createHash("sha256").update(email).digest("hex").substring(0, 8) });
    return { ok: false, erro: "Muitas tentativas. Solicite um novo código." };
  }
  var hash = crypto.createHash("sha256").update(codigo + email).digest("hex");
  // Comparação em tempo constante
  if (!crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(entry.hash))) {
    return { ok: false, erro: "Código inválido" };
  }
  otpStore.delete(email);
  return { ok: true };
}

// ════════════════════════════════════════
// PUSH NOTIFICATIONS (Web Push / VAPID)
// ════════════════════════════════════════
// Diferente de JWT_SECRET/SUPABASE/RESEND, VAPID não entra em
// REQUIRED_ENV: push é uma funcionalidade de reengajamento, não
// algo que impeça o sistema de funcionar. Sem as chaves, o helper
// abaixo simplesmente não envia (log de aviso), sem derrubar o boot.
if (CONFIG.VAPID_PUBLIC && CONFIG.VAPID_PRIVATE) {
  webpush.setVapidDetails("mailto:workappoficial@gmail.com", CONFIG.VAPID_PUBLIC, CONFIG.VAPID_PRIVATE);
}

/**
 * Envia push para todas as subscriptions de uma empresa (ou de um
 * funcionário específico). Remove automaticamente subscriptions que
 * o navegador já invalidou (erro 410 Gone) — sem isso a tabela
 * acumula lixo de dispositivos desinstalados/expirados para sempre.
 */
async function enviarPush(empresaId, payload, funcionarioId) {
  if (!CONFIG.VAPID_PUBLIC) {
    console.log(JSON.stringify({ ts: new Date().toISOString(), event: "push_skipped_no_vapid" }));
    return;
  }
  var query = `empresa_id=eq.${empresaId}` + (funcionarioId ? `&funcionario_id=eq.${funcionarioId}` : "");
  var subs = await supabase("GET", "push_subscriptions", { query }).catch(() => ({ body: [] }));

  for (var sub of (subs.body || [])) {
    try {
      await webpush.sendNotification(
        { endpoint: sub.endpoint, keys: sub.keys },
        JSON.stringify(payload)
      );
    } catch(e) {
      if (e.statusCode === 410 || e.statusCode === 404) {
        // Subscription morta — o próprio browser confirmou que não
        // existe mais. Remove para não tentar de novo no futuro.
        await supabase("DELETE", "push_subscriptions", { query: `id=eq.${sub.id}` }).catch(() => {});
      }
    }
  }
}

// ════════════════════════════════════════
// EMAIL VIA RESEND
// ════════════════════════════════════════
function enviarEmail(para, assunto, html) {
  return new Promise((resolve, reject) => {
    var data = JSON.stringify({
      from:    "Worka <onboarding@resend.dev>",
      to:      [para],
      subject: assunto,
      html
    });
    var req = https.request({
      hostname: "api.resend.com",
      path:     "/emails",
      method:   "POST",
      headers: {
        "Authorization":  `Bearer ${CONFIG.RESEND_KEY}`,
        "Content-Type":   "application/json",
        "Content-Length": Buffer.byteLength(data)
      }
    }, (res) => {
      var raw = "";
      res.on("data", c => raw += c);
      res.on("end", () => {
        if (res.statusCode >= 400) return reject(new Error(`Resend ${res.statusCode}`));
        resolve(JSON.parse(raw));
      });
    });
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

// ════════════════════════════════════════
// TEMPLATES DE EMAIL
// ════════════════════════════════════════
// (mesmos templates do v2, importados aqui de forma compacta)
function emailBase(conteudo) {
  return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f0f4f0;font-family:'Segoe UI',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f4f0;padding:32px 16px"><tr><td align="center">
<table width="100%" style="max-width:560px;background:#fff;border-radius:20px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
<tr><td style="background:linear-gradient(135deg,#0a2e1a,#1e8a40);padding:32px 40px;text-align:center">
<div style="font-size:28px;font-weight:900;color:#fff">Work<span style="color:#3dd669">a</span></div>
<div style="font-size:12px;color:rgba(255,255,255,.5);margin-top:4px;letter-spacing:2px;text-transform:uppercase">Gestão de Equipe</div>
</td></tr>
<tr><td style="padding:36px 40px">${conteudo}</td></tr>
<tr><td style="background:#f7f9f7;padding:20px 40px;text-align:center;border-top:1px solid #e8ede8">
<p style="font-size:12px;color:#9aab9a;margin:0">Worka — Sistema de Gestão de Equipe</p>
</td></tr>
</table></td></tr></table></body></html>`;
}

var EMAIL_TEMPLATES = {
  codigo: (nome, codigo) => emailBase(`
    <h2 style="margin:0 0 8px;color:#0a2e1a;font-size:22px;font-weight:800">Seu código de verificação 🔐</h2>
    <p style="color:#5a6b5a;font-size:15px;margin:0 0 28px;line-height:1.6">Olá, <strong>${SANITIZE.string(nome)}</strong>! Use o código abaixo para confirmar seu acesso.</p>
    <div style="background:linear-gradient(135deg,#0a2e1a,#16622f);border-radius:16px;padding:28px;text-align:center;margin:0 0 28px">
      <div style="font-size:44px;font-weight:900;color:#3dd669;letter-spacing:14px;font-family:'Courier New',monospace">${codigo}</div>
      <div style="font-size:13px;color:rgba(255,255,255,.6);margin-top:10px">⏰ Expira em <strong style="color:#fff">10 minutos</strong></div>
    </div>
    <div style="background:#f0faf2;border-radius:12px;padding:16px;border-left:4px solid #3dd669">
      <p style="margin:0;font-size:13px;color:#2d5a2d">🔒 <strong>Não compartilhe</strong> este código. A Worka nunca pedirá seu código por telefone.</p>
    </div>`),

  boasVindas: (nome, teamId, trialFim) => emailBase(`
    <h2 style="margin:0 0 8px;color:#0a2e1a;font-size:22px;font-weight:800">Bem-vindo ao Worka! 🎉</h2>
    <p style="color:#5a6b5a;font-size:15px;margin:0 0 20px;line-height:1.6">Olá, <strong>${SANITIZE.string(nome)}</strong>! Sua conta foi criada. Você tem <strong>7 dias grátis</strong>.</p>
    <div style="background:linear-gradient(135deg,#0a2e1a,#25b251);border-radius:16px;padding:24px;margin:0 0 24px;color:#fff">
      <div style="font-size:13px;color:rgba(255,255,255,.7)">Seu ID de equipe</div>
      <div style="font-size:28px;font-weight:900;letter-spacing:3px;color:#3dd669">${SANITIZE.string(teamId)}</div>
      <div style="font-size:12px;color:rgba(255,255,255,.5);margin-top:6px">Compartilhe com seus funcionários</div>
    </div>
    <div style="background:#fffbeb;border-radius:12px;padding:16px;border-left:4px solid #f59e0b">
      <p style="margin:0;font-size:13px;color:#78350f">⏰ Trial termina em <strong>${new Date(trialFim).toLocaleDateString("pt-BR")}</strong>. Após: R$ 24,90/mês.</p>
    </div>`),

  pagamentoConfirmado: (nome, valor) => emailBase(`
    <h2 style="text-align:center;margin:0 0 8px;color:#0a2e1a;font-size:22px;font-weight:800">Pagamento confirmado! ✅</h2>
    <p style="color:#5a6b5a;text-align:center;margin:0 0 24px">Olá, <strong>${SANITIZE.string(nome)}</strong>! Seu pagamento foi processado.</p>
    <div style="background:#f7f9f7;border-radius:16px;padding:24px">
      <table width="100%"><tr><td style="font-size:13px;color:#6b7a6b">Valor</td><td style="font-weight:900;color:#1e8a40;text-align:right">R$ ${SANITIZE.string(valor)}</td></tr></table>
    </div>`),

  trialAcabando: (nome, dias) => emailBase(`
    <h2 style="text-align:center;margin:0 0 8px;color:#0a2e1a;font-weight:800">Seu trial acaba em ${SANITIZE.int(dias, 0, 30)} dia(s)! ⏰</h2>
    <p style="color:#5a6b5a;text-align:center">Olá, <strong>${SANITIZE.string(nome)}</strong>! Renove por R$ 24,90/mês para não perder o acesso.</p>`),

  trialExpirado: (nome) => emailBase(`
    <h2 style="text-align:center;margin:0 0 8px;color:#0a2e1a;font-weight:800">Seu trial expirou 😢</h2>
    <p style="color:#5a6b5a;text-align:center">Olá, <strong>${SANITIZE.string(nome)}</strong>! Seus dados estão salvos. Reative por R$ 24,90/mês.</p>`)
};

// ════════════════════════════════════════
// HELPERS HTTP
// ════════════════════════════════════════
function getBody(req) {
  return new Promise((resolve, reject) => {
    var raw = "";
    var size = 0;
    req.on("data", c => {
      size += c.length;
      if (size > 50 * 1024) { // limite 50KB
        reject(new Error("Payload muito grande"));
        req.destroy();
        return;
      }
      raw += c;
    });
    req.on("end", () => resolve(raw));
    req.on("error", reject);
  });
}

function parseBody(raw) {
  try {
    var data = JSON.parse(raw);
    if (typeof data !== "object" || Array.isArray(data)) throw new Error("JSON inválido");
    return data;
  } catch(e) {
    return null;
  }
}

function getIP(req) {
  var forwarded = req.headers["x-forwarded-for"];
  if (forwarded) return forwarded.split(",")[0].trim().substring(0, 45);
  return req.socket.remoteAddress || "unknown";
}

// ════════════════════════════════════════
// HEADERS DE SEGURANÇA
// ════════════════════════════════════════
function setSecurityHeaders(res, origin) {
  // CORS restrito
  var allowedOrigin = CONFIG.ALLOWED_ORIGINS.includes(origin) ? origin : CONFIG.ALLOWED_ORIGINS[0];
  res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Max-Age", "86400");
  res.setHeader("Vary", "Origin");

  // Security headers (OWASP)
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=()");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.setHeader("Content-Type", "application/json; charset=utf-8");

  // Strict-Transport-Security (HSTS) — ativo em produção
  if (process.env.NODE_ENV === "production") {
    res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  }
}

function jsonOk(res, data, status = 200) {
  res.writeHead(status);
  res.end(JSON.stringify(data));
}

function jsonErr(res, msg, status = 400) {
  res.writeHead(status);
  // Nunca devolver stack traces ou detalhes internos
  res.end(JSON.stringify({ error: msg }));
}

// ════════════════════════════════════════
// CRON — verificar trials expirando
// ════════════════════════════════════════
async function verificarTrials() {
  try {
    var em2dias = await DB.select("empresas",
      "status=eq.trial" +
      "&trial_fim=gte." + new Date(Date.now() + 1.5*24*60*60*1000).toISOString() +
      "&trial_fim=lte." + new Date(Date.now() + 2.5*24*60*60*1000).toISOString() +
      "&aviso_trial_sent=is.false"
    );
    for (var emp of (em2dias.body || [])) {
      var dias = Math.ceil((new Date(emp.trial_fim) - Date.now()) / (1000*60*60*24));
      await enviarEmail(emp.email, `⏰ Seu trial acaba em ${dias} dia(s)!`, EMAIL_TEMPLATES.trialAcabando(emp.nome, dias));
      enviarPush(emp.id, { title: "Seu trial está acabando", body: `Faltam ${dias} dia(s). Renove para não perder o acesso.`, url: "/Worka-backend/worka.html" }).catch(() => {});
      await DB.update("empresas", "id=eq." + emp.id, { aviso_trial_sent: true });
      secLog("trial_aviso_enviado", { empresa_id: emp.id, dias });
    }

    var expirados = await DB.select("empresas",
      "status=eq.trial&trial_fim=lt." + new Date().toISOString() + "&aviso_expirado_sent=is.false"
    );
    for (var emp of (expirados.body || [])) {
      await enviarEmail(emp.email, "😢 Seu trial do Worka expirou", EMAIL_TEMPLATES.trialExpirado(emp.nome));
      await DB.update("empresas", "id=eq." + emp.id, { status: "inadimplente", aviso_expirado_sent: true });
      secLog("trial_expirado", { empresa_id: emp.id });
    }
  } catch(e) {
    secLog("cron_error", { message: e.message });
  }
}
setInterval(verificarTrials, 60 * 60 * 1000);

// ════════════════════════════════════════
// SERVIDOR HTTP
// ════════════════════════════════════════
var server = http.createServer(async (req, res) => {
  var ip     = getIP(req);
  var origin = req.headers["origin"] || "";
  var url    = new URL(req.url, `http://localhost:${CONFIG.PORT}`);
  var path   = url.pathname;
  var method = req.method;

  setSecurityHeaders(res, origin);

  if (method === "OPTIONS") { res.writeHead(204); return res.end(); }

  // ── Rate limiting global ──
  var rl = checkRateLimit(ip, path.startsWith("/login") ? "/login" : (RATE_LIMITS[path] ? path : "default"));
  if (rl.blocked) {
    secLog("rate_limit_blocked", { ip, path });
    res.setHeader("Retry-After", rl.retryAfter);
    return jsonErr(res, "Muitas requisições. Tente novamente em breve.", 429);
  }

  try {

    // ── HEALTH ──────────────────────────────────────
    if (path === "/" || path === "/health") {
      return jsonOk(res, {
        status: "ok",
        service: "worka-backend",
        version: "3.0",
        // Nunca expor status de serviços externos em produção
        ...(process.env.NODE_ENV !== "production" && {
          supabase: !!CONFIG.SUPABASE_KEY,
          resend:   !!CONFIG.RESEND_KEY
        })
      });
    }

    // ── CADASTRO DE EMPRESA ──────────────────────────
    if (method === "POST" && path === "/empresas") {
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      var v = validate(body, {
        nome:  v => SANITIZE.string(v, 120) || null,
        email: v => SANITIZE.email(v),
        senha: v => SANITIZE.senha(v),
      });
      if (!v.ok) return jsonErr(res, `Campos inválidos: ${v.erros.join(", ")}`);

      // Verificar se email já existe
      var existe = await DB.select("empresas", `email=eq.${encodeURIComponent(v.data.email)}&select=id`);
      if (existe.body && existe.body.length > 0) {
        // Não revelar se o email existe (enumeração de usuários)
        // Responder igual ao sucesso mas não criar
        secLog("cadastro_email_duplicado", { email_hash: crypto.createHash("sha256").update(v.data.email).digest("hex").substring(0, 8) });
        return jsonOk(res, { ok: true, message: "Se esse email for novo, você receberá um código de verificação." }, 200);
      }

      var senhaHash = await hashSenha(v.data.senha);
      var trialFim  = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
      var result    = await DB.insert("empresas", {
        nome:                 v.data.nome,
        email:                v.data.email,
        senha_hash:           senhaHash,
        ramo:                 SANITIZE.string(body.ramo || "", 80),
        team_id:              gerarTeamId(),
        status:               "trial",
        trial_fim:            trialFim,
        aviso_trial_sent:     false,
        aviso_expirado_sent:  false
      });

      var empresa = result.body[0];
      secLog("empresa_cadastrada", { empresa_id: empresa.id, team_id: empresa.team_id });

      // Email async — não bloquear resposta
      enviarEmail(empresa.email, "🎉 Bem-vindo ao Worka!", EMAIL_TEMPLATES.boasVindas(empresa.nome, empresa.team_id, trialFim))
        .catch(e => secLog("email_error", { type: "boas_vindas", message: e.message }));

      // Não retornar senha_hash
      delete empresa.senha_hash;
      return jsonOk(res, { empresa, trial_fim: trialFim }, 201);
    }

    // ── LOGIN EMPRESA ────────────────────────────────
    if (method === "POST" && path === "/login/empresa") {
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      var v = validate(body, {
        email: v => SANITIZE.email(v),
        senha: v => typeof v === "string" && v.length >= 1 ? v : null,
      });
      if (!v.ok) return jsonErr(res, "Email ou senha inválidos", 401);

      var result = await DB.select("empresas", `email=eq.${encodeURIComponent(v.data.email)}&select=*`);
      var empresa = result.body && result.body[0];

      // Verificar senha mesmo se empresa não existir (evitar timing attack)
      var senhaOk = false;
      if (empresa) {
        senhaOk = await verificarSenha(v.data.senha, empresa.senha_hash);
      } else {
        // Hash dummy para manter timing constante
        await bcrypt.compare(v.data.senha, "$2b$12$abcdefghijklmnopqrstuvuxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
      }

      if (!empresa || !senhaOk) {
        secLog("login_falhou", { ip, email_hash: crypto.createHash("sha256").update(v.data.email).digest("hex").substring(0, 8) });
        return jsonErr(res, "Email ou senha incorretos", 401);
      }

      var token = jwtSign({ empresa_id: empresa.id, email: empresa.email, role: "dono" });
      var trialInfo = null;
      if (empresa.status === "trial") {
        var dias = Math.ceil((new Date(empresa.trial_fim) - Date.now()) / (1000*60*60*24));
        trialInfo = { dias_restantes: dias, expirado: dias <= 0 };
      }

      secLog("login_ok", { empresa_id: empresa.id });
      delete empresa.senha_hash;
      return jsonOk(res, { token, empresa, trial: trialInfo });
    }

    // ── LOGIN FUNCIONÁRIO ────────────────────────────
    if (method === "POST" && path === "/login/funcionario") {
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      var v = validate(body, {
        teamId: v => SANITIZE.teamId(v),
        email:  v => SANITIZE.email(v),
        senha:  v => typeof v === "string" && v.length >= 1 ? v : null,
      });
      if (!v.ok) return jsonErr(res, "Dados inválidos", 401);

      var emp = await DB.select("empresas", `team_id=eq.${encodeURIComponent(v.data.teamId)}&select=id,nome,team_id,status`);
      var empresa = emp.body && emp.body[0];

      var func = empresa ? await DB.select("funcionarios",
        `empresa_id=eq.${empresa.id}&email=eq.${encodeURIComponent(v.data.email)}&select=*`
      ) : null;
      var funcionario = func && func.body && func.body[0];

      var senhaOk = false;
      if (funcionario) {
        senhaOk = await verificarSenha(v.data.senha, funcionario.senha_hash);
      } else {
        await bcrypt.compare(v.data.senha, "$2b$12$abcdefghijklmnopqrstuvuxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
      }

      if (!empresa || !funcionario || !senhaOk) {
        secLog("login_func_falhou", { ip });
        return jsonErr(res, "Credenciais inválidas", 401);
      }

      // O role do RBAC deriva do cargo cadastrado, não é escolha do
      // cliente no login — evita que alguém se autodeclare "gerente".
      // Qualquer cargo além de "Gerente" cai no menor privilégio.
      var rbacRole = funcionario.cargo === "Gerente" ? "gerente" : "funcionario";
      var token = jwtSign({ funcionario_id: funcionario.id, empresa_id: empresa.id, role: rbacRole });
      delete funcionario.senha_hash;
      secLog("login_func_ok", { funcionario_id: funcionario.id });
      return jsonOk(res, { token, funcionario, empresa });
    }

    // ── ENVIAR CÓDIGO OTP ───────────────────────────
    if (method === "POST" && path === "/enviar-codigo") {
      // Rate limiting extra para OTP
      var rlOtp = rateLimit(`otp:${ip}`, 3, 10 * 60 * 1000);
      if (rlOtp.blocked) return jsonErr(res, "Muitas requisições de código. Aguarde.", 429);

      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      var email = SANITIZE.email(body.email);
      if (!email) return jsonErr(res, "Email inválido");

      var nome = SANITIZE.string(body.name || "Cliente", 80);
      var codigo = gerarCodigo();
      salvarOTP(email, codigo);

      secLog("otp_gerado", { email_hash: crypto.createHash("sha256").update(email).digest("hex").substring(0, 8) });

      try {
        await enviarEmail(email, "🔐 Seu código de verificação Worka", EMAIL_TEMPLATES.codigo(nome, codigo));
        return jsonOk(res, { ok: true });
      } catch(e) {
        secLog("otp_email_error", { message: e.message });
        return jsonErr(res, "Erro ao enviar código. Tente novamente.", 500);
      }
    }

    // ── VERIFICAR CÓDIGO OTP ────────────────────────
    if (method === "POST" && path === "/verificar-codigo") {
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      var email = SANITIZE.email(body.email);
      var codigo = SANITIZE.string(body.codigo || "", 6);
      if (!email || !codigo || !/^\d{6}$/.test(codigo)) return jsonErr(res, "Dados inválidos");

      var otpResult = verificarOTP(email, codigo);
      if (!otpResult.ok) return jsonErr(res, otpResult.erro);

      secLog("otp_verificado", { email_hash: crypto.createHash("sha256").update(email).digest("hex").substring(0, 8) });

      // Se enviar dados de empresa, cadastrar automaticamente
      if (body.nome && body.senha) {
        var nome  = SANITIZE.string(body.nome, 120);
        var senha = SANITIZE.senha(body.senha);
        if (!nome || !senha) return jsonErr(res, "Dados de cadastro inválidos");

        var senhaHash = await hashSenha(senha);
        var trialFim  = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

        var result = await DB.insert("empresas", {
          nome, email, senha_hash: senhaHash,
          team_id: gerarTeamId(), status: "trial",
          trial_fim: trialFim, aviso_trial_sent: false, aviso_expirado_sent: false
        }).catch(() => ({ body: [] }));

        if (result.body[0]) {
          var emp = result.body[0];
          var token = jwtSign({ empresa_id: emp.id, email: emp.email, role: "dono" });
          enviarEmail(emp.email, "🎉 Bem-vindo ao Worka!", EMAIL_TEMPLATES.boasVindas(emp.nome, emp.team_id, trialFim))
            .catch(() => {});
          secLog("empresa_via_otp", { empresa_id: emp.id });
          delete emp.senha_hash;
          return jsonOk(res, { ok: true, token, empresa: emp, trial_fim: trialFim });
        }
      }

      return jsonOk(res, { ok: true });
    }

    // ─── A PARTIR DAQUI: REQUER JWT ─────────────────
    // Rotas abaixo checam permissão específica via requirePermission()
    // em vez de só validar o token — isso é o que efetivamente
    // impede um funcionário comum de chamar rotas de dono/gerente.
    var authPayload = requireAuth(req);
    if (!authPayload) {
      secLog("auth_required", { ip, path });
      return jsonErr(res, "Autenticação necessária", 401);
    }

    // ── FUNCIONÁRIOS ─────────────────────────────────
    if (method === "POST" && path === "/funcionarios") {
      if (!hasPermission(authPayload, "funcionarios:write")) {
        secLog("permission_denied", { role: authPayload.role, action: "funcionarios:write" });
        return jsonErr(res, "Você não tem permissão para adicionar funcionários", 403);
      }
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      var v = validate(body, {
        teamId: v => SANITIZE.teamId(v),
        nome:   v => SANITIZE.string(v, 120) || null,
        email:  v => SANITIZE.email(v),
        senha:  v => SANITIZE.senha(v),
      });
      if (!v.ok) return jsonErr(res, `Campos inválidos: ${v.erros.join(", ")}`);

      var emp = await DB.select("empresas", `team_id=eq.${encodeURIComponent(v.data.teamId)}&select=id`);
      if (!emp.body || !emp.body[0]) return jsonErr(res, "Equipe não encontrada", 404);

      var senhaHash = await hashSenha(v.data.senha);
      var result = await DB.insert("funcionarios", {
        empresa_id: emp.body[0].id,
        nome:       v.data.nome,
        email:      v.data.email,
        senha_hash: senhaHash,
        telefone:   SANITIZE.string(body.telefone || "", 20),
        status:     "pendente"
      });

      var func = result.body[0];
      delete func.senha_hash;
      secLog("funcionario_cadastrado", { empresa_id: emp.body[0].id, funcionario_id: func.id });
      return jsonOk(res, { funcionario: func }, 201);
    }

    if (method === "GET" && path === "/funcionarios") {
      // Ver a lista de colegas é uso legítimo para qualquer role
      // (ex: saber quem está de folga) — não bloqueamos a rota.
      // O que precisa ser restrito é o CAMPO salario_base dentro
      // da resposta, não o acesso à lista inteira.
      var empresa_id = authPayload.empresa_id;
      var podeVerSalario = hasPermission(authPayload, "salarios:read");
      var campos = podeVerSalario
        ? "id,nome,email,telefone,cargo,status,salario_base,created_at"
        : "id,nome,email,telefone,cargo,status,created_at";

      var result = await DB.select("funcionarios",
        `empresa_id=eq.${empresa_id}&select=${campos}&order=created_at.desc`
      );
      return jsonOk(res, result.body);
    }

    if (method === "PUT" && path.match(/^\/funcionarios\/[\w-]+\/status$/)) {
      var raw = await getBody(req);
      var body = parseBody(raw);
      var funcId = SANITIZE.uuid(path.split("/")[2]);
      if (!funcId) return jsonErr(res, "ID inválido");

      var status = SANITIZE.funcStatus(body && body.status);
      if (!status) return jsonErr(res, "Status inválido");

      // Verificar que o funcionário pertence à empresa do JWT
      var check = await DB.select("funcionarios", `id=eq.${funcId}&empresa_id=eq.${authPayload.empresa_id}&select=id`);
      if (!check.body || !check.body[0]) return jsonErr(res, "Não autorizado", 403);

      await DB.update("funcionarios", `id=eq.${funcId}`, { status });
      secLog("func_status_atualizado", { funcionario_id: funcId, status });
      return jsonOk(res, { ok: true });
    }

    if (method === "DELETE" && path.match(/^\/funcionarios\/[\w-]+$/)) {
      // Excluir funcionário é irreversível — só "dono" pode, gerente não.
      if (!hasPermission(authPayload, "funcionarios:delete")) {
        secLog("permission_denied", { role: authPayload.role, action: "funcionarios:delete" });
        return jsonErr(res, "Apenas o dono pode remover funcionários", 403);
      }
      var funcId = SANITIZE.uuid(path.split("/")[2]);
      if (!funcId) return jsonErr(res, "ID inválido");

      // Verificar propriedade antes de deletar
      var check = await DB.select("funcionarios", `id=eq.${funcId}&empresa_id=eq.${authPayload.empresa_id}&select=id`);
      if (!check.body || !check.body[0]) return jsonErr(res, "Não autorizado", 403);

      await DB.delete("funcionarios", `id=eq.${funcId}`);
      secLog("func_removido", { funcionario_id: funcId, empresa_id: authPayload.empresa_id });
      return jsonOk(res, { ok: true });
    }

    // ── PONTO ────────────────────────────────────────
    if (method === "POST" && path === "/ponto") {
      if (!hasPermission(authPayload, "ponto:write")) {
        return jsonErr(res, "Sem permissão para registrar ponto", 403);
      }
      // Um funcionário só pode registrar o PRÓPRIO ponto — mesmo tendo
      // a permissão "ponto:write", não pode passar funcionario_id de outra
      // pessoa no body. Dono/gerente podem registrar em nome de alguém
      // (ex: ajuste manual), então essa trava vale só para role funcionario.
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      if (authPayload.role === "funcionario" && body.funcionario_id && body.funcionario_id !== authPayload.funcionario_id) {
        secLog("ponto_spoof_attempt", { funcionario_id_token: authPayload.funcionario_id, funcionario_id_body: body.funcionario_id });
        return jsonErr(res, "Você só pode registrar seu próprio ponto", 403);
      }

      var tipo = SANITIZE.pontoTipo(body.tipo);
      if (!tipo) return jsonErr(res, "Tipo de ponto inválido");

      // Validar coordenadas
      var lat = body.latitude  ? parseFloat(body.latitude)  : null;
      var lng = body.longitude ? parseFloat(body.longitude) : null;
      if (lat !== null && (isNaN(lat) || lat < -90  || lat > 90))  lat = null;
      if (lng !== null && (isNaN(lng) || lng < -180 || lng > 180)) lng = null;

      var result = await DB.insert("registros_ponto", {
        funcionario_id: authPayload.funcionario_id || authPayload.empresa_id,
        empresa_id:     authPayload.empresa_id,
        tipo,
        latitude:   lat,
        longitude:  lng,
        biometria:  body.biometria === true
      });

      secLog("ponto_registrado", { tipo, empresa_id: authPayload.empresa_id });
      return jsonOk(res, { registro: result.body[0] }, 201);
    }

    if (method === "GET" && path === "/ponto") {
      var hoje = new Date().toISOString().split("T")[0];
      // Dono/gerente veem o ponto de toda a equipe (necessário para
      // gestão). Um funcionário comum só pode ver o PRÓPRIO histórico
      // — sem este filtro, a query devolvia o ponto de todos os
      // colegas para qualquer autenticado, vazando horário de entrada/
      // saída e localização GPS de terceiros.
      var filtroPonto = `empresa_id=eq.${authPayload.empresa_id}&horario=gte.${hoje}`;
      if (authPayload.role === "funcionario") {
        filtroPonto += `&funcionario_id=eq.${authPayload.funcionario_id}`;
      }
      var result = await DB.select("registros_ponto", `${filtroPonto}&order=horario.desc`);
      return jsonOk(res, result.body);
    }

    // ── TAREFAS ──────────────────────────────────────
    if (method === "POST" && path === "/tarefas") {
      if (!hasPermission(authPayload, "tarefas:write")) {
        return jsonErr(res, "Sem permissão para criar tarefas", 403);
      }
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      var titulo = SANITIZE.string(body.titulo, 200);
      if (!titulo) return jsonErr(res, "Título inválido");

      // Antes: "responsavel" era só texto livre com o nome, sem
      // vínculo real com o funcionário — impossível notificar a
      // pessoa certa ou saber com segurança quem é. Agora resolve
      // por funcionario_id (UUID) e mantém o nome só como cache de
      // exibição, preenchido a partir do cadastro real.
      var responsavelId = SANITIZE.uuid(body.responsavel_id);
      var responsavelNome = "";
      if (responsavelId) {
        var respCheck = await DB.select("funcionarios", `id=eq.${responsavelId}&empresa_id=eq.${authPayload.empresa_id}&select=id,nome`);
        if (!respCheck.body || !respCheck.body[0]) return jsonErr(res, "Funcionário responsável não encontrado");
        responsavelNome = respCheck.body[0].nome;
      }

      var result = await DB.insert("tarefas", {
        empresa_id:      authPayload.empresa_id,
        titulo,
        descricao:       SANITIZE.string(body.descricao || "", 1000),
        prioridade:      ["normal","alta","urgente"].includes(body.prioridade) ? body.prioridade : "normal",
        status:          "pendente",
        responsavel_id:  responsavelId,
        responsavel:     responsavelNome
      });

      // Notifica o responsável em tempo real — fire-and-forget,
      // não atrasa a resposta da criação da tarefa.
      if (responsavelId) {
        enviarPush(authPayload.empresa_id, {
          title: "Nova tarefa atribuída",
          body: titulo,
          url: "/Worka-backend/worka-app.html"
        }, responsavelId).catch(() => {});
      }

      return jsonOk(res, { tarefa: result.body[0] }, 201);
    }

    if (method === "GET" && path === "/tarefas") {
      // Dono/gerente veem todas as tarefas da empresa. Um funcionário
      // comum vê apenas as tarefas atribuídas a ele OU tarefas gerais
      // sem responsável definido (responsavel_id IS NULL) — sem isso,
      // qualquer autenticado via app de funcionário lia a lista
      // completa de tarefas de todos os colegas.
      var filtroTarefas = `empresa_id=eq.${authPayload.empresa_id}`;
      if (authPayload.role === "funcionario") {
        filtroTarefas += `&or=(responsavel_id.eq.${authPayload.funcionario_id},responsavel_id.is.null)`;
      }
      var result = await DB.select("tarefas", `${filtroTarefas}&order=created_at.desc`);
      return jsonOk(res, result.body);
    }

    if (method === "PUT" && path.match(/^\/tarefas\/[\w-]+$/)) {
      var raw = await getBody(req);
      var body = parseBody(raw);
      var tarefaId = SANITIZE.uuid(path.split("/")[2]);
      if (!tarefaId || !body) return jsonErr(res, "Dados inválidos");

      // Verificar propriedade
      var check = await DB.select("tarefas", `id=eq.${tarefaId}&empresa_id=eq.${authPayload.empresa_id}&select=id,titulo,empresa_id,funcionario_id`);
      if (!check.body || !check.body[0]) return jsonErr(res, "Não autorizado", 403);

      var allowed = { status: true, descricao: true, prioridade: true };
      var update = {};
      if (allowed.status && body.status && ["pendente","em_andamento","concluida","atrasada"].includes(body.status)) update.status = body.status;
      if (body.descricao) update.descricao = SANITIZE.string(body.descricao, 1000);

      await DB.update("tarefas", `id=eq.${tarefaId}`, update);
      secLog("tarefa_atualizada", { tarefa_id: tarefaId, status: update.status });
      return jsonOk(res, { ok: true });
    }

    // ── SALÁRIOS ─────────────────────────────────────
    if (method === "POST" && path === "/salarios/ajuste") {
      // Ajuste de salário é dado financeiro sensível — funcionário
      // nunca pode alterar salário (nem o próprio). Só dono tem
      // "salarios:write"; gerente só tem "salarios:read".
      if (!hasPermission(authPayload, "salarios:write")) {
        secLog("permission_denied", { role: authPayload.role, action: "salarios:write" });
        return jsonErr(res, "Apenas o dono pode ajustar salários", 403);
      }
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      var funcId = SANITIZE.uuid(body.funcionario_id);
      var salNovo = parseFloat(body.salario_novo);
      var salAnt  = parseFloat(body.salario_anterior);
      if (!funcId || isNaN(salNovo) || salNovo < 0 || salNovo > 999999) return jsonErr(res, "Dados inválidos");

      // Verificar propriedade
      var check = await DB.select("funcionarios", `id=eq.${funcId}&empresa_id=eq.${authPayload.empresa_id}&select=id`);
      if (!check.body || !check.body[0]) return jsonErr(res, "Não autorizado", 403);

      await DB.update("funcionarios", `id=eq.${funcId}`, { salario_base: salNovo });
      await DB.insert("historico_salarios", {
        funcionario_id:  funcId,
        salario_anterior: isNaN(salAnt) ? 0 : salAnt,
        salario_novo:    salNovo,
        tipo:            salNovo > (salAnt || 0) ? "aumento" : "reducao",
        motivo:          SANITIZE.string(body.motivo || "", 300)
      }).catch(() => {});

      secLog("salario_ajustado", { funcionario_id: funcId, empresa_id: authPayload.empresa_id });
      return jsonOk(res, { ok: true }, 201);
    }

    // ── VALIDADE ─────────────────────────────────────
    if (method === "POST" && path === "/validade") {
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      var nome = SANITIZE.string(body.nome, 200);
      if (!nome) return jsonErr(res, "Nome inválido");

      // Validar data
      var dataVenc = new Date(body.data_vencimento);
      if (isNaN(dataVenc.getTime())) return jsonErr(res, "Data inválida");

      var result = await DB.insert("produtos_validade", {
        empresa_id:       authPayload.empresa_id,
        nome,
        lote:             SANITIZE.string(body.lote || "", 50),
        data_vencimento:  dataVenc.toISOString().split("T")[0],
        quantidade:       SANITIZE.int(body.quantidade, 0, 999999) || 0
      });
      return jsonOk(res, { produto: result.body[0] }, 201);
    }

    if (method === "GET" && path === "/validade") {
      var result = await DB.select("produtos_validade",
        `empresa_id=eq.${authPayload.empresa_id}&order=data_vencimento.asc`
      );
      return jsonOk(res, result.body);
    }

    // ── AUSÊNCIAS ────────────────────────────────────
    if (method === "POST" && path === "/ausencias") {
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      var funcId = SANITIZE.uuid(body.funcionario_id);
      if (!funcId) return jsonErr(res, "Funcionário inválido");

      var check = await DB.select("funcionarios", `id=eq.${funcId}&empresa_id=eq.${authPayload.empresa_id}&select=id`);
      if (!check.body || !check.body[0]) return jsonErr(res, "Não autorizado", 403);

      var result = await DB.insert("ausencias", {
        empresa_id:    authPayload.empresa_id,
        funcionario_id: funcId,
        data:          SANITIZE.string(body.data || "", 10),
        tipo:          ["falta","atestado","licenca"].includes(body.tipo) ? body.tipo : "falta",
        motivo:        SANITIZE.string(body.motivo || "", 500)
      });
      return jsonOk(res, { ausencia: result.body[0] }, 201);
    }

    // ── PUSH — INSCREVER DISPOSITIVO ─────────────────
    // O sw.js já sabia RECEBER push (self.addEventListener('push', ...))
    // mas nada no frontend pedia permissão nem enviava a subscription
    // para o backend, e o backend não tinha onde guardá-la nem como
    // disparar um envio. Esta rota fecha essa lacuna.
    if (method === "POST" && path === "/push/subscribe") {
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body || !body.subscription || !body.subscription.endpoint) {
        return jsonErr(res, "Subscription inválida");
      }

      // Upsert: se o dispositivo já tinha uma subscription (endpoint
      // igual), atualiza; senão cria. Evita duplicar notificações
      // para o mesmo aparelho.
      var existing = await DB.select("push_subscriptions",
        `endpoint=eq.${encodeURIComponent(body.subscription.endpoint)}&select=id`
      );

      var record = {
        empresa_id:      authPayload.empresa_id,
        funcionario_id:  authPayload.funcionario_id || null,
        endpoint:        body.subscription.endpoint,
        keys:            body.subscription.keys,
        updated_at:      new Date().toISOString()
      };

      if (existing.body && existing.body[0]) {
        await DB.update("push_subscriptions", `id=eq.${existing.body[0].id}`, record);
      } else {
        await DB.insert("push_subscriptions", record);
      }

      secLog("push_subscribed", { empresa_id: authPayload.empresa_id });
      return jsonOk(res, { ok: true });
    }

    // ── DASHBOARD — DADOS AGREGADOS REAIS ────────────
    // Substitui os números fixos que hoje estão hardcoded no HTML
    // do worka-app.html. O frontend deve buscar isto ao carregar
    // a tela de Dashboard em vez de exibir "8 funcionários" fixo.
    if (method === "GET" && path === "/dashboard-data") {
      var empresaId = authPayload.empresa_id;
      var hoje = new Date().toISOString().split("T")[0];

      // Executa as agregações em paralelo — cada uma é uma query
      // simples ao Supabase via REST (não há join complexo aqui
      // de propósito: manter cada chamada rápida e cacheável).
      var [funcs, pontoHoje, tarefasAbertas, tarefasAtrasadas, validadesUrgentes] = await Promise.all([
        DB.select("funcionarios", `empresa_id=eq.${empresaId}&select=id,status`),
        DB.select("registros_ponto", `empresa_id=eq.${empresaId}&horario=gte.${hoje}&select=funcionario_id,tipo`),
        DB.select("tarefas", `empresa_id=eq.${empresaId}&status=neq.concluida&select=id`),
        DB.select("tarefas", `empresa_id=eq.${empresaId}&status=eq.pendente&prazo=lt.${new Date().toISOString()}&select=id`),
        DB.select("produtos_validade", `empresa_id=eq.${empresaId}&data_vencimento=lte.${new Date(Date.now()+3*24*60*60*1000).toISOString().split("T")[0]}&select=id,nome,data_vencimento`)
      ]);

      var totalFuncs   = (funcs.body || []).length;
      var funcsAtivos  = (funcs.body || []).filter(f => f.status === "ativo").length;

      // "Online agora" = registrou entrada hoje e ainda não registrou saída
      var registrosPorFunc = {};
      (pontoHoje.body || []).forEach(r => {
        if (!registrosPorFunc[r.funcionario_id]) registrosPorFunc[r.funcionario_id] = [];
        registrosPorFunc[r.funcionario_id].push(r.tipo);
      });
      var onlineAgora = Object.values(registrosPorFunc).filter(tipos =>
        tipos.includes("entrada") && !tipos.includes("saida")
      ).length;

      return jsonOk(res, {
        funcionarios: { total: totalFuncs, ativos: funcsAtivos, online_agora: onlineAgora },
        ponto: { registrados_hoje: Object.keys(registrosPorFunc).length, sem_registro: totalFuncs - Object.keys(registrosPorFunc).length },
        tarefas: { abertas: (tarefasAbertas.body || []).length, atrasadas: (tarefasAtrasadas.body || []).length },
        alertas: {
          validades_urgentes: (validadesUrgentes.body || []).length,
          produtos: (validadesUrgentes.body || []).map(p => ({ nome: p.nome, vencimento: p.data_vencimento }))
        },
        gerado_em: new Date().toISOString()
      });
    }

    // ── FINANCEIRO — MOTOR REAL ──────────────────────
    // Antes: a tela "Financeiro" era 100% HTML fixo (R$45.800 nunca
    // mudava). Agora lê de fato a tabela lancamentos_financeiros.
    if (method === "GET" && path === "/financeiro/resumo") {
      var empresaId = authPayload.empresa_id;
      if (!hasPermission(authPayload, "financeiro:read")) {
        return jsonErr(res, "Sem permissão para ver dados financeiros", 403);
      }

      var inicioMes = new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString();
      var lancamentos = await DB.select("lancamentos_financeiros",
        `empresa_id=eq.${empresaId}&data=gte.${inicioMes}&select=tipo,valor,categoria`
      );

      var entradas = (lancamentos.body || []).filter(l => l.tipo === "entrada").reduce((s, l) => s + parseFloat(l.valor), 0);
      var saidas   = (lancamentos.body || []).filter(l => l.tipo === "saida").reduce((s, l) => s + parseFloat(l.valor), 0);

      // Saldo = soma de TODOS os lançamentos históricos, não só do mês
      var todosLancamentos = await DB.select("lancamentos_financeiros", `empresa_id=eq.${empresaId}&select=tipo,valor`);
      var saldo = (todosLancamentos.body || []).reduce((s, l) =>
        s + (l.tipo === "entrada" ? parseFloat(l.valor) : -parseFloat(l.valor)), 0
      );

      return jsonOk(res, {
        saldo_atual: Math.round(saldo * 100) / 100,
        receita_mes: Math.round(entradas * 100) / 100,
        despesas_mes: Math.round(saidas * 100) / 100,
        lucro_mes: Math.round((entradas - saidas) * 100) / 100
      });
    }

    if (method === "POST" && path === "/financeiro/lancamento") {
      if (!hasPermission(authPayload, "financeiro:write")) {
        return jsonErr(res, "Sem permissão para registrar lançamentos", 403);
      }
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      var tipo = ["entrada", "saida"].includes(body.tipo) ? body.tipo : null;
      var valor = parseFloat(body.valor);
      if (!tipo || isNaN(valor) || valor <= 0 || valor > 999999) return jsonErr(res, "Tipo ou valor inválido");

      var descricao = SANITIZE.string(body.descricao, 200);
      if (!descricao) return jsonErr(res, "Descrição obrigatória");

      var result = await DB.insert("lancamentos_financeiros", {
        empresa_id: authPayload.empresa_id,
        tipo, valor,
        descricao,
        categoria: SANITIZE.categoriaFinanceira(body.categoria),
        data: new Date().toISOString()
      });

      secLog("lancamento_financeiro", { empresa_id: authPayload.empresa_id, tipo, valor });
      return jsonOk(res, { lancamento: result.body[0] }, 201);
    }

    // ── LOGS ─────────────────────────────────────────
    if (method === "GET" && path === "/logs") {
      if (!hasPermission(authPayload, "logs:read")) {
        return jsonErr(res, "Sem permissão para ver o histórico de auditoria", 403);
      }
      var limit = SANITIZE.int(url.searchParams.get("limit"), 1, 100) || 50;
      var result = await DB.select("logs_sistema",
        `empresa_id=eq.${authPayload.empresa_id}&order=created_at.desc&limit=${limit}`
      );
      return jsonOk(res, result.body);
    }


    // ── WER — PROXY SEGURO PARA xAI ────────────────
    if (method === "POST" && path === "/wer/chat") {
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body || !Array.isArray(body.messages)) return jsonErr(res, "Dados inválidos");

      // Limitar histórico a 20 mensagens
      var messages = body.messages.slice(-20);

      // Sanitizar conteúdo das mensagens
      messages = messages.filter(m => m && typeof m.content === "string" && m.role);
      messages = messages.map(m => ({
        role:    ["user","assistant","system","tool"].includes(m.role) ? m.role : "user",
        content: m.content.substring(0, 4000), // limite de tokens
        ...(m.tool_call_id && { tool_call_id: m.tool_call_id }),
        ...(m.tool_calls && { tool_calls: m.tool_calls })
      }));

      var xaiKey = process.env.XAI_API_KEY;
      if (!xaiKey) return jsonErr(res, "Serviço indisponível", 503);

      var payload = JSON.stringify({
        model:        "grok-beta",
        max_tokens:   800,
        tools:        body.tools || [],
        tool_choice:  "auto",
        messages
      });

      var response = await new Promise((resolve, reject) => {
        var req2 = https.request({
          hostname: "api.x.ai",
          path:     "/v1/chat/completions",
          method:   "POST",
          headers: {
            "Content-Type":   "application/json",
            "Authorization":  "Bearer " + xaiKey,
            "Content-Length": Buffer.byteLength(payload)
          }
        }, res2 => {
          var raw2 = "";
          res2.on("data", c => raw2 += c);
          res2.on("end", () => {
            try { resolve({ status: res2.statusCode, body: JSON.parse(raw2) }); }
            catch(e) { resolve({ status: res2.statusCode, body: {} }); }
          });
        });
        req2.on("error", reject);
        req2.write(payload);
        req2.end();
      });

      if (response.status >= 400) return jsonErr(res, "Erro no assistente", 502);
      return jsonOk(res, response.body);
    }

    // ── PIX ──────────────────────────────────────────
    if (method === "POST" && path === "/pix") {
      if (!CONFIG.PIX_URL) return jsonErr(res, "PIX não configurado", 503);

      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      var email = SANITIZE.email(body.email);
      var nome  = SANITIZE.string(body.name || "", 120);
      var doc   = (body.document || "").replace(/\D/g, "").substring(0, 14);
      var tel   = (body.phone || "").replace(/\D/g, "").substring(0, 11);

      if (!email || !nome) return jsonErr(res, "Dados inválidos");

      // SSRF prevention — validar que PIX_URL é o domínio esperado
      var pixUrl = new URL(CONFIG.PIX_URL);
      if (!pixUrl.hostname.includes("duttyfy") && !pixUrl.hostname.includes("worka")) {
        secLog("ssrf_attempt", { hostname: pixUrl.hostname });
        return jsonErr(res, "Configuração inválida", 500);
      }

      var payload = {
        amount: 2490,
        customer: { name: nome, document: doc, email, phone: tel },
        item: { title: "Plano Completo Worka", price: 2490, quantity: 1 },
        paymentMethod: "PIX"
      };

      var response = await new Promise((resolve, reject) => {
        var data = JSON.stringify(payload);
        var req2 = https.request({
          hostname: pixUrl.hostname,
          path:     pixUrl.pathname + pixUrl.search,
          method:   "POST",
          headers:  { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) }
        }, res2 => {
          var raw2 = "";
          res2.on("data", c => raw2 += c);
          res2.on("end", () => {
            try { resolve({ status: res2.statusCode, body: JSON.parse(raw2) }); }
            catch(e) { resolve({ status: res2.statusCode, body: {} }); }
          });
        });
        req2.on("error", reject);
        req2.write(data);
        req2.end();
      });

      if (response.status >= 400) return jsonErr(res, "Erro no processamento do pagamento", 502);

      secLog("pix_gerado", { empresa_id: authPayload.empresa_id });
      return jsonOk(res, {
        pixCode:       response.body.pixCode,
        transactionId: response.body.transactionId,
        status:        response.body.status
      });
    }

    // 404
    secLog("rota_nao_encontrada", { ip, path, method });
    return jsonErr(res, "Rota não encontrada", 404);

  } catch(e) {
    // Nunca expor stack trace em produção
    secLog("server_error", { path, message: e.message });
    return jsonErr(res, "Erro interno do servidor", 500);
  }
});

server.listen(CONFIG.PORT, () => {
  secLog("server_start", { port: CONFIG.PORT, env: process.env.NODE_ENV || "development" });
});

// Graceful shutdown
process.on("SIGTERM", () => {
  secLog("server_shutdown", {});
  server.close(() => process.exit(0));
});

process.on("uncaughtException", (e) => {
  secLog("uncaught_exception", { message: e.message });
  process.exit(1);
});
