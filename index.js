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
  // Conta administrativa única da Worka (painel Owner). Opcional — se
  // não configurada, a rota /login/owner responde 503 em vez de negar
  // acesso a uma conta que não existe. OWNER_PASSWORD_HASH é o hash
  // bcrypt da senha (gerar com: node -e "console.log(require('bcryptjs').hashSync('SUA_SENHA',12))"),
  // nunca a senha em texto plano.
  OWNER_EMAIL:         process.env.OWNER_EMAIL ? process.env.OWNER_EMAIL.toLowerCase() : null,
  OWNER_PASSWORD_HASH: process.env.OWNER_PASSWORD_HASH || null,
  BCRYPT_ROUNDS: 12,
  JWT_EXPIRES:   "8h",
  // Valor do plano em CENTAVOS — é assim que o gateway PIX espera
  // receber. Fonte única da verdade: o cálculo de desconto por cupom
  // e a cobrança partem daqui, para o preço nunca divergir entre a
  // tela de checkout e o que é realmente cobrado.
  PLANO_CENTAVOS: 4999,
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
  "/recuperar-senha": { max: 3,  window: 15 * 60 * 1000 }, // 3/15min — anti spam de email
  "/redefinir-senha": { max: 5,  window: 15 * 60 * 1000 }, // 5/15min — anti brute force do código
  "/cupom/validar":  { max: 20,  window: 10 * 60 * 1000 }, // 20/10min — anti varredura de cupons
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
var PERMISSOES_DONO = [
  "funcionarios:read", "funcionarios:write", "funcionarios:delete",
  "salarios:read", "salarios:write",
  "financeiro:read", "financeiro:write",
  "ponto:read", "ponto:write",
  "tarefas:read", "tarefas:write",
  "validade:read", "validade:write",
  "ausencias:read", "ausencias:write",
  "logs:read",
  "config:write"
];

var ROLE_PERMISSIONS = {
  dono: new Set(PERMISSOES_DONO),
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
  // Dono da Worka (não do cliente). Recebe as mesmas permissões de um
  // "dono" — para navegar por todas as telas do produto — MAIS as
  // permissões administrativas do painel Owner (incluindo cupons).
  //
  // Importante: dar permissão de dono NÃO dá acesso aos dados de
  // nenhuma empresa cliente. Toda rota filtra por
  // `authPayload.empresa_id`, que vem do JWT, e o token de owner é
  // emitido sem empresa_id — então as consultas não casam com empresa
  // alguma. Na prática o owner enxerga o produto inteiro, com os dados
  // da própria conta (vazios), e nunca a conta de outra pessoa.
  owner_saas: new Set([
    ...PERMISSOES_DONO,
    "saas:read", "saas:write",
    "cupons:read", "cupons:write"
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
    "lancamentos_financeiros", "push_subscriptions", "cupons"
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
      hostname: new URL(CONFIG.SUPABASE_URL).hostname,
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
// CUPONS DE DESCONTO
// ════════════════════════════════════════

/**
 * Busca um cupom pelo código e valida se ele pode ser usado agora.
 * Devolve sempre o mesmo formato — { ok, erro?, cupom?, ... } — para
 * a rota de preview (/cupom/validar) e a de cobrança (/pix) usarem
 * exatamente a mesma regra. Duplicar essa lógica nos dois lugares
 * abriria espaço para o checkout mostrar um preço e o cliente ser
 * cobrado outro.
 *
 * O desconto é calculado em CENTAVOS o tempo todo (nunca em reais
 * com casa decimal) para não acumular erro de ponto flutuante no
 * valor que vai para o gateway de pagamento.
 */
async function validarCupom(codigoBruto) {
  var codigo = SANITIZE.string(codigoBruto || "", 40).toUpperCase().trim();
  if (!codigo) return { ok: false, erro: "Informe um código de cupom." };

  var resultado = await supabase("GET", "cupons",
    { query: `codigo=eq.${encodeURIComponent(codigo)}&select=*&limit=1` }
  ).catch(e => {
    // Tabela ainda não criada no banco (migration não rodada) ou banco
    // fora do ar: tratado como "cupom não encontrado" para o checkout
    // seguir funcionando sem desconto, em vez de travar a venda.
    secLog("cupom_lookup_falhou", { message: e.message });
    return { body: [] };
  });

  var cupom = resultado.body && resultado.body[0];
  if (!cupom) return { ok: false, erro: "Cupom não encontrado." };
  if (!cupom.ativo) return { ok: false, erro: "Este cupom não está mais ativo." };

  if (cupom.validade) {
    // Compara só a data (sem hora): um cupom válido "até 31/12" deve
    // funcionar o dia 31 inteiro, não expirar à meia-noite do dia 30.
    var hojeStr = new Date().toISOString().split("T")[0];
    if (cupom.validade < hojeStr) return { ok: false, erro: "Este cupom expirou." };
  }

  if (cupom.usos_max != null && (cupom.usos || 0) >= cupom.usos_max) {
    return { ok: false, erro: "Este cupom atingiu o limite de usos." };
  }

  var valorCupom = parseFloat(cupom.valor);
  if (isNaN(valorCupom) || valorCupom <= 0) return { ok: false, erro: "Cupom inválido." };

  var precoOriginal = CONFIG.PLANO_CENTAVOS;
  var desconto;
  if (cupom.tipo === "percentual") {
    if (valorCupom > 100) valorCupom = 100; // trava de segurança
    desconto = Math.round(precoOriginal * (valorCupom / 100));
  } else {
    desconto = Math.round(valorCupom * 100); // reais → centavos
  }

  // Nunca deixar o valor final ficar zero ou negativo: um PIX de R$ 0
  // seria rejeitado pelo gateway e um valor negativo é sem sentido.
  // Piso de R$ 1,00 — cupons de 100% precisam de um fluxo próprio de
  // "conta cortesia", que não existe hoje.
  if (desconto >= precoOriginal) desconto = precoOriginal - 100;
  if (desconto < 0) desconto = 0;

  return {
    ok: true,
    cupom,
    codigo,
    desconto_centavos: desconto,
    valor_original_centavos: precoOriginal,
    valor_final_centavos: precoOriginal - desconto
  };
}

// Formata centavos como "49,99" para exibir/enviar em texto.
function centavosParaReais(centavos) {
  return (centavos / 100).toFixed(2).replace(".", ",");
}

// ════════════════════════════════════════
// ARMAZENAMENTO SEGURO DE CÓDIGOS OTP
// (Render free reinicia a instância por inatividade — um Map() em
// memória perderia todo código pendente nesse restart, forçando o
// usuário a recomeçar o cadastro no meio. Persistido em
// codigos_verificacao para sobreviver a isso.)
// ════════════════════════════════════════

async function salvarOTP(email, codigo) {
  // Hash do código para nunca armazenar em plaintext — mesma
  // disciplina da versão em memória, agora persistida.
  var hash = crypto.createHash("sha256").update(codigo + email).digest("hex");
  var expiraEm = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 min

  // Invalida qualquer código anterior não usado para este email antes
  // de criar um novo, para não deixar múltiplos códigos válidos ao
  // mesmo tempo (cada "reenviar código" deveria matar o anterior).
  await supabase("PATCH", "codigos_verificacao",
    { query: `email=eq.${encodeURIComponent(email)}&usado=is.false`, body: { usado: true } }
  ).catch(() => {});

  await supabase("POST", "codigos_verificacao", {
    body: { email, codigo_hash: hash, expira_em: expiraEm, usado: false, tentativas: 0 }
  });
}

async function verificarOTP(email, codigo) {
  var result = await supabase("GET", "codigos_verificacao",
    { query: `email=eq.${encodeURIComponent(email)}&usado=is.false&order=created_at.desc&limit=1` }
  ).catch(() => ({ body: [] }));

  var entry = result.body && result.body[0];
  if (!entry) return { ok: false, erro: "Código não encontrado" };

  if (new Date(entry.expira_em).getTime() < Date.now()) {
    await supabase("PATCH", "codigos_verificacao", { query: `id=eq.${entry.id}`, body: { usado: true } }).catch(() => {});
    return { ok: false, erro: "Código expirado" };
  }

  // Máximo 5 tentativas (anti brute force) — mesmo limite da versão anterior
  var tentativas = (entry.tentativas || 0) + 1;
  if (tentativas > 5) {
    await supabase("PATCH", "codigos_verificacao", { query: `id=eq.${entry.id}`, body: { usado: true } }).catch(() => {});
    secLog("otp_brute_force", { email_hash: crypto.createHash("sha256").update(email).digest("hex").substring(0, 8) });
    return { ok: false, erro: "Muitas tentativas. Solicite um novo código." };
  }
  await supabase("PATCH", "codigos_verificacao", { query: `id=eq.${entry.id}`, body: { tentativas } }).catch(() => {});

  var hash = crypto.createHash("sha256").update(codigo + email).digest("hex");
  var hashBuf = Buffer.from(hash);
  var entryBuf = Buffer.from(entry.codigo_hash);
  // timingSafeEqual exige buffers do mesmo tamanho — ambos são SHA-256
  // hex (64 chars) então sempre batem em tamanho, mas a checagem evita
  // exception caso o dado no banco esteja corrompido por algum motivo.
  if (hashBuf.length !== entryBuf.length || !crypto.timingSafeEqual(hashBuf, entryBuf)) {
    return { ok: false, erro: "Código inválido" };
  }

  await supabase("PATCH", "codigos_verificacao", { query: `id=eq.${entry.id}`, body: { usado: true } }).catch(() => {});
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
      <p style="margin:0;font-size:13px;color:#78350f">⏰ Trial termina em <strong>${new Date(trialFim).toLocaleDateString("pt-BR")}</strong>. Após: R$ 49,99/mês.</p>
    </div>`),

  pagamentoConfirmado: (nome, valor) => emailBase(`
    <h2 style="text-align:center;margin:0 0 8px;color:#0a2e1a;font-size:22px;font-weight:800">Pagamento confirmado! ✅</h2>
    <p style="color:#5a6b5a;text-align:center;margin:0 0 24px">Olá, <strong>${SANITIZE.string(nome)}</strong>! Seu pagamento foi processado.</p>
    <div style="background:#f7f9f7;border-radius:16px;padding:24px">
      <table width="100%"><tr><td style="font-size:13px;color:#6b7a6b">Valor</td><td style="font-weight:900;color:#1e8a40;text-align:right">R$ ${SANITIZE.string(valor)}</td></tr></table>
    </div>`),

  trialAcabando: (nome, dias) => emailBase(`
    <h2 style="text-align:center;margin:0 0 8px;color:#0a2e1a;font-weight:800">Seu trial acaba em ${SANITIZE.int(dias, 0, 30)} dia(s)! ⏰</h2>
    <p style="color:#5a6b5a;text-align:center">Olá, <strong>${SANITIZE.string(nome)}</strong>! Renove por R$ 49,99/mês para não perder o acesso.</p>`),

  trialExpirado: (nome) => emailBase(`
    <h2 style="text-align:center;margin:0 0 8px;color:#0a2e1a;font-weight:800">Seu trial expirou 😢</h2>
    <p style="color:#5a6b5a;text-align:center">Olá, <strong>${SANITIZE.string(nome)}</strong>! Seus dados estão salvos. Reative por R$ 49,99/mês.</p>`),

  recuperarSenha: (nome, codigo) => emailBase(`
    <h2 style="margin:0 0 8px;color:#0a2e1a;font-size:22px;font-weight:800">Redefinir sua senha 🔑</h2>
    <p style="color:#5a6b5a;font-size:15px;margin:0 0 28px;line-height:1.6">Olá, <strong>${SANITIZE.string(nome)}</strong>! Recebemos um pedido para redefinir a senha da sua conta Worka. Use o código abaixo:</p>
    <div style="background:linear-gradient(135deg,#0a2e1a,#16622f);border-radius:16px;padding:28px;text-align:center;margin:0 0 28px">
      <div style="font-size:44px;font-weight:900;color:#3dd669;letter-spacing:14px;font-family:'Courier New',monospace">${codigo}</div>
      <div style="font-size:13px;color:rgba(255,255,255,.6);margin-top:10px">⏰ Expira em <strong style="color:#fff">10 minutos</strong></div>
    </div>
    <div style="background:#fff5f5;border-radius:12px;padding:16px;border-left:4px solid #ef4444">
      <p style="margin:0;font-size:13px;color:#991b1b">🔒 <strong>Não foi você?</strong> Ignore este e-mail — sua senha atual continua valendo e nada foi alterado.</p>
    </div>`)
};

// ════════════════════════════════════════
// HELPERS HTTP
// ════════════════════════════════════════

/**
 * Faz uma requisição HTTP(S) a um serviço externo e resolve com
 * { status, body } (body já parseado como JSON quando possível).
 * Único ponto de implementação — antes, cada rota que precisava
 * chamar uma API externa reimplementava a mesma Promise de
 * https.request na mão, com pequenas variações.
 */
function httpRequestExterno(urlObj, method, payload, headersExtra) {
  return new Promise((resolve, reject) => {
    var data = payload ? JSON.stringify(payload) : null;
    var headers = Object.assign({}, headersExtra || {});
    if (data) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(data);
    }
    var req2 = https.request({
      hostname: urlObj.hostname,
      path:     urlObj.pathname + urlObj.search,
      method:   method,
      headers:  headers
    }, res2 => {
      var raw2 = "";
      res2.on("data", c => raw2 += c);
      res2.on("end", () => {
        try { resolve({ status: res2.statusCode, body: JSON.parse(raw2) }); }
        catch(e) { resolve({ status: res2.statusCode, body: {} }); }
      });
    });
    req2.on("error", reject);
    if (data) req2.write(data);
    req2.end();
  });
}

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

      // Mensagem distinta para "não existe conta" vs "senha errada", a
      // pedido do produto: sem isso, quem ainda não se cadastrou ficava
      // preso tentando a senha de novo, achando que tinha errado a senha.
      // Contrapartida consciente: isso permite descobrir se um e-mail tem
      // conta na Worka (enumeração de usuários). O risco é aceitável aqui
      // porque a lista de e-mails de empresas clientes não é segredo, e o
      // rate limit de 5 tentativas/15min já barra varredura em massa.
      if (!empresa) {
        secLog("login_email_inexistente", { ip });
        res.writeHead(401);
        return res.end(JSON.stringify({
          error: "Não encontramos uma conta com esse e-mail. Você precisa realizar o cadastro.",
          nao_cadastrado: true
        }));
      }

      if (!senhaOk) {
        secLog("login_falhou", { ip, email_hash: crypto.createHash("sha256").update(v.data.email).digest("hex").substring(0, 8) });
        return jsonErr(res, "Senha incorreta. Tente novamente ou use \"Esqueci minha senha\".", 401);
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

      // O role do RBAC deriva do cargo cadastrado. A comparação por
      // nome de texto ("Gerente") nunca funcionava de verdade: a
      // coluna real em funcionarios é cargo_id (uuid, FK para a
      // tabela cargos), não existe coluna de texto "cargo" — então
      // funcionario.cargo era sempre undefined e todo funcionário
      // caía em "funcionario", nunca em "gerente", mesmo quando
      // deveria. A tabela cargos existe mas nenhuma rota a popula ou
      // resolve ainda, então não há como promover alguém a gerente
      // de forma confiável hoje. Até essa funcionalidade existir,
      // todo funcionário recebe o menor privilégio de propósito —
      // é o comportamento seguro, não o "quase certo por acaso".
      var rbacRole = "funcionario";
      var token = jwtSign({ funcionario_id: funcionario.id, empresa_id: empresa.id, role: rbacRole });
      delete funcionario.senha_hash;
      secLog("login_func_ok", { funcionario_id: funcionario.id });
      return jsonOk(res, { token, funcionario, empresa });
    }

    // ── LOGIN OWNER (conta administrativa única da Worka) ───
    // Substitui a checagem anterior, que comparava email/senha em
    // texto plano dentro do JavaScript do frontend (worka.html e
    // worka-app.html) — qualquer pessoa via "Ver código-fonte" via a
    // senha real. Agora a senha nunca sai do servidor: só o hash
    // bcrypt fica configurado (via OWNER_PASSWORD_HASH), a mesma
    // disciplina de todo o resto deste arquivo.
    if (method === "POST" && path === "/login/owner") {
      if (!CONFIG.OWNER_EMAIL || !CONFIG.OWNER_PASSWORD_HASH) {
        return jsonErr(res, "Login de owner não configurado", 503);
      }
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      var v = validate(body, {
        email: v => SANITIZE.email(v),
        senha: v => typeof v === "string" && v.length >= 1 ? v : null,
      });
      if (!v.ok) return jsonErr(res, "Email ou senha inválidos", 401);

      // bcrypt.compare roda sempre, mesmo com email errado, para não
      // vazar por timing se o email configurado bate ou não.
      var senhaOk = await verificarSenha(v.data.senha, CONFIG.OWNER_PASSWORD_HASH);
      var emailOk = v.data.email === CONFIG.OWNER_EMAIL;

      if (!emailOk || !senhaOk) {
        secLog("login_owner_falhou", { ip });
        return jsonErr(res, "Email ou senha incorretos", 401);
      }

      var token = jwtSign({ email: v.data.email, role: "owner_saas" });
      secLog("login_owner_ok", {});
      return jsonOk(res, { token, owner: { nome: "Owner Worka", email: v.data.email } });
    }

    // ── ENVIAR CÓDIGO OTP ───────────────────────────
    if (method === "POST" && path === "/enviar-codigo") {
      // Rate limiting já aplicado no bloco global (checkRateLimit acima),
      // via RATE_LIMITS["/enviar-codigo"] = 3/10min — mesma janela que
      // havia aqui duplicada sob uma chave diferente ("otp:"+ip).

      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      var email = SANITIZE.email(body.email);
      if (!email) return jsonErr(res, "Email inválido");

      var nome = SANITIZE.string(body.name || "Cliente", 80);
      var codigo = gerarCodigo();
      await salvarOTP(email, codigo);

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

      var otpResult = await verificarOTP(email, codigo);
      if (!otpResult.ok) return jsonErr(res, otpResult.erro);

      secLog("otp_verificado", { email_hash: crypto.createHash("sha256").update(email).digest("hex").substring(0, 8) });

      // Se enviar dados de empresa, cadastrar automaticamente
      if (body.nome && body.senha) {
        var nome  = SANITIZE.string(body.nome, 120);
        var senha = SANITIZE.senha(body.senha);
        if (!nome || !senha) return jsonErr(res, "Dados de cadastro inválidos");

        // BUG CORRIGIDO: antes, o INSERT era feito direto e um email já
        // cadastrado fazia o banco rejeitar por chave única. O
        // .catch(() => ({ body: [] })) engolia esse erro em silêncio e a
        // função caía no `return jsonOk(res, { ok: true })` lá embaixo —
        // então o site mostrava "Trial ativado!" com toda a confiança,
        // sem ter criado conta nenhuma e sem devolver token. A pessoa
        // saía achando que tinha conta, e não conseguia logar depois.
        // Agora a existência é checada ANTES, com resposta explícita.
        var jaExiste = await DB.select("empresas", `email=eq.${encodeURIComponent(email)}&select=id`);
        if (jaExiste.body && jaExiste.body.length > 0) {
          secLog("cadastro_duplicado_trial", { email_hash: crypto.createHash("sha256").update(email).digest("hex").substring(0, 8) });
          // ja_cadastrado permite o frontend oferecer "Fazer login" em vez
          // de só mostrar um erro genérico e deixar a pessoa travada.
          res.writeHead(409);
          return res.end(JSON.stringify({
            error: "Este e-mail já tem uma conta Worka. Faça login para continuar.",
            ja_cadastrado: true
          }));
        }

        var senhaHash = await hashSenha(senha);
        var trialFim  = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

        var result = await DB.insert("empresas", {
          nome, email, senha_hash: senhaHash,
          team_id: gerarTeamId(), status: "trial",
          trial_fim: trialFim, aviso_trial_sent: false, aviso_expirado_sent: false
        }).catch(e => { secLog("erro_criar_empresa", { message: e.message }); return { body: [] }; });

        if (result.body[0]) {
          var emp = result.body[0];
          var token = jwtSign({ empresa_id: emp.id, email: emp.email, role: "dono" });
          enviarEmail(emp.email, "🎉 Bem-vindo ao Worka!", EMAIL_TEMPLATES.boasVindas(emp.nome, emp.team_id, trialFim))
            .catch(() => {});
          secLog("empresa_via_otp", { empresa_id: emp.id });
          delete emp.senha_hash;
          return jsonOk(res, { ok: true, token, empresa: emp, trial_fim: trialFim });
        }

        // Chegou aqui: o insert falhou por outro motivo (banco fora do ar,
        // coluna faltando etc.). Nunca mais responder ok:true nesse caso —
        // era exatamente isso que fazia o site mentir "Trial ativado!".
        return jsonErr(res, "Não foi possível criar sua conta agora. Tente novamente em instantes.", 500);
      }

      return jsonOk(res, { ok: true });
    }

    // ── RECUPERAR SENHA — PEDIR CÓDIGO (rota pública) ─
    // Reaproveita a mesma infra de OTP do cadastro (tabela
    // codigos_verificacao, com hash do código e limite de tentativas),
    // em vez de criar um segundo mecanismo de token por email.
    if (method === "POST" && path === "/recuperar-senha") {
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      var email = SANITIZE.email(body.email);
      if (!email) return jsonErr(res, "E-mail inválido");

      var contaResult = await DB.select("empresas", `email=eq.${encodeURIComponent(email)}&select=id,nome`);
      var conta = contaResult.body && contaResult.body[0];

      // Diferente do login, aqui a resposta é SEMPRE a mesma exista ou
      // não a conta. Um formulário de "esqueci a senha" é aberto ao
      // público e não tem rate limit por conta, então revelar quais
      // e-mails existem aqui viraria uma ferramenta de varredura — e,
      // ao contrário do login, não há ganho de UX real em revelar
      // (quem não tem conta é orientado a conferir o e-mail digitado).
      if (conta) {
        var codigoRec = gerarCodigo();
        await salvarOTP(email, codigoRec);
        secLog("recuperacao_senha_solicitada", { empresa_id: conta.id });
        enviarEmail(email, "🔑 Redefinir sua senha — Worka", EMAIL_TEMPLATES.recuperarSenha(conta.nome, codigoRec))
          .catch(e => secLog("email_error", { type: "recuperar_senha", message: e.message }));
      } else {
        secLog("recuperacao_senha_email_inexistente", { ip });
      }

      return jsonOk(res, { ok: true, message: "Se existir uma conta com esse e-mail, enviamos um código de redefinição." });
    }

    // ── RECUPERAR SENHA — DEFINIR NOVA (rota pública) ─
    if (method === "POST" && path === "/redefinir-senha") {
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      var email = SANITIZE.email(body.email);
      var codigo = SANITIZE.string(body.codigo || "", 6);
      var senhaNova = SANITIZE.senha(body.senha);

      if (!email || !codigo || !/^\d{6}$/.test(codigo)) return jsonErr(res, "Dados inválidos");
      if (!senhaNova) return jsonErr(res, "A nova senha precisa ter no mínimo 8 caracteres, sem espaços.");

      var otpRec = await verificarOTP(email, codigo);
      if (!otpRec.ok) return jsonErr(res, otpRec.erro);

      var contaRec = await DB.select("empresas", `email=eq.${encodeURIComponent(email)}&select=id,nome,team_id,status,trial_fim`);
      var empRec = contaRec.body && contaRec.body[0];
      // O código só é gerado para e-mail existente, então cair aqui
      // significa que a conta sumiu no meio do processo.
      if (!empRec) return jsonErr(res, "Conta não encontrada.", 404);

      var novoHash = await hashSenha(senhaNova);
      await DB.update("empresas", `id=eq.${empRec.id}`, { senha_hash: novoHash });
      secLog("senha_redefinida", { empresa_id: empRec.id });

      // Já devolve o token para a pessoa entrar direto, sem ter que
      // digitar a senha que acabou de criar.
      var tokenRec = jwtSign({ empresa_id: empRec.id, email, role: "dono" });
      var trialRec = null;
      if (empRec.status === "trial") {
        var diasRec = Math.ceil((new Date(empRec.trial_fim) - Date.now()) / (1000*60*60*24));
        trialRec = { dias_restantes: diasRec, expirado: diasRec <= 0 };
      }
      return jsonOk(res, { ok: true, token: tokenRec, empresa: empRec, trial: trialRec });
    }

    // ── CUPOM — VALIDAR / PREVIEW (rota pública) ─────
    // Chamada pelo checkout quando a pessoa digita um código, antes
    // de gerar o PIX, só para mostrar o desconto na tela.
    if (method === "POST" && path === "/cupom/validar") {
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      var checagem = await validarCupom(body.codigo);
      if (!checagem.ok) return jsonErr(res, checagem.erro, 404);

      secLog("cupom_validado", { codigo: checagem.codigo });
      return jsonOk(res, {
        ok: true,
        codigo:         checagem.codigo,
        descricao:      checagem.cupom.descricao || null,
        tipo:           checagem.cupom.tipo,
        valor:          parseFloat(checagem.cupom.valor),
        desconto_reais: centavosParaReais(checagem.desconto_centavos),
        valor_original: centavosParaReais(checagem.valor_original_centavos),
        valor_final:    centavosParaReais(checagem.valor_final_centavos)
      });
    }

    // ── PIX — GERAR COBRANÇA (rota pública) ──────────
    // Chamada pelo formulário de assinatura do site institucional,
    // antes de qualquer login existir — por isso fica na zona
    // pública, junto de /enviar-codigo e /verificar-codigo. Estava
    // antes posicionada depois do bloco JWT, o que fazia todo pedido
    // de pagamento retornar 401 sempre, sem exceção.
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

      var pixUrl = new URL(CONFIG.PIX_URL);
      if (!pixUrl.hostname.includes("duttyfy") && !pixUrl.hostname.includes("worka")) {
        secLog("ssrf_attempt", { hostname: pixUrl.hostname });
        return jsonErr(res, "Configuração inválida", 500);
      }

      // Cupom: o desconto é SEMPRE recalculado aqui no servidor a
      // partir do código enviado. O valor final que o navegador
      // mostrou é ignorado de propósito — se o cliente adulterasse o
      // valor no JavaScript, ele pagaria o que quisesse.
      var valorCobrado = CONFIG.PLANO_CENTAVOS;
      var cupomAplicado = null;
      if (body.cupom) {
        var cupomCheck = await validarCupom(body.cupom);
        if (cupomCheck.ok) {
          valorCobrado = cupomCheck.valor_final_centavos;
          cupomAplicado = cupomCheck;
        }
        // Cupom inválido não bloqueia a compra: cobra o valor cheio.
        // Barrar a venda por causa de um código digitado errado seria
        // perder o cliente na última etapa do funil.
      }

      var response = await httpRequestExterno(pixUrl, "POST", {
        amount: valorCobrado,
        customer: { name: nome, document: doc, email, phone: tel },
        item: { title: "Plano Completo Worka", price: valorCobrado, quantity: 1 },
        paymentMethod: "PIX"
      });

      if (response.status >= 400) return jsonErr(res, "Erro no processamento do pagamento", 502);

      // Contabiliza o uso só depois que a cobrança foi realmente
      // criada no gateway. Fire-and-forget: falhar aqui não pode
      // derrubar um PIX que já foi gerado com sucesso.
      if (cupomAplicado) {
        supabase("PATCH", "cupons", {
          query: `id=eq.${cupomAplicado.cupom.id}`,
          body: { usos: (cupomAplicado.cupom.usos || 0) + 1 }
        }).catch(e => secLog("cupom_incremento_falhou", { message: e.message }));
        secLog("cupom_usado", { codigo: cupomAplicado.codigo, valor_final: valorCobrado });
      }

      secLog("pix_gerado", { email_hash: crypto.createHash("sha256").update(email).digest("hex").substring(0, 8), valor: valorCobrado });
      return jsonOk(res, {
        pixCode:       response.body.pixCode,
        transactionId: response.body.transactionId,
        status:        response.body.status,
        valor_cobrado: centavosParaReais(valorCobrado),
        cupom_aplicado: cupomAplicado ? cupomAplicado.codigo : null
      });
    }

    // ── PIX — CONSULTAR STATUS (rota pública) ────────
    // Implementação nova: esta rota nunca existiu no backend v5.
    // O site fazia polling contra ela a cada 5s esperando confirmação
    // de pagamento, mas como a rota não existia (404), o polling
    // sempre falhava silenciosamente até o timeout de 15min mostrar
    // "PIX expirado" — mesmo quando o cliente pagava de verdade.
    // Existia uma versão em v2 do backend, perdida na reescrita de
    // segurança sem ser portada; reimplementada aqui já com a
    // ativação real da empresa quando o pagamento é confirmado.
    if (method === "GET" && path === "/pix") {
      if (!CONFIG.PIX_URL) return jsonErr(res, "PIX não configurado", 503);

      var transactionId = url.searchParams.get("transactionId");
      var emailConsulta  = SANITIZE.email(url.searchParams.get("email"));
      if (!transactionId) return jsonErr(res, "transactionId obrigatório");

      var pixUrl2 = new URL(CONFIG.PIX_URL);
      if (!pixUrl2.hostname.includes("duttyfy") && !pixUrl2.hostname.includes("worka")) {
        secLog("ssrf_attempt", { hostname: pixUrl2.hostname });
        return jsonErr(res, "Configuração inválida", 500);
      }
      pixUrl2.searchParams.set("transactionId", transactionId);

      var statusResp = await httpRequestExterno(pixUrl2, "GET");
      if (statusResp.status >= 400) return jsonErr(res, "Erro ao consultar pagamento", 502);

      var statusPix = statusResp.body && statusResp.body.status;

      // Se aprovado e temos o email do cliente, ativa a assinatura de
      // verdade: status=ativa, +30 dias de acesso, email de confirmação.
      // Idempotente por natureza (o polling chama isto a cada 5s até
      // parar) — o UPDATE roda de novo em cada chamada enquanto o
      // status seguir "COMPLETED", mas isso é inofensivo (mesmos
      // valores), não duplica cobrança nem envia e-mails em duplicidade
      // graças ao filtro "status=neq.ativa" abaixo.
      if (statusPix === "COMPLETED" && emailConsulta) {
        var empresaPag = await DB.select("empresas", `email=eq.${encodeURIComponent(emailConsulta)}&status=neq.ativa&select=id,nome,email`);
        if (empresaPag.body && empresaPag.body[0]) {
          var empPag = empresaPag.body[0];
          var novoFim = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
          await DB.update("empresas", `id=eq.${empPag.id}`, {
            status: "ativa",
            trial_fim: novoFim,
            aviso_trial_sent: false,
            aviso_expirado_sent: false
          });
          enviarEmail(empPag.email, "✅ Pagamento confirmado — Worka", EMAIL_TEMPLATES.pagamentoConfirmado(empPag.nome, "49,99"))
            .catch(() => {});
          secLog("pagamento_confirmado", { empresa_id: empPag.id });
        }
      }

      return jsonOk(res, { status: statusPix });
    }
    // Rotas abaixo checam permissão específica via requirePermission()
    // em vez de só validar o token — isso é o que efetivamente
    // impede um funcionário comum de chamar rotas de dono/gerente.
    var authPayload = requireAuth(req);
    if (!authPayload) {
      secLog("auth_required", { ip, path });
      return jsonErr(res, "Autenticação necessária", 401);
    }

    // ── SESSÃO ATUAL (restaurar login a partir do token) ─────
    // Sem esta rota, o token salvo em localStorage pelo site (no
    // cadastro/login) nunca era aproveitado pelo app: toda vez que
    // worka-app.html carregava, a pessoa caía na tela de login e
    // precisava digitar email/senha de novo, mesmo já autenticada.
    if (method === "GET" && path === "/me") {
      // Owner da Worka: sessão válida, mas sem empresa vinculada — o
      // app monta o menu completo a partir do role, sem depender de
      // dados de empresa nenhuma.
      if (authPayload.role === "owner_saas") {
        return jsonOk(res, {
          owner: { email: authPayload.email, nome: "Owner Worka" },
          empresa: null,
          trial: null
        });
      }
      if (authPayload.role !== "dono") {
        // Login de funcionário continua 100% local no app hoje (não
        // migrado ainda) — não há uma tabela/rota que sirva o perfil
        // de funcionário aqui, então não finjo suportar isso.
        return jsonErr(res, "Sessão não suportada para este tipo de usuário", 403);
      }
      var meResult = await DB.select("empresas", `id=eq.${authPayload.empresa_id}&select=*`);
      var meEmpresa = meResult.body && meResult.body[0];
      if (!meEmpresa) return jsonErr(res, "Empresa não encontrada", 404);

      var meTrialInfo = null;
      if (meEmpresa.status === "trial") {
        var meDias = Math.ceil((new Date(meEmpresa.trial_fim) - Date.now()) / (1000*60*60*24));
        meTrialInfo = { dias_restantes: meDias, expirado: meDias <= 0 };
      }
      delete meEmpresa.senha_hash;
      return jsonOk(res, { empresa: meEmpresa, trial: meTrialInfo });
    }

    // ── CUPONS — GESTÃO (somente owner da Worka) ─────
    // Cupom vale para a assinatura da plataforma, não para nada dentro
    // da empresa cliente — por isso só o role owner_saas administra.
    if (method === "GET" && path === "/cupons") {
      if (!hasPermission(authPayload, "cupons:read")) {
        secLog("permission_denied", { role: authPayload.role, action: "cupons:read" });
        return jsonErr(res, "Apenas o owner da Worka pode ver cupons", 403);
      }
      var listaCupons = await DB.select("cupons", "select=*&order=created_at.desc&limit=200")
        .catch(e => {
          secLog("cupons_listagem_falhou", { message: e.message });
          return { body: null };
        });
      // body null = tabela ainda não existe (migration não rodada).
      // Sinalizamos isso explicitamente para o painel poder orientar,
      // em vez de mostrar uma lista vazia como se não houvesse cupons.
      if (listaCupons.body === null) {
        return jsonOk(res, { cupons: [], tabela_ausente: true });
      }
      return jsonOk(res, { cupons: listaCupons.body || [] });
    }

    if (method === "POST" && path === "/cupons") {
      if (!hasPermission(authPayload, "cupons:write")) {
        secLog("permission_denied", { role: authPayload.role, action: "cupons:write" });
        return jsonErr(res, "Apenas o owner da Worka pode criar cupons", 403);
      }
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      var codigoNovo = SANITIZE.string(body.codigo || "", 40).toUpperCase().replace(/\s+/g, "");
      if (!codigoNovo || codigoNovo.length < 3) return jsonErr(res, "Código do cupom precisa ter ao menos 3 caracteres.");

      var tipoNovo = ["percentual", "valor"].includes(body.tipo) ? body.tipo : null;
      if (!tipoNovo) return jsonErr(res, "Tipo inválido — use 'percentual' ou 'valor'.");

      var valorNovo = parseFloat(body.valor);
      if (isNaN(valorNovo) || valorNovo <= 0) return jsonErr(res, "Informe um valor de desconto maior que zero.");
      if (tipoNovo === "percentual" && valorNovo > 100) return jsonErr(res, "Desconto percentual não pode passar de 100%.");
      if (tipoNovo === "valor" && valorNovo * 100 >= CONFIG.PLANO_CENTAVOS) {
        return jsonErr(res, `Desconto em reais precisa ser menor que o valor do plano (R$ ${centavosParaReais(CONFIG.PLANO_CENTAVOS)}).`);
      }

      var jaExisteCupom = await DB.select("cupons", `codigo=eq.${encodeURIComponent(codigoNovo)}&select=id`)
        .catch(() => ({ body: [] }));
      if (jaExisteCupom.body && jaExisteCupom.body.length > 0) {
        return jsonErr(res, "Já existe um cupom com esse código.", 409);
      }

      var registroCupom = {
        codigo:    codigoNovo,
        tipo:      tipoNovo,
        valor:     valorNovo,
        descricao: SANITIZE.string(body.descricao || "", 200) || null,
        ativo:     body.ativo !== false,
        validade:  null,
        usos_max:  SANITIZE.int(body.usos_max, 1, 100000) || null,
        usos:      0
      };
      if (body.validade && /^\d{4}-\d{2}-\d{2}$/.test(body.validade)) {
        registroCupom.validade = body.validade;
      }

      var criado = await DB.insert("cupons", registroCupom).catch(e => {
        secLog("cupom_criacao_falhou", { message: e.message });
        return { body: [] };
      });
      if (!criado.body || !criado.body[0]) {
        return jsonErr(res, "Não foi possível criar o cupom. Confirme se a tabela 'cupons' já existe no banco (migrations/001_cupons.sql).", 500);
      }

      secLog("cupom_criado", { codigo: codigoNovo, tipo: tipoNovo });
      return jsonOk(res, { cupom: criado.body[0] }, 201);
    }

    // Ativar/desativar um cupom sem apagá-lo — preserva o histórico de
    // usos, que some se o registro for excluído.
    if (method === "PUT" && path.match(/^\/cupons\/[\w-]+$/)) {
      if (!hasPermission(authPayload, "cupons:write")) {
        return jsonErr(res, "Apenas o owner da Worka pode alterar cupons", 403);
      }
      var cupomId = SANITIZE.uuid(path.split("/")[2]);
      if (!cupomId) return jsonErr(res, "ID inválido");
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body || typeof body.ativo !== "boolean") return jsonErr(res, "Informe 'ativo' (true/false).");

      await DB.update("cupons", `id=eq.${cupomId}`, { ativo: body.ativo });
      secLog("cupom_atualizado", { cupom_id: cupomId, ativo: body.ativo });
      return jsonOk(res, { ok: true });
    }

    if (method === "DELETE" && path.match(/^\/cupons\/[\w-]+$/)) {
      if (!hasPermission(authPayload, "cupons:write")) {
        return jsonErr(res, "Apenas o owner da Worka pode remover cupons", 403);
      }
      var cupomIdDel = SANITIZE.uuid(path.split("/")[2]);
      if (!cupomIdDel) return jsonErr(res, "ID inválido");
      await DB.delete("cupons", `id=eq.${cupomIdDel}`);
      secLog("cupom_removido", { cupom_id: cupomIdDel });
      return jsonOk(res, { ok: true });
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
      // Corrigido: a coluna real é "cargo_id" (uuid, FK para a tabela
      // cargos), não "cargo" (texto) — pedir "cargo" direto quebraria
      // com erro do Postgres, coluna inexistente. cargo_id ainda não
      // é resolvido para nome legível aqui porque a tabela cargos
      // não está sendo populada por nenhuma rota ainda.
      var campos = podeVerSalario
        ? "id,nome,email,telefone,cargo_id,status,salario_base,created_at"
        : "id,nome,email,telefone,cargo_id,status,created_at";

      var result = await DB.select("funcionarios",
        `empresa_id=eq.${empresa_id}&select=${campos}&order=created_at.desc`
      );
      return jsonOk(res, result.body);
    }

    if (method === "PUT" && path.match(/^\/funcionarios\/[\w-]+\/status$/)) {
      if (!hasPermission(authPayload, "funcionarios:write")) {
        secLog("permission_denied", { role: authPayload.role, action: "funcionarios:status" });
        return jsonErr(res, "Sem permissão para alterar status de funcionários", 403);
      }
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
        // Corrigido: authPayload.funcionario_id só existe quando quem
        // bate o ponto é um funcionário. Quando é o dono (role=dono),
        // não existe funcionario_id — o fallback anterior gravava
        // empresa_id nessa coluna por engano, misturando dois tipos
        // de ID diferentes. Usa NULL explícito nesse caso: o dono não
        // tem registro na tabela funcionarios, então não há id válido
        // de funcionário para associar.
        funcionario_id: authPayload.funcionario_id || null,
        empresa_id:     authPayload.empresa_id,
        tipo,
        latitude:   lat,
        longitude:  lng
        // "biometria" removido: a coluna não existe em registros_ponto
        // no schema real. O sinal de que a batida usou biometria fica
        // registrado no log de auditoria (secLog abaixo), não na linha
        // do ponto em si.
      });

      secLog("ponto_registrado", { tipo, empresa_id: authPayload.empresa_id, biometria: body.biometria === true });
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

      // responsavel_id (UUID) substitui o antigo campo de texto
      // livre "responsavel" — que nunca existiu como coluna real na
      // tabela (só responsavel_id existe, confirmado contra o
      // schema). A consulta abaixo valida que o id informado
      // pertence a um funcionário real desta empresa antes de
      // gravar a referência — sem isso, qualquer UUID aceitável por
      // SANITIZE.uuid seria gravado sem checagem de existência.
      var responsavelId = SANITIZE.uuid(body.responsavel_id);
      if (responsavelId) {
        var respCheck = await DB.select("funcionarios", `id=eq.${responsavelId}&empresa_id=eq.${authPayload.empresa_id}&select=id`);
        if (!respCheck.body || !respCheck.body[0]) return jsonErr(res, "Funcionário responsável não encontrado");
      }

      var prazoValido = null;
      if (body.prazo) {
        var dataPrazo = new Date(body.prazo);
        if (!isNaN(dataPrazo.getTime())) prazoValido = dataPrazo.toISOString();
      }

      var result = await DB.insert("tarefas", {
        empresa_id:      authPayload.empresa_id,
        titulo,
        descricao:       SANITIZE.string(body.descricao || "", 1000),
        prioridade:      ["normal","alta","urgente"].includes(body.prioridade) ? body.prioridade : "normal",
        status:          "pendente",
        responsavel_id:  responsavelId,
        prazo:           prazoValido,
        recorrencia:     ["nenhuma","diaria","semanal","mensal"].includes(body.recorrencia) ? body.recorrencia : "nenhuma",
        requer_foto:     body.requer_foto === true
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

      // Verificar propriedade (responsavel_id é o campo real da tabela,
      // não funcionario_id — confirmado contra o schema real do banco)
      var check = await DB.select("tarefas", `id=eq.${tarefaId}&empresa_id=eq.${authPayload.empresa_id}&select=id,titulo,empresa_id,responsavel_id`);
      if (!check.body || !check.body[0]) return jsonErr(res, "Não autorizado", 403);
      var tarefaAtual = check.body[0];

      var podeEditarTudo = hasPermission(authPayload, "tarefas:write");
      var update = {};

      if (podeEditarTudo) {
        // Dono/gerente: podem alterar qualquer campo de qualquer
        // tarefa da empresa.
        if (body.status && ["pendente","em_andamento","concluida","atrasada"].includes(body.status)) update.status = body.status;
        if (body.descricao) update.descricao = SANITIZE.string(body.descricao, 1000);
        if (body.prioridade && ["normal","alta","urgente"].includes(body.prioridade)) update.prioridade = body.prioridade;
      } else if (authPayload.role === "funcionario") {
        // Funcionário: só pode marcar status (ex: concluir), e só em
        // tarefas que são dele ou gerais (sem responsável definido).
        // Antes, esta rota não checava nada disso — qualquer
        // funcionário autenticado podia editar descrição/prioridade
        // de qualquer tarefa da empresa, inclusive as de colegas.
        var ehDele = tarefaAtual.responsavel_id === authPayload.funcionario_id || tarefaAtual.responsavel_id === null;
        if (!ehDele) {
          secLog("permission_denied", { role: authPayload.role, action: "tarefas:editar_de_outro" });
          return jsonErr(res, "Você só pode atualizar suas próprias tarefas", 403);
        }
        if (body.status && ["pendente","em_andamento","concluida"].includes(body.status)) update.status = body.status;
        // "atrasada" fica de fora de propósito: é um status derivado
        // de prazo vencido, não algo que a própria pessoa deveria
        // poder se auto-atribuir ou remover.
      } else {
        return jsonErr(res, "Sem permissão para atualizar tarefas", 403);
      }

      if (Object.keys(update).length === 0) return jsonErr(res, "Nenhum campo válido para atualizar");

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

    // Histórico de ajustes de salário da empresa. historico_salarios
    // não tem coluna empresa_id (só funcionario_id) — por isso busca
    // primeiro os ids de funcionário da empresa e filtra por
    // "in.(...)", em vez de assumir um embed/relacionamento do
    // PostgREST que não dá pra confirmar sem acesso ao schema.
    if (method === "GET" && path === "/historico_salarios") {
      if (!hasPermission(authPayload, "salarios:read")) {
        return jsonErr(res, "Sem permissão para ver histórico de salários", 403);
      }
      var funcsEmpresa = await DB.select("funcionarios", `empresa_id=eq.${authPayload.empresa_id}&select=id`);
      var idsFuncs = (funcsEmpresa.body || []).map(f => f.id);
      if (idsFuncs.length === 0) return jsonOk(res, []);

      var historico = await DB.select("historico_salarios",
        `funcionario_id=in.(${idsFuncs.join(",")})&order=created_at.desc&limit=100`
      );
      return jsonOk(res, historico.body);
    }

    // ── VALIDADE ─────────────────────────────────────
    if (method === "POST" && path === "/validade") {
      if (!hasPermission(authPayload, "validade:write")) {
        secLog("permission_denied", { role: authPayload.role, action: "validade:write" });
        return jsonErr(res, "Sem permissão para cadastrar produtos", 403);
      }
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      var nome = SANITIZE.string(body.nome, 200);
      if (!nome) return jsonErr(res, "Nome inválido");

      var dataVenc = new Date(body.data_vencimento);
      if (isNaN(dataVenc.getTime())) return jsonErr(res, "Data inválida");

      // "status" não é definido aqui de propósito: o gatilho
      // trg_validade_status no banco calcula sozinho (normal/atencao/
      // urgente/vencido) a partir de data_vencimento e dias_aviso,
      // toda vez que a linha é inserida ou atualizada.
      var result = await DB.insert("produtos_validade", {
        empresa_id:       authPayload.empresa_id,
        nome,
        lote:             SANITIZE.string(body.lote || "", 50),
        categoria:        SANITIZE.string(body.categoria || "", 80),
        unidade:          SANITIZE.string(body.unidade || "unidades", 30),
        data_vencimento:  dataVenc.toISOString().split("T")[0],
        quantidade:       SANITIZE.int(body.quantidade, 0, 999999) || 0,
        dias_aviso:       SANITIZE.int(body.dias_aviso, 1, 365) || 30
      });
      secLog("produto_cadastrado", { empresa_id: authPayload.empresa_id });
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
      // Faltava a checagem de permissão que toda outra rota de
      // escrita sensível já tem — sem isso, qualquer funcionário
      // autenticado podia registrar falta/atestado/suspensão para
      // qualquer colega, sabendo só o id (visível em GET /funcionarios).
      if (!hasPermission(authPayload, "ausencias:write")) {
        secLog("permission_denied", { role: authPayload.role, action: "ausencias:write" });
        return jsonErr(res, "Sem permissão para registrar ausências", 403);
      }
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
        tipo:          ["falta_injustificada","falta_justificada","atestado","licenca","suspensao"].includes(body.tipo) ? body.tipo : "falta_injustificada",
        motivo:        SANITIZE.string(body.motivo || "", 500)
      });
      secLog("ausencia_registrada", { empresa_id: authPayload.empresa_id, funcionario_id: funcId });
      return jsonOk(res, { ausencia: result.body[0] }, 201);
    }

    // Lista de ausências da empresa — faltava por completo; sem ela
    // o frontend não tinha como mostrar o histórico registrado pelo
    // POST acima, só o formulário de cadastro existia.
    if (method === "GET" && path === "/ausencias") {
      if (!hasPermission(authPayload, "ausencias:read")) {
        return jsonErr(res, "Sem permissão para ver ausências", 403);
      }
      var inicioMesAus = new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString().split("T")[0];
      var result = await DB.select("ausencias",
        `empresa_id=eq.${authPayload.empresa_id}&data=gte.${inicioMesAus}&order=data.desc`
      );
      return jsonOk(res, result.body);
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


    // (POST /pix e GET /pix foram movidos para antes da linha
    // "A PARTIR DAQUI: REQUER JWT", junto de /enviar-codigo e
    // /verificar-codigo. Estavam aqui por engano: exigiam token, mas
    // são chamadas pelo formulário público de assinatura, onde
    // ninguém está logado — todo pedido de pagamento retornava 401
    // sempre, sem exceção.)

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
