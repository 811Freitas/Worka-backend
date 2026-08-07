/**
 * WORKAP BACKEND v3.0 — SECURE
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

/**
 * Lê uma variável de ambiente removendo espaços e quebras de linha nas
 * pontas. Colar um valor no painel do Render arrasta com frequência um
 * espaço ou um "\n" invisível no fim — e um segredo com um caractere a
 * mais simplesmente não confere, sem nenhuma pista do motivo. Valor
 * vazio (ou só espaços) vira null, para que os testes de "está
 * configurado?" não sejam enganados por uma string vazia.
 */
function env(nome) {
  var v = process.env[nome];
  if (typeof v !== "string") return null;
  v = v.trim();
  return v === "" ? null : v;
}

const CONFIG = {
  PORT:          process.env.PORT || 3000,
  JWT_SECRET:    env("JWT_SECRET"),                // OBRIGATÓRIO
  // Worka1 — projeto ativo (o projeto original está pausado). Era uma
  // constante fixa: a única configuração do sistema que não vinha do
  // ambiente, o que impedia apontar o backend para outro banco (um de
  // teste, por exemplo) sem editar o código e fazer deploy.
  SUPABASE_URL:  env("SUPABASE_URL") || "https://vtkmqykwyilcdnigaxsr.supabase.co",
  SUPABASE_KEY:  env("SUPABASE_SERVICE_KEY"),
  RESEND_KEY:    env("RESEND_KEY"),
  PIX_URL:       env("DUTTYFY_PIX_URL_ENCRYPTED"),
  ENCRYPT_KEY:   env("ENCRYPT_SECRET"),
  VAPID_PUBLIC:  env("VAPID_PUBLIC_KEY"),
  VAPID_PRIVATE: env("VAPID_PRIVATE_KEY"),
  // Conta administrativa única da Workap (painel Owner). Opcional — se
  // não configurada, a rota /login/owner responde 503 em vez de negar
  // acesso a uma conta que não existe. OWNER_PASSWORD_HASH é o hash
  // bcrypt da senha (gerar com: node -e "console.log(require('bcryptjs').hashSync('SUA_SENHA',12))"),
  // nunca a senha em texto plano.
  OWNER_EMAIL:         env("OWNER_EMAIL") ? env("OWNER_EMAIL").toLowerCase() : null,
  OWNER_PASSWORD_HASH: env("OWNER_PASSWORD_HASH"),
  BCRYPT_ROUNDS: 12,
  JWT_EXPIRES:   "8h",
  // Valor do plano em CENTAVOS — é assim que o gateway PIX espera
  // receber. Fonte única da verdade: o cálculo de desconto por cupom
  // e a cobrança partem daqui, para o preço nunca divergir entre a
  // tela de checkout e o que é realmente cobrado.
  PLANO_CENTAVOS: 4999,
  // Domínios permitidos no CORS.
  // ATENÇÃO: o domínio real do site (arquivo CNAME) é "workap.com.br",
  // com P. A lista tinha "worka.com.br" — domínio diferente, que não é
  // o do site. Com isso, todo request vindo do domínio próprio era
  // barrado pelo CORS: login, cadastro, PIX, tudo. Mantidas as duas
  // grafias porque o GitHub Pages segue servindo em 811freitas.github.io
  // e um eventual redirect pode chegar com qualquer uma delas.
  ALLOWED_ORIGINS: [
    "https://811freitas.github.io",
    "https://workap.com.br",
    "https://www.workap.com.br",
    "https://worka.com.br",
    "http://localhost:3000",
    "http://localhost:5500"
  ]
};

// Validar variáveis críticas na inicialização
const REQUIRED_ENV = ["JWT_SECRET", "SUPABASE_SERVICE_KEY", "RESEND_KEY"];
for (var nomeEnv of REQUIRED_ENV) {
  // env() já corta espaços: uma variável preenchida só com espaço conta
  // como não definida, que é o que ela é na prática.
  if (!env(nomeEnv)) {
    console.error(`[SECURITY] FATAL: variável de ambiente ${nomeEnv} não definida`);
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
  "/login/confirmar-dispositivo": { max: 8, window: 15 * 60 * 1000 }, // 8/15min — anti brute force do código
  // Face ID: gerar desafio é barato, mas serve para descobrir quais
  // e-mails têm credencial cadastrada. Limite bem menor que o geral.
  "/webauthn/login/inicio": { max: 10, window: 10 * 60 * 1000 },
  "/webauthn/login/fim":    { max: 10, window: 10 * 60 * 1000 },
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
  "escala:read", "escala:write",
  "mural:read", "mural:write",
  "cargos:read", "cargos:write",
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
    "escala:read", "escala:write",
    "mural:read", "mural:write",
    "cargos:read",          // vê os cargos, mas quem cria é o dono
    "logs:read"
  ]),
  funcionario: new Set([
    "ponto:write",       // só o próprio ponto — checagem extra na rota
    "tarefas:read",
    "validade:read",
    "escala:read",       // consulta a própria escala da semana
    "mural:read"         // lê os comunicados da empresa
  ]),
  // Dono da Workap (não do cliente). Recebe as mesmas permissões de um
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
    "lancamentos_financeiros", "push_subscriptions", "cupons",
    "dispositivos_confiaveis", "comunicados_plataforma",
    "owners_plataforma", "webauthn_credentials", "webauthn_challenges",
    "config_plataforma", "utmify_envios",
    "comunicados", "cargos", "config_faltas"
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

    // A porta vem da própria URL. Sem isso, https.request assume 443 e
    // qualquer endereço com porta explícita — um banco de teste, um
    // túnel local — é chamado na porta errada, com um "connection
    // refused" que não diz em momento algum que a porta foi ignorada.
    var alvo = new URL(CONFIG.SUPABASE_URL);
    var req = https.request({
      hostname: alvo.hostname,
      port: alvo.port || 443,
      path, method, headers
    }, (res) => {
      var raw = "";
      res.on("data", c => raw += c);
      res.on("end", () => {
        var body;
        try {
          body = JSON.parse(raw || "[]");
        } catch(e) {
          // Resposta que não é JSON: página de erro do proxy, 502 do
          // gateway, corpo truncado. Antes isso resolvia com body sendo
          // a STRING crua — e aí `body[0]` virava o primeiro CARACTERE
          // do texto, que é truthy. O login lia esse caractere como se
          // fosse a empresa encontrada e chamava bcrypt com senha_hash
          // undefined (erro 500); a checagem de e-mail duplicado no
          // cadastro lia `body.length` como o tamanho do texto e
          // acusava "e-mail já cadastrado" para quem nunca se cadastrou.
          // Falha de infraestrutura tem que falhar como falha, nunca
          // ser confundida com dado vindo do banco.
          secLog("supabase_resposta_invalida", { table, status: res.statusCode, tamanho: raw.length });
          return reject(new Error("Resposta inválida do banco de dados"));
        }

        // Erro do PostgREST: às vezes vem com code+message, às vezes só
        // com message ("Invalid API key"). O status HTTP é o sinal
        // confiável — qualquer 4xx/5xx é erro, não resultado.
        if (res.statusCode >= 400) {
          secLog("supabase_error", { table, status: res.statusCode, code: (body && body.code) || null });
          return reject(new Error((body && body.message) || `Erro ${res.statusCode} no banco de dados`));
        }

        // Consulta bem-sucedida sempre devolve array (GET/POST/PATCH com
        // return=representation) ou vazio (DELETE 204). Um objeto solto
        // aqui não é linha de tabela.
        resolve({ status: res.statusCode, body });
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
// DISPOSITIVOS CONFIÁVEIS
// ════════════════════════════════════════
// Senha correta em aparelho desconhecido não basta: o sistema manda um
// código por e-mail antes de liberar o acesso. Aparelho já reconhecido
// (e usado nos últimos DIAS_CONFIANCA dias) entra direto, para não
// transformar o login do dia a dia num incômodo.
var DIAS_CONFIANCA = 30;

// O device_id é gerado pelo navegador (crypto.randomUUID) e guardado no
// localStorage. Aceitamos só o formato esperado para ninguém conseguir
// injetar texto arbitrário na consulta.
function sanitizarDeviceId(v) {
  if (typeof v !== "string") return null;
  var limpo = v.trim();
  return /^[A-Za-z0-9_-]{16,64}$/.test(limpo) ? limpo : null;
}

/**
 * Diz se este aparelho já é confiável para esta conta.
 *
 * Falha "aberta" de propósito: se a tabela ainda não existe (migration
 * 002 não rodada) ou o banco está indisponível, devolve true — ou seja,
 * não exige código. Bloquear o login de todo mundo por causa de uma
 * tabela ausente seria pior que rodar sem a camada extra; a senha
 * continua sendo exigida normalmente nesse caso.
 */
async function dispositivoConfiavel(email, deviceId) {
  // Sem id de aparelho não há verificação possível: o segundo passo
  // (POST /login/confirmar-dispositivo) exige um deviceId válido para
  // registrar o aparelho, então pedir código aqui criaria um login que
  // NUNCA conclui. É o caso de quem navega em janela privada do Safari,
  // onde o localStorage não persiste. A senha continua sendo exigida —
  // o que se perde é só a camada extra, para quem já não podia tê-la.
  if (!deviceId) {
    secLog("dispositivo_sem_id", {});
    return true;
  }

  var res = await supabase("GET", "dispositivos_confiaveis", {
    query: `email=eq.${encodeURIComponent(email)}&device_id=eq.${encodeURIComponent(deviceId)}&select=id,ultimo_acesso&limit=1`
  }).catch(e => {
    secLog("dispositivos_indisponivel", { message: e.message });
    return { body: null, indisponivel: true };
  });

  if (res.indisponivel) return true;

  var registro = res.body && res.body[0];
  if (!registro) return false;

  // "Login frequente": aparelho parado há muito tempo volta a pedir
  // código, porque pode ter sido vendido, perdido ou emprestado.
  var diasParado = (Date.now() - new Date(registro.ultimo_acesso).getTime()) / (1000 * 60 * 60 * 24);
  if (diasParado > DIAS_CONFIANCA) return false;

  // Renova o carimbo de uso — quem entra sempre nunca vai ver o código.
  supabase("PATCH", "dispositivos_confiaveis", {
    query: `id=eq.${registro.id}`,
    body: { ultimo_acesso: new Date().toISOString() }
  }).catch(() => {});

  return true;
}

/** Marca o aparelho como confiável depois que o código foi conferido. */
async function registrarDispositivo(email, deviceId, empresaId, descricao) {
  if (!deviceId) return;
  var existente = await supabase("GET", "dispositivos_confiaveis", {
    query: `email=eq.${encodeURIComponent(email)}&device_id=eq.${encodeURIComponent(deviceId)}&select=id&limit=1`
  }).catch(() => ({ body: [] }));

  var agora = new Date().toISOString();
  if (existente.body && existente.body[0]) {
    await supabase("PATCH", "dispositivos_confiaveis", {
      query: `id=eq.${existente.body[0].id}`,
      body: { ultimo_acesso: agora }
    }).catch(() => {});
  } else {
    await supabase("POST", "dispositivos_confiaveis", {
      body: {
        email: email,
        empresa_id: empresaId || null,
        device_id: deviceId,
        descricao: SANITIZE.string(descricao || "", 80) || null,
        ultimo_acesso: agora
      }
    }).catch(e => secLog("dispositivo_registro_falhou", { message: e.message }));
  }
}

/**
 * Dispara o código de verificação de aparelho novo. Reaproveita a
 * mesma infra de OTP do cadastro (hash do código, expiração, limite de
 * tentativas) em vez de criar um segundo mecanismo.
 */
async function exigirCodigoDispositivo(email, nome) {
  var codigo = gerarCodigo();
  await salvarOTP(email, codigo);
  enviarEmail(email, "🔐 Confirme seu acesso — Workap", EMAIL_TEMPLATES.novoDispositivo(nome || "", codigo))
    .catch(e => secLog("email_error", { type: "novo_dispositivo", message: e.message }));
}

// Hash bcrypt válido de uma senha que ninguém conhece. Serve para
// gastar o mesmo tempo de CPU quando a conta não existe: sem isso, uma
// resposta rápida denuncia "esse e-mail não está cadastrado" antes
// mesmo de olhar a mensagem devolvida.
var SENHA_DUMMY = "$2b$12$abcdefghijklmnopqrstuvuxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

/**
 * Confere a senha do owner da Workap e responde o login.
 *
 * Existe como função porque o owner entra por dois caminhos: o
 * formulário comum (POST /login/empresa, que reconhece o e-mail) e a
 * rota dedicada antiga (POST /login/owner, mantida para navegadores
 * com HTML em cache). Se cada rota tivesse sua própria checagem, uma
 * delas ficaria para trás na primeira mudança de regra — e a que
 * ficasse para trás seria uma porta aberta para o painel que enxerga
 * todos os assinantes.
 */
/**
 * Procura uma conta de owner da plataforma pelo e-mail.
 *
 * Fonte principal: tabela owners_plataforma (migration 003). Antes
 * disso a conta vivia só em variável de ambiente, o que funcionava mas
 * transformava "trocar a senha do admin" numa ida ao painel do Render
 * e um reinício do serviço.
 *
 * As variáveis de ambiente continuam valendo como reserva, para o caso
 * de a migration ainda não ter rodado ou o banco estar fora do ar —
 * sem isso, um deploy na ordem errada trancaria o acesso ao painel da
 * plataforma. Nenhum dos dois caminhos dispensa a senha: o que muda é
 * apenas de onde vem o hash usado na comparação.
 *
 * Devolve null quando o e-mail não é de owner — e aí o login segue o
 * fluxo normal de empresa.
 */
async function buscarOwner(email) {
  if (!email) return null;

  var achado = await supabase("GET", "owners_plataforma", {
    query: `email=eq.${encodeURIComponent(email)}&ativo=is.true&select=id,email,nome,senha_hash&limit=1`
  }).catch(e => {
    secLog("owners_indisponivel", { message: e.message });
    return null;
  });

  var linha = achado && achado.body && achado.body[0];
  if (linha && linha.senha_hash) {
    return {
      id:         linha.id,
      email:      linha.email,
      nome:       linha.nome || "Owner Workap",
      senha_hash: linha.senha_hash,
      origem:     "banco"
    };
  }

  if (CONFIG.OWNER_EMAIL && CONFIG.OWNER_PASSWORD_HASH && email === CONFIG.OWNER_EMAIL) {
    return {
      id:         null,
      email:      CONFIG.OWNER_EMAIL,
      nome:       "Owner Workap",
      senha_hash: CONFIG.OWNER_PASSWORD_HASH,
      origem:     "env"
    };
  }

  return null;
}

async function responderLoginOwner(res, owner, senha, deviceIdBruto, ip) {
  if (!owner) return jsonErr(res, "Login de owner não configurado", 503);

  if (!(await verificarSenha(senha, owner.senha_hash))) {
    secLog("login_owner_falhou", { ip, origem: owner.origem });
    return jsonErr(res, "Senha incorreta. Tente novamente ou use \"Esqueci minha senha\".", 401);
  }

  // A conta de owner administra a plataforma inteira — é a que mais
  // precisa da verificação de aparelho novo.
  var deviceIdOwner = sanitizarDeviceId(deviceIdBruto);
  if (!(await dispositivoConfiavel(owner.email, deviceIdOwner))) {
    await exigirCodigoDispositivo(owner.email, owner.nome);
    secLog("login_owner_novo_dispositivo", { ip });
    return jsonOk(res, {
      requer_codigo: true,
      email: owner.email,
      message: "Enviamos um código para o seu e-mail para confirmar este aparelho."
    });
  }

  registrarLoginOwner(owner);
  secLog("login_owner_ok", { origem: owner.origem });
  return jsonOk(res, {
    token: jwtSign({ email: owner.email, role: "owner_saas" }),
    owner: { nome: owner.nome, email: owner.email },
    // O frontend usa isto para mandar direto ao painel da plataforma
    // em vez do painel de empresa, já que a resposta chega pela mesma
    // rota de login das empresas.
    is_owner: true
  });
}

/**
 * Carimba a data do último login do owner. Fire-and-forget de
 * propósito: é informação de auditoria, não pode segurar nem derrubar
 * um login que já foi aprovado.
 */
function registrarLoginOwner(owner) {
  if (!owner || !owner.id) return;
  supabase("PATCH", "owners_plataforma", {
    query: `id=eq.${owner.id}`,
    body: { ultimo_login: new Date().toISOString() }
  }).catch(e => secLog("owner_ultimo_login_falhou", { message: e.message }));
}

// ════════════════════════════════════════
// CONFIGURAÇÃO DA PLATAFORMA (chave/valor no banco)
// ════════════════════════════════════════
// Ajustes que o owner precisa mudar sem esperar deploy — hoje o token
// da Utmify e o liga/desliga da integração. Guardado no banco, não em
// variável de ambiente, justamente para não depender de reiniciar o
// serviço a cada mudança.

var cacheConfig = { valores: {}, expiraEm: 0 };

async function lerConfigPlataforma() {
  // 60s de cache: a rota de PIX consulta a configuração a cada cobrança,
  // e ir ao banco toda vez para ler duas linhas é desperdício. Curto o
  // bastante para uma mudança no painel valer quase de imediato.
  if (Date.now() < cacheConfig.expiraEm) return cacheConfig.valores;

  var linhas = await supabase("GET", "config_plataforma", { query: "select=chave,valor" })
    .catch(e => { secLog("config_plataforma_indisponivel", { message: e.message }); return null; });

  if (!linhas) return cacheConfig.valores;   // mantém o último valor conhecido

  var mapa = {};
  (linhas.body || []).forEach(function (l) { mapa[l.chave] = l.valor; });
  cacheConfig = { valores: mapa, expiraEm: Date.now() + 60000 };
  return mapa;
}

async function gravarConfigPlataforma(chave, valor) {
  var existente = await supabase("GET", "config_plataforma",
    { query: `chave=eq.${encodeURIComponent(chave)}&select=chave&limit=1` }
  ).catch(() => ({ body: [] }));

  var corpo = { chave: chave, valor: valor, updated_at: new Date().toISOString() };
  if (existente.body && existente.body[0]) {
    await supabase("PATCH", "config_plataforma", { query: `chave=eq.${encodeURIComponent(chave)}`, body: corpo });
  } else {
    await supabase("POST", "config_plataforma", { body: corpo });
  }
  cacheConfig.expiraEm = 0;   // força releitura na próxima consulta
}

// ════════════════════════════════════════
// UTMIFY — rastreio de origem das vendas
// ════════════════════════════════════════
// A Utmify recebe cada pedido e casa a venda com o anúncio que a
// originou. São dois avisos por venda: um quando o PIX é gerado
// (waiting_payment) e outro quando o pagamento cai (paid). Sem o
// primeiro, o funil não mostra quantos geraram cobrança e desistiram —
// que é o número que diz se o problema está no anúncio ou no checkout.

var UTMIFY_URL_PADRAO = "https://api.utmify.com.br/api-credentials/orders";

function utmifyDataFormatada(data) {
  // A Utmify espera "YYYY-MM-DD HH:MM:SS" em UTC, não ISO com T e Z.
  return new Date(data).toISOString().replace("T", " ").substring(0, 19);
}

/** Só as chaves de rastreio conhecidas, e sempre as 6, mesmo vazias. */
function normalizarUtm(bruto) {
  var origem = bruto || {};
  function limpar(v) { return SANITIZE.string(v || "", 200) || null; }
  return {
    src:          limpar(origem.src),
    sck:          limpar(origem.sck),
    utm_source:   limpar(origem.utm_source),
    utm_campaign: limpar(origem.utm_campaign),
    utm_medium:   limpar(origem.utm_medium),
    utm_content:  limpar(origem.utm_content),
    utm_term:     limpar(origem.utm_term)
  };
}

/**
 * Manda um pedido para a Utmify e registra o que voltou.
 *
 * Nunca lança: é chamada no meio do fluxo de pagamento, e uma
 * integração de marketing fora do ar não pode impedir uma venda. Mas
 * também não falha calada — cada tentativa vira uma linha em
 * utmify_envios com o status e a resposta, para dar para ver na tela
 * do painel que parou de funcionar.
 */
async function enviarUtmify(dados) {
  var cfg = await lerConfigPlataforma();
  var token = cfg.utmify_token;
  var ativo = cfg.utmify_ativo === "1";

  if (!ativo || !token) return { enviado: false, motivo: "integracao_desligada" };

  var payload = {
    orderId:       String(dados.orderId),
    platform:      "Workap",
    paymentMethod: "pix",
    status:        dados.status,                       // waiting_payment | paid
    createdAt:     utmifyDataFormatada(dados.criadoEm || Date.now()),
    approvedDate:  dados.status === "paid" ? utmifyDataFormatada(dados.pagoEm || Date.now()) : null,
    refundedAt:    null,
    customer: {
      name:     dados.cliente.nome  || "Cliente",
      email:    dados.cliente.email || "",
      phone:    dados.cliente.telefone || null,
      document: dados.cliente.documento || null,
      country:  "BR",
      ip:       dados.cliente.ip || null
    },
    products: [{
      id:            "plano-completo",
      name:          "Plano Completo Workap",
      planId:        null,
      planName:      null,
      quantity:      1,
      priceInCents:  dados.valorCentavos
    }],
    trackingParameters: normalizarUtm(dados.utm),
    commission: {
      totalPriceInCents:    dados.valorCentavos,
      gatewayFeeInCents:    0,
      userCommissionInCents: dados.valorCentavos
    },
    isTest: dados.teste === true
  };

  var url;
  try { url = new URL(cfg.utmify_url || UTMIFY_URL_PADRAO); }
  catch (e) { return { enviado: false, motivo: "url_invalida" }; }

  var resultado = { enviado: false, status: null, resposta: "" };
  try {
    var resp = await httpRequestExterno(url, "POST", payload, { "x-api-token": token });
    resultado.status = resp.status;
    resultado.resposta = (resp.raw || "").substring(0, 500);
    resultado.enviado = resp.status >= 200 && resp.status < 300;
  } catch (e) {
    resultado.resposta = "Falha de conexão: " + e.message;
  }

  await supabase("POST", "utmify_envios", {
    body: {
      transaction_id: String(dados.orderId),
      evento:         dados.status,
      status_http:    resultado.status,
      sucesso:        resultado.enviado,
      resposta:       resultado.resposta,
      payload_resumo: JSON.stringify({
        valor: dados.valorCentavos,
        utm:   payload.trackingParameters,
        teste: payload.isTest
      }).substring(0, 500)
    }
  }).catch(e => secLog("utmify_log_falhou", { message: e.message }));

  if (!resultado.enviado) {
    secLog("utmify_falhou", { status: resultado.status, evento: dados.status });
  }
  return resultado;
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
// FACE ID / TOUCH ID / SENHA DO APARELHO (WebAuthn)
// ════════════════════════════════════════
// Substitui o código por e-mail na confirmação de aparelho: em vez de
// esperar uma mensagem chegar na caixa de entrada, a pessoa confirma
// com o que o próprio celular já usa para se desbloquear — Face ID,
// Touch ID ou a senha do aparelho. O navegador decide qual; o padrão
// só exige que tenha havido "verificação do usuário".
//
// O que o servidor guarda é apenas uma CHAVE PÚBLICA. A biometria em
// si nunca sai do aparelho, nunca trafega e não é armazenada aqui —
// nem poderia ser. O que chega é uma assinatura, que só a chave
// privada guardada no chip de segurança do celular consegue produzir.

// ── Base64URL ────────────────────────────────────────────────
function b64urlParaBuffer(s) {
  if (typeof s !== "string") return Buffer.alloc(0);
  var b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  return Buffer.from(b64, "base64");
}
function bufferParaB64url(buf) {
  return Buffer.from(buf).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Decodificador CBOR mínimo — só o que o WebAuthn usa.
 *
 * O attestationObject e a chave pública vêm em CBOR, um formato
 * binário. Aqui só existem os tipos que aparecem nessas estruturas:
 * inteiros, negativos, bytes, texto, listas e mapas. Não é um CBOR
 * completo de propósito — implementar o formato inteiro seria mais
 * superfície de erro do que o problema pede, e qualquer coisa fora
 * desse conjunto é sinal de dado que não deveria estar ali.
 */
function cborDecodificar(buf, inicio) {
  var pos = inicio || 0;

  function lerTamanho(info) {
    if (info < 24) return info;
    if (info === 24) { var v = buf.readUInt8(pos); pos += 1; return v; }
    if (info === 25) { var v2 = buf.readUInt16BE(pos); pos += 2; return v2; }
    if (info === 26) { var v3 = buf.readUInt32BE(pos); pos += 4; return v3; }
    throw new Error("CBOR: tamanho não suportado (" + info + ")");
  }

  function valor() {
    if (pos >= buf.length) throw new Error("CBOR: acabou no meio");
    var b = buf.readUInt8(pos); pos += 1;
    var tipo = b >> 5, info = b & 0x1f;

    if (tipo === 0) return lerTamanho(info);            // inteiro
    if (tipo === 1) return -1 - lerTamanho(info);       // negativo
    if (tipo === 2) {                                    // bytes
      var n = lerTamanho(info); var fatia = buf.slice(pos, pos + n); pos += n; return fatia;
    }
    if (tipo === 3) {                                    // texto
      var n2 = lerTamanho(info); var txt = buf.slice(pos, pos + n2).toString("utf8"); pos += n2; return txt;
    }
    if (tipo === 4) {                                    // lista
      var n3 = lerTamanho(info); var lista = [];
      for (var i = 0; i < n3; i++) lista.push(valor());
      return lista;
    }
    if (tipo === 5) {                                    // mapa
      var n4 = lerTamanho(info); var mapa = new Map();
      for (var j = 0; j < n4; j++) { var k = valor(); mapa.set(k, valor()); }
      return mapa;
    }
    if (tipo === 7) {                                    // false/true/null
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
    }
    throw new Error("CBOR: tipo não suportado (" + tipo + ")");
  }

  var resultado = valor();
  return { valor: resultado, fim: pos };
}

/**
 * Lê o authenticatorData, um buffer de campos de tamanho fixo:
 *   32 bytes  hash do domínio (rpIdHash)
 *    1 byte   flags — bit 0 presença, bit 2 verificação do usuário,
 *             bit 6 se traz credencial nova
 *    4 bytes  contador de assinaturas
 *   [quando bit 6] 16 bytes aaguid + 2 bytes tamanho + id + chave COSE
 */
function lerAuthData(buf) {
  if (!buf || buf.length < 37) throw new Error("authData curto demais");
  var flags = buf.readUInt8(32);
  var dados = {
    rpIdHash:  buf.slice(0, 32),
    presenca:  !!(flags & 0x01),   // alguém tocou/olhou o aparelho
    verificado:!!(flags & 0x04),   // Face ID / Touch ID / senha conferidos
    temCredencial: !!(flags & 0x40),
    contador:  buf.readUInt32BE(33)
  };

  if (dados.temCredencial) {
    var p = 37 + 16;                       // pula o aaguid
    var tamId = buf.readUInt16BE(p); p += 2;
    dados.credentialId = buf.slice(p, p + tamId); p += tamId;
    dados.chaveCose = cborDecodificar(buf, p).valor;
  }
  return dados;
}

/**
 * Converte a chave pública COSE para um objeto de chave do Node.
 * Só aceita ECDSA P-256 (alg -7) e RSA (alg -257) — os dois formatos
 * que iPhone e Android geram. Recusar o resto é proposital: uma curva
 * inesperada aqui é motivo para desconfiar, não para tentar adivinhar.
 */
function coseParaChave(cose) {
  if (!(cose instanceof Map)) throw new Error("chave COSE inválida");
  var kty = cose.get(1), alg = cose.get(3);

  if (kty === 2 && alg === -7) {                 // EC2 P-256
    if (cose.get(-1) !== 1) throw new Error("curva não suportada");
    return crypto.createPublicKey({
      key: {
        kty: "EC", crv: "P-256",
        x: bufferParaB64url(cose.get(-2)),
        y: bufferParaB64url(cose.get(-3))
      },
      format: "jwk"
    });
  }

  if (kty === 3 && alg === -257) {               // RSA
    return crypto.createPublicKey({
      key: {
        kty: "RSA",
        n: bufferParaB64url(cose.get(-1)),
        e: bufferParaB64url(cose.get(-2))
      },
      format: "jwk"
    });
  }

  throw new Error("algoritmo não suportado (" + alg + ")");
}

/**
 * De qual domínio a credencial é. WebAuthn amarra cada credencial a um
 * domínio: uma cadastrada em workap.com.br não funciona em outro lugar,
 * e é justamente isso que impede um site clonado de pedir o Face ID da
 * pessoa e reaproveitar a resposta.
 *
 * Sai da Origin do próprio pedido, mas só depois de a Origin passar
 * pela mesma lista de permitidos do CORS — senão bastaria mandar uma
 * Origin qualquer para escolher o domínio da credencial.
 */
function rpIdDaOrigem(origem) {
  if (!origem || CONFIG.ALLOWED_ORIGINS.indexOf(origem) === -1) return null;
  try { return new URL(origem).hostname; } catch (e) { return null; }
}

async function guardarDesafio(email, finalidade) {
  var desafio = bufferParaB64url(crypto.randomBytes(32));

  // Um desafio pendente por vez, por conta e finalidade.
  await supabase("PATCH", "webauthn_challenges", {
    query: `email=eq.${encodeURIComponent(email)}&finalidade=eq.${finalidade}&usado=is.false`,
    body: { usado: true }
  }).catch(() => {});

  await supabase("POST", "webauthn_challenges", {
    body: {
      email: email,
      challenge: desafio,
      finalidade: finalidade,
      usado: false,
      expira_em: new Date(Date.now() + 5 * 60 * 1000).toISOString()
    }
  });
  return desafio;
}

/** Consome o desafio: confere que existe, não venceu e não foi usado. */
async function consumirDesafio(email, finalidade, desafioRecebido) {
  var achado = await supabase("GET", "webauthn_challenges", {
    query: `email=eq.${encodeURIComponent(email)}&finalidade=eq.${finalidade}` +
           `&usado=is.false&order=created_at.desc&limit=1`
  }).catch(() => ({ body: [] }));

  var linha = achado.body && achado.body[0];
  if (!linha) return { ok: false, erro: "Desafio não encontrado. Tente de novo." };

  // Marca como usado ANTES de validar: mesmo que a comparação falhe, o
  // desafio morre. Sem isso dava para ficar tentando contra o mesmo.
  await supabase("PATCH", "webauthn_challenges", { query: `id=eq.${linha.id}`, body: { usado: true } }).catch(() => {});

  if (new Date(linha.expira_em) < new Date()) return { ok: false, erro: "Tempo esgotado. Tente de novo." };

  var a = Buffer.from(linha.challenge), b = Buffer.from(desafioRecebido || "");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, erro: "Desafio não confere." };
  }
  return { ok: true };
}

/**
 * Confere as partes que registro e login têm em comum: o clientDataJSON
 * (o que o navegador diz ter assinado) e o authenticatorData.
 */
async function conferirCeremonia(opcoes) {
  var dadosCliente;
  try {
    dadosCliente = JSON.parse(b64urlParaBuffer(opcoes.clientDataJSON).toString("utf8"));
  } catch (e) {
    return { ok: false, erro: "Resposta do aparelho ilegível." };
  }

  if (dadosCliente.type !== opcoes.tipoEsperado) {
    return { ok: false, erro: "Tipo de operação inesperado." };
  }
  // A Origin volta assinada pelo navegador: é o que impede um site
  // clonado de usar a credencial cadastrada no site verdadeiro.
  if (dadosCliente.origin !== opcoes.origem) {
    secLog("webauthn_origem_divergente", { esperada: opcoes.origem, recebida: String(dadosCliente.origin).slice(0, 80) });
    return { ok: false, erro: "Origem não confere." };
  }

  var desafio = await consumirDesafio(opcoes.email, opcoes.finalidade, dadosCliente.challenge);
  if (!desafio.ok) return { ok: false, erro: desafio.erro };

  var authData;
  try { authData = lerAuthData(b64urlParaBuffer(opcoes.authDataB64)); }
  catch (e) { return { ok: false, erro: "Dados do aparelho inválidos." }; }

  var hashEsperado = crypto.createHash("sha256").update(opcoes.rpId).digest();
  if (!crypto.timingSafeEqual(authData.rpIdHash, hashEsperado)) {
    return { ok: false, erro: "Domínio não confere." };
  }
  if (!authData.presenca) return { ok: false, erro: "O aparelho não confirmou a presença." };
  if (!authData.verificado) {
    // É o ponto todo: sem Face ID/Touch ID/senha conferidos, isto vira
    // só "tem o aparelho na mão", que é bem menos do que se promete.
    return { ok: false, erro: "Confirme com Face ID, Touch ID ou a senha do aparelho." };
  }

  return { ok: true, authData: authData, dadosCliente: dadosCliente };
}

// ════════════════════════════════════════
// PUSH NOTIFICATIONS (Web Push / VAPID)
// ════════════════════════════════════════
// Diferente de JWT_SECRET/SUPABASE/RESEND, VAPID não entra em
// REQUIRED_ENV: push é uma funcionalidade de reengajamento, não
// algo que impeça o sistema de funcionar. Sem as chaves, o helper
// abaixo simplesmente não envia (log de aviso), sem derrubar o boot.
//
// O try/catch não é decoração. setVapidDetails() valida o formato das
// chaves e LANÇA se algo estiver fora do padrão base64url — um espaço
// invisível colado junto no painel do Render já basta. Sem o catch,
// essa exceção acontece no topo do arquivo, antes do servidor subir, e
// o processo morre com "Exited with status 1": ponto, tarefas, folha,
// pagamento, tudo fora do ar por causa de uma chave de notificação.
// Aqui a falha é registrada, o push é desligado, e o resto do sistema
// continua funcionando normalmente.
if (CONFIG.VAPID_PUBLIC && CONFIG.VAPID_PRIVATE) {
  try {
    webpush.setVapidDetails("mailto:workappoficial@gmail.com", CONFIG.VAPID_PUBLIC, CONFIG.VAPID_PRIVATE);
  } catch (e) {
    console.error(JSON.stringify({
      ts: new Date().toISOString(),
      event: "vapid_invalido",
      message: e.message,
      dica: "Confira VAPID_PUBLIC_KEY (87 caracteres) e VAPID_PRIVATE_KEY (43 caracteres). " +
            "Só podem conter A-Z a-z 0-9 - _ — sem espaços, sem aspas, sem quebra de linha e sem '='. " +
            "Gere um par novo com: npx web-push generate-vapid-keys",
      tamanho_publica:  CONFIG.VAPID_PUBLIC.length,
      tamanho_privada:  CONFIG.VAPID_PRIVATE.length
    }));
    // Desliga o push explicitamente: enviarPush() e /push/vapid-key
    // checam VAPID_PUBLIC, então zerar aqui evita que o resto do
    // código tente usar uma configuração que nunca foi aceita.
    CONFIG.VAPID_PUBLIC  = null;
    CONFIG.VAPID_PRIVATE = null;
  }
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
      from:    "Workap <onboarding@resend.dev>",
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
<p style="font-size:12px;color:#9aab9a;margin:0">Workap — Sistema de Gestão de Equipe</p>
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
      <p style="margin:0;font-size:13px;color:#2d5a2d">🔒 <strong>Não compartilhe</strong> este código. A Workap nunca pedirá seu código por telefone.</p>
    </div>`),

  boasVindas: (nome, teamId, trialFim) => emailBase(`
    <h2 style="margin:0 0 8px;color:#0a2e1a;font-size:22px;font-weight:800">Bem-vindo ao Workap! 🎉</h2>
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

  // Comunicado da plataforma para as empresas clientes. O texto vem do
  // painel Owner, então passa por SANITIZE.string antes de entrar no
  // HTML — sem isso, um comunicado com "<" quebraria o e-mail.
  comunicadoPlataforma: (titulo, mensagem) => emailBase(`
    <h2 style="margin:0 0 16px;color:#0a2e1a;font-size:22px;font-weight:800">${SANITIZE.string(titulo, 150)}</h2>
    <div style="color:#3a3d39;font-size:15px;line-height:1.7;white-space:pre-wrap">${SANITIZE.string(mensagem, 4000)}</div>
    <div style="margin-top:28px;padding-top:20px;border-top:1px solid #e8ede8">
      <p style="margin:0;font-size:12px;color:#9aab9a">Você recebeu este aviso porque tem uma conta no Workap.</p>
    </div>`),

  novoDispositivo: (nome, codigo) => emailBase(`
    <h2 style="margin:0 0 8px;color:#0a2e1a;font-size:22px;font-weight:800">Confirme seu acesso 🔐</h2>
    <p style="color:#5a6b5a;font-size:15px;margin:0 0 28px;line-height:1.6">Olá${nome ? ", <strong>" + SANITIZE.string(nome) + "</strong>" : ""}! Detectamos um acesso à sua conta Workap a partir de um <strong>aparelho novo</strong>. Use o código abaixo para confirmar que é você:</p>
    <div style="background:linear-gradient(135deg,#0a2e1a,#16622f);border-radius:16px;padding:28px;text-align:center;margin:0 0 28px">
      <div style="font-size:44px;font-weight:900;color:#3dd669;letter-spacing:14px;font-family:'Courier New',monospace">${codigo}</div>
      <div style="font-size:13px;color:rgba(255,255,255,.6);margin-top:10px">⏰ Expira em <strong style="color:#fff">10 minutos</strong></div>
    </div>
    <div style="background:#fff5f5;border-radius:12px;padding:16px;border-left:4px solid #ef4444">
      <p style="margin:0;font-size:13px;color:#991b1b">🚨 <strong>Não foi você?</strong> Alguém pode saber sua senha. Troque sua senha imediatamente usando "Esqueci minha senha" na tela de login.</p>
    </div>`),

  recuperarSenha: (nome, codigo) => emailBase(`
    <h2 style="margin:0 0 8px;color:#0a2e1a;font-size:22px;font-weight:800">Redefinir sua senha 🔑</h2>
    <p style="color:#5a6b5a;font-size:15px;margin:0 0 28px;line-height:1.6">Olá, <strong>${SANITIZE.string(nome)}</strong>! Recebemos um pedido para redefinir a senha da sua conta Workap. Use o código abaixo:</p>
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
      // A porta vem da própria URL. Sem isso, https.request assume 443
      // e qualquer endereço com porta explícita é chamado na porta
      // errada — com um "connection refused" que não diz em momento
      // algum que a porta foi descartada.
      port:     urlObj.port || 443,
      path:     urlObj.pathname + urlObj.search,
      method:   method,
      headers:  headers
    }, res2 => {
      var raw2 = "";
      res2.on("data", c => raw2 += c);
      res2.on("end", () => {
        // O corpo cru vai junto: quando a resposta não é JSON (erro de
        // validação em texto, página de erro do gateway), era descartado
        // aqui e o motivo real da falha se perdia.
        try { resolve({ status: res2.statusCode, body: JSON.parse(raw2), raw: raw2 }); }
        catch(e) { resolve({ status: res2.statusCode, body: {}, raw: raw2 }); }
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
      enviarPush(emp.id, { title: "Seu trial está acabando", body: `Faltam ${dias} dia(s). Renove para não perder o acesso.`, url: "./" }).catch(() => {});
      await DB.update("empresas", "id=eq." + emp.id, { aviso_trial_sent: true });
      secLog("trial_aviso_enviado", { empresa_id: emp.id, dias });
    }

    var expirados = await DB.select("empresas",
      "status=eq.trial&trial_fim=lt." + new Date().toISOString() + "&aviso_expirado_sent=is.false"
    );
    for (var emp of (expirados.body || [])) {
      await enviarEmail(emp.email, "😢 Seu trial do Workap expirou", EMAIL_TEMPLATES.trialExpirado(emp.nome));
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

    // ── CHAVE PÚBLICA VAPID (rota pública) ───────────
    // O navegador precisa dessa chave para criar a inscrição de push.
    // É pública por definição do protocolo Web Push — o par privado
    // (VAPID_PRIVATE_KEY) é que assina os envios e nunca sai do
    // servidor. Sem esta rota, o frontend não tinha como se inscrever,
    // e era por isso que nenhum push chegava a lugar nenhum.
    if (method === "GET" && path === "/push/vapid-key") {
      if (!CONFIG.VAPID_PUBLIC) {
        return jsonErr(res, "Push não configurado neste servidor", 503);
      }
      return jsonOk(res, { publicKey: CONFIG.VAPID_PUBLIC });
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
      enviarEmail(empresa.email, "🎉 Bem-vindo ao Workap!", EMAIL_TEMPLATES.boasVindas(empresa.nome, empresa.team_id, trialFim))
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

      // A conta de owner da Workap entra pelo MESMO formulário das
      // empresas — sem aba separada, sem URL escondida: e-mail e senha
      // como qualquer cliente. Ela é reconhecida aqui, antes da busca
      // no banco, porque não existe na tabela `empresas` (vive em
      // variável de ambiente, para não haver linha de administrador
      // dentro dos dados dos clientes).
      var ownerEmp = await buscarOwner(v.data.email);
      if (ownerEmp) {
        return await responderLoginOwner(res, ownerEmp, v.data.senha, body.deviceId, ip);
      }

      var result = await DB.select("empresas", `email=eq.${encodeURIComponent(v.data.email)}&select=*`);
      var empresa = result.body && result.body[0];

      // Verificar senha mesmo se empresa não existir (evitar timing attack)
      var senhaOk = false;
      if (empresa) {
        senhaOk = await verificarSenha(v.data.senha, empresa.senha_hash);
      } else {
        // Hash dummy para manter timing constante
        await bcrypt.compare(v.data.senha, SENHA_DUMMY);
      }

      // Mensagem distinta para "não existe conta" vs "senha errada", a
      // pedido do produto: sem isso, quem ainda não se cadastrou ficava
      // preso tentando a senha de novo, achando que tinha errado a senha.
      // Contrapartida consciente: isso permite descobrir se um e-mail tem
      // conta na Workap (enumeração de usuários). O risco é aceitável aqui
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

      // Senha certa, mas aparelho desconhecido (ou parado há mais de
      // 30 dias): manda código por e-mail e NÃO devolve token ainda.
      var deviceIdEmp = sanitizarDeviceId(body.deviceId);
      if (!(await dispositivoConfiavel(empresa.email, deviceIdEmp))) {
        await exigirCodigoDispositivo(empresa.email, empresa.nome);
        secLog("login_novo_dispositivo", { empresa_id: empresa.id });
        return jsonOk(res, {
          requer_codigo: true,
          email: empresa.email,
          message: "Enviamos um código para o seu e-mail para confirmar este aparelho."
        });
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
        await bcrypt.compare(v.data.senha, SENHA_DUMMY);
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

    // ── LOGIN OWNER (conta administrativa única da Workap) ───
    // Substitui a checagem anterior, que comparava email/senha em
    // texto plano dentro do JavaScript do frontend (worka.html e
    // worka-app.html) — qualquer pessoa via "Ver código-fonte" via a
    // senha real. Agora a senha nunca sai do servidor: só o hash
    // bcrypt fica configurado (via OWNER_PASSWORD_HASH), a mesma
    // disciplina de todo o resto deste arquivo.
    // Mantida no ar mesmo depois de o login de owner passar a funcionar
    // pelo formulário comum: navegadores guardam HTML antigo em cache e
    // PWAs instalados podem demorar dias para atualizar. Ela e o login
    // comum chamam a MESMA função, então não há como uma checagem ficar
    // mais frouxa que a outra com o tempo.
    if (method === "POST" && path === "/login/owner") {
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      var v = validate(body, {
        email: v => SANITIZE.email(v),
        senha: v => typeof v === "string" && v.length >= 1 ? v : null,
      });
      if (!v.ok) return jsonErr(res, "Email ou senha inválidos", 401);

      // O e-mail errado cai no mesmo "incorretos" da senha errada: esta
      // rota é a porta da conta que administra a plataforma toda, então
      // aqui não se confirma nem qual é o e-mail do owner.
      var ownerRota = await buscarOwner(v.data.email);
      if (!ownerRota) {
        await verificarSenha(v.data.senha, SENHA_DUMMY);
        secLog("login_owner_falhou", { ip });
        return jsonErr(res, "Email ou senha incorretos", 401);
      }

      return await responderLoginOwner(res, ownerRota, v.data.senha, body.deviceId, ip);
    }

    // ════════════════════════════════════════
    // FACE ID / TOUCH ID — 4 rotas
    // ════════════════════════════════════════

    // ── 1. Começar o cadastro do Face ID (exige sessão) ──
    // Só quem já entrou com a senha pode cadastrar. Sem isso, qualquer
    // pessoa cadastraria o próprio rosto numa conta alheia.
    if (method === "POST" && path === "/webauthn/registrar/inicio") {
      var authWA = requireAuth(req);
      if (!authWA) return jsonErr(res, "Não autorizado", 401);

      var rpIdReg = rpIdDaOrigem(req.headers.origin);
      if (!rpIdReg) return jsonErr(res, "Origem não permitida para Face ID", 403);

      var emailWA = authWA.email;
      if (!emailWA) return jsonErr(res, "Sessão sem e-mail", 400);

      var desafioReg = await guardarDesafio(emailWA, "registro");

      return jsonOk(res, {
        challenge: desafioReg,
        rp: { id: rpIdReg, name: "Workap" },
        user: {
          // O id do usuário no WebAuthn é opaco: usamos o e-mail em
          // bytes só para o aparelho saber que credenciais da mesma
          // conta se substituem, em vez de acumular uma por login.
          id: bufferParaB64url(Buffer.from(emailWA, "utf8")),
          name: emailWA,
          displayName: emailWA
        },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
        authenticatorSelection: {
          authenticatorAttachment: "platform",  // o próprio aparelho, não chavinha USB
          userVerification: "required",         // exige Face ID / Touch ID / senha
          residentKey: "preferred"
        },
        timeout: 60000,
        attestation: "none"
      });
    }

    // ── 2. Terminar o cadastro do Face ID (exige sessão) ──
    if (method === "POST" && path === "/webauthn/registrar/fim") {
      var authFim = requireAuth(req);
      if (!authFim) return jsonErr(res, "Não autorizado", 401);

      var rpIdFim = rpIdDaOrigem(req.headers.origin);
      if (!rpIdFim) return jsonErr(res, "Origem não permitida para Face ID", 403);

      var rawFim = await getBody(req);
      var bodyFim = parseBody(rawFim);
      if (!bodyFim || !bodyFim.clientDataJSON || !bodyFim.attestationObject) {
        return jsonErr(res, "Dados incompletos");
      }

      var attest;
      try { attest = cborDecodificar(b64urlParaBuffer(bodyFim.attestationObject)).valor; }
      catch (e) { return jsonErr(res, "Resposta do aparelho ilegível."); }

      var authDataBruto = attest instanceof Map ? attest.get("authData") : null;
      if (!authDataBruto) return jsonErr(res, "Resposta do aparelho incompleta.");

      var conf = await conferirCeremonia({
        email: authFim.email,
        finalidade: "registro",
        tipoEsperado: "webauthn.create",
        origem: req.headers.origin,
        rpId: rpIdFim,
        clientDataJSON: bodyFim.clientDataJSON,
        authDataB64: bufferParaB64url(authDataBruto)
      });
      if (!conf.ok) return jsonErr(res, conf.erro, 400);
      if (!conf.authData.credentialId || !conf.authData.chaveCose) {
        return jsonErr(res, "O aparelho não enviou a credencial.");
      }

      var chavePublica;
      try { chavePublica = coseParaChave(conf.authData.chaveCose); }
      catch (e) {
        secLog("webauthn_chave_recusada", { message: e.message });
        return jsonErr(res, "Tipo de segurança do aparelho não suportado.");
      }

      var credId = bufferParaB64url(conf.authData.credentialId);

      // Guardamos a chave em JWK (texto), e não o COSE cru: assim a
      // verificação do login não precisa reinterpretar binário toda vez.
      var registro = {
        email:        authFim.email,
        empresa_id:   authFim.empresa_id || null,
        funcionario_id: authFim.funcionario_id || null,
        credential_id: credId,
        public_key:   JSON.stringify(chavePublica.export({ format: "jwk" })),
        counter:      conf.authData.contador,
        device_label: SANITIZE.string(bodyFim.descricao || "", 80) || null
      };

      var jaTem = await supabase("GET", "webauthn_credentials",
        { query: `credential_id=eq.${encodeURIComponent(credId)}&select=id&limit=1` }
      ).catch(() => ({ body: [] }));

      if (jaTem.body && jaTem.body[0]) {
        await supabase("PATCH", "webauthn_credentials",
          { query: `id=eq.${jaTem.body[0].id}`, body: registro });
      } else {
        await supabase("POST", "webauthn_credentials", { body: registro });
      }

      secLog("webauthn_cadastrado", { email_hash: crypto.createHash("sha256").update(authFim.email).digest("hex").substring(0, 8) });
      return jsonOk(res, { ok: true, message: "Este aparelho agora entra com Face ID." });
    }

    // ── 3. Começar o login por Face ID (rota pública) ──
    if (method === "POST" && path === "/webauthn/login/inicio") {
      var rpIdLog = rpIdDaOrigem(req.headers.origin);
      if (!rpIdLog) return jsonErr(res, "Origem não permitida para Face ID", 403);

      var rawLog = await getBody(req);
      var bodyLog = parseBody(rawLog);
      var emailLog = SANITIZE.email(bodyLog && bodyLog.email);
      if (!emailLog) return jsonErr(res, "E-mail inválido");

      var creds = await supabase("GET", "webauthn_credentials",
        { query: `email=eq.${encodeURIComponent(emailLog)}&select=credential_id` }
      ).catch(() => ({ body: [] }));

      var lista = (creds.body || []).map(function (c) {
        return { type: "public-key", id: c.credential_id };
      });

      // Conta sem Face ID cadastrado devolve lista vazia em vez de erro:
      // o frontend cai no código por e-mail sozinho, e quem estiver
      // sondando não descobre quais contas têm biometria.
      if (!lista.length) return jsonOk(res, { disponivel: false, allowCredentials: [] });

      return jsonOk(res, {
        disponivel: true,
        challenge: await guardarDesafio(emailLog, "login"),
        rpId: rpIdLog,
        allowCredentials: lista,
        userVerification: "required",
        timeout: 60000
      });
    }

    // ── 4. Terminar o login por Face ID (rota pública) ──
    // Substitui o código de 6 dígitos: prova que é o mesmo aparelho E
    // que a pessoa passou pelo desbloqueio dele. A senha da conta já
    // foi conferida no passo anterior do login.
    if (method === "POST" && path === "/webauthn/login/fim") {
      var rpIdVer = rpIdDaOrigem(req.headers.origin);
      if (!rpIdVer) return jsonErr(res, "Origem não permitida para Face ID", 403);

      var rawVer = await getBody(req);
      var bodyVer = parseBody(rawVer);
      if (!bodyVer) return jsonErr(res, "Dados inválidos");

      var emailVer = SANITIZE.email(bodyVer.email);
      var senhaVer = typeof bodyVer.senha === "string" ? bodyVer.senha : "";
      if (!emailVer || !senhaVer) return jsonErr(res, "Dados inválidos");
      if (!bodyVer.credentialId || !bodyVer.clientDataJSON || !bodyVer.authenticatorData || !bodyVer.signature) {
        return jsonErr(res, "Resposta do aparelho incompleta.");
      }

      // A senha continua obrigatória. O Face ID substitui o CÓDIGO do
      // e-mail, não a senha — sem isso, quem pegasse o celular
      // desbloqueado entraria sem saber a senha da conta.
      var ownerVer = await buscarOwner(emailVer);
      var empresaVer = null;
      if (ownerVer) {
        if (!(await verificarSenha(senhaVer, ownerVer.senha_hash))) {
          secLog("webauthn_senha_errada", { ip });
          return jsonErr(res, "Email ou senha incorretos", 401);
        }
      } else {
        var buscaVer = await DB.select("empresas", `email=eq.${encodeURIComponent(emailVer)}&select=*`);
        empresaVer = buscaVer.body && buscaVer.body[0];
        if (!empresaVer || !(await verificarSenha(senhaVer, empresaVer.senha_hash))) {
          secLog("webauthn_senha_errada", { ip });
          return jsonErr(res, "Email ou senha incorretos", 401);
        }
      }

      var credBusca = await supabase("GET", "webauthn_credentials", {
        query: `credential_id=eq.${encodeURIComponent(bodyVer.credentialId)}` +
               `&email=eq.${encodeURIComponent(emailVer)}&select=*&limit=1`
      }).catch(() => ({ body: [] }));

      var cred = credBusca.body && credBusca.body[0];
      if (!cred) {
        secLog("webauthn_credencial_desconhecida", { ip });
        return jsonErr(res, "Este aparelho não está cadastrado.", 401);
      }

      var confVer = await conferirCeremonia({
        email: emailVer,
        finalidade: "login",
        tipoEsperado: "webauthn.get",
        origem: req.headers.origin,
        rpId: rpIdVer,
        clientDataJSON: bodyVer.clientDataJSON,
        authDataB64: bodyVer.authenticatorData
      });
      if (!confVer.ok) return jsonErr(res, confVer.erro, 401);

      // A assinatura cobre authenticatorData + hash do clientDataJSON.
      // É isto que prova que a chave privada — que nunca saiu do chip
      // de segurança do aparelho — participou desta operação.
      var authBuf = b64urlParaBuffer(bodyVer.authenticatorData);
      var hashCliente = crypto.createHash("sha256").update(b64urlParaBuffer(bodyVer.clientDataJSON)).digest();
      var assinado = Buffer.concat([authBuf, hashCliente]);

      var chaveVer;
      try { chaveVer = crypto.createPublicKey({ key: JSON.parse(cred.public_key), format: "jwk" }); }
      catch (e) { return jsonErr(res, "Credencial corrompida. Cadastre o Face ID de novo.", 401); }

      var assinaturaOk = crypto.verify("sha256", assinado, chaveVer, b64urlParaBuffer(bodyVer.signature));
      if (!assinaturaOk) {
        secLog("webauthn_assinatura_invalida", { ip });
        return jsonErr(res, "Não foi possível confirmar este aparelho.", 401);
      }

      // Contador: o autenticador incrementa a cada uso. Voltar para trás
      // indica credencial clonada. Zero dos dois lados significa que o
      // aparelho não usa contador (comum no iPhone) — aí não dá sinal.
      if (confVer.authData.contador > 0 && confVer.authData.contador <= Number(cred.counter)) {
        secLog("webauthn_contador_suspeito", { guardado: cred.counter, recebido: confVer.authData.contador });
        return jsonErr(res, "Não foi possível confirmar este aparelho.", 401);
      }

      await supabase("PATCH", "webauthn_credentials", {
        query: `id=eq.${cred.id}`,
        body: { counter: confVer.authData.contador, last_used_at: new Date().toISOString() }
      }).catch(() => {});

      // Aparelho provado: registra como confiável, igual faria o código
      // por e-mail, para os próximos 30 dias entrarem direto.
      var deviceVer = sanitizarDeviceId(bodyVer.deviceId);
      if (deviceVer) {
        await registrarDispositivo(emailVer, deviceVer, empresaVer ? empresaVer.id : null, bodyVer.descricao);
      }

      if (ownerVer) {
        registrarLoginOwner(ownerVer);
        secLog("login_owner_ok", { via: "face_id" });
        return jsonOk(res, {
          token: jwtSign({ email: emailVer, role: "owner_saas" }),
          owner: { nome: ownerVer.nome, email: emailVer },
          is_owner: true
        });
      }

      var trialVer = null;
      if (empresaVer.status === "trial") {
        var diasVer = Math.ceil((new Date(empresaVer.trial_fim) - Date.now()) / (1000 * 60 * 60 * 24));
        trialVer = { dias_restantes: diasVer, expirado: diasVer <= 0 };
      }
      secLog("login_ok", { empresa_id: empresaVer.id, via: "face_id" });
      delete empresaVer.senha_hash;
      return jsonOk(res, {
        token: jwtSign({ empresa_id: empresaVer.id, email: empresaVer.email, role: "dono" }),
        empresa: empresaVer,
        trial: trialVer
      });
    }

    // ── CONFIRMAR APARELHO NOVO (rota pública) ───────
    // Segundo passo do login quando o aparelho não é reconhecido.
    // A senha é conferida DE NOVO aqui de propósito: sem isso,
    // qualquer pessoa que soubesse o e-mail poderia tentar adivinhar
    // só o código de 6 dígitos e entrar sem nunca saber a senha.
    if (method === "POST" && path === "/login/confirmar-dispositivo") {
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      var emailConf = SANITIZE.email(body.email);
      var codigoConf = SANITIZE.string(body.codigo || "", 6);
      var senhaConf = typeof body.senha === "string" ? body.senha : "";
      var deviceIdConf = sanitizarDeviceId(body.deviceId);

      if (!emailConf || !/^\d{6}$/.test(codigoConf) || !senhaConf) {
        return jsonErr(res, "Dados inválidos");
      }
      if (!deviceIdConf) return jsonErr(res, "Identificação do aparelho inválida.");

      var ownerConf = await buscarOwner(emailConf);
      var ehOwner = !!ownerConf;
      var empresaConf = null;

      if (ehOwner) {
        if (!(await verificarSenha(senhaConf, ownerConf.senha_hash))) {
          secLog("confirmar_dispositivo_senha_errada", { ip });
          return jsonErr(res, "Email ou senha incorretos", 401);
        }
      } else {
        var buscaConf = await DB.select("empresas", `email=eq.${encodeURIComponent(emailConf)}&select=*`);
        empresaConf = buscaConf.body && buscaConf.body[0];
        if (!empresaConf || !(await verificarSenha(senhaConf, empresaConf.senha_hash))) {
          secLog("confirmar_dispositivo_senha_errada", { ip });
          return jsonErr(res, "Email ou senha incorretos", 401);
        }
      }

      // Só depois da senha conferida é que o código é validado — assim
      // o limite de 5 tentativas do OTP não é gasto por quem nem tem a senha.
      var otpConf = await verificarOTP(emailConf, codigoConf);
      if (!otpConf.ok) return jsonErr(res, otpConf.erro);

      await registrarDispositivo(
        emailConf,
        deviceIdConf,
        empresaConf ? empresaConf.id : null,
        body.descricao
      );

      if (ehOwner) {
        registrarLoginOwner(ownerConf);
        secLog("login_owner_ok", { via: "novo_dispositivo" });
        return jsonOk(res, {
          token: jwtSign({ email: emailConf, role: "owner_saas" }),
          owner: { nome: ownerConf.nome, email: emailConf },
          // Mesmo sinal do login comum: quem decide qual painel abrir é
          // o servidor, não uma lembrança guardada no navegador entre
          // os dois passos do login.
          is_owner: true
        });
      }

      var trialConf = null;
      if (empresaConf.status === "trial") {
        var diasConf = Math.ceil((new Date(empresaConf.trial_fim) - Date.now()) / (1000*60*60*24));
        trialConf = { dias_restantes: diasConf, expirado: diasConf <= 0 };
      }
      secLog("login_ok", { empresa_id: empresaConf.id, via: "novo_dispositivo" });
      delete empresaConf.senha_hash;
      return jsonOk(res, {
        token: jwtSign({ empresa_id: empresaConf.id, email: empresaConf.email, role: "dono" }),
        empresa: empresaConf,
        trial: trialConf
      });
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
        await enviarEmail(email, "🔐 Seu código de verificação Workap", EMAIL_TEMPLATES.codigo(nome, codigo));
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
        // Um e-mail de owner não pode virar empresa. Se virasse, o login
        // acharia o owner primeiro e sempre abriria o painel da
        // plataforma — a conta de empresa existiria no banco sem
        // nenhuma forma de entrar nela.
        if (await buscarOwner(email)) {
          secLog("cadastro_email_de_owner", { ip });
          res.writeHead(409);
          return res.end(JSON.stringify({
            error: "Este e-mail já tem uma conta Workap. Faça login para continuar.",
            ja_cadastrado: true
          }));
        }

        var jaExiste = await DB.select("empresas", `email=eq.${encodeURIComponent(email)}&select=id`);
        if (jaExiste.body && jaExiste.body.length > 0) {
          secLog("cadastro_duplicado_trial", { email_hash: crypto.createHash("sha256").update(email).digest("hex").substring(0, 8) });
          // ja_cadastrado permite o frontend oferecer "Fazer login" em vez
          // de só mostrar um erro genérico e deixar a pessoa travada.
          res.writeHead(409);
          return res.end(JSON.stringify({
            error: "Este e-mail já tem uma conta Workap. Faça login para continuar.",
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
          enviarEmail(emp.email, "🎉 Bem-vindo ao Workap!", EMAIL_TEMPLATES.boasVindas(emp.nome, emp.team_id, trialFim))
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
        enviarEmail(email, "🔑 Redefinir sua senha — Workap", EMAIL_TEMPLATES.recuperarSenha(conta.nome, codigoRec))
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
      if (!pixUrl.hostname.includes("duttyfy") && !pixUrl.hostname.includes("workap")) {
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
        item: { title: "Plano Completo Workap", price: valorCobrado, quantity: 1 },
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

      // Utmify: avisa que a cobrança nasceu. Fire-and-forget de
      // propósito — o PIX já foi gerado, e uma integração de marketing
      // fora do ar não pode segurar a resposta nem derrubar a venda.
      enviarUtmify({
        orderId:       response.body.transactionId,
        status:        "waiting_payment",
        criadoEm:      Date.now(),
        valorCentavos: valorCobrado,
        cliente:       { nome: nome, email: email, telefone: tel || null, documento: doc || null, ip: ip },
        utm:           body.utm
      }).catch(e => secLog("utmify_erro", { message: e.message }));

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
      if (!pixUrl2.hostname.includes("duttyfy") && !pixUrl2.hostname.includes("workap")) {
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
          enviarEmail(empPag.email, "✅ Pagamento confirmado — Workap", EMAIL_TEMPLATES.pagamentoConfirmado(empPag.nome, "49,99"))
            .catch(() => {});
          secLog("pagamento_confirmado", { empresa_id: empPag.id });

          // Utmify: a venda virou receita. Este é o evento que casa o
          // dinheiro com o anúncio — sem ele o painel de anúncios
          // mostra cliques e nenhuma conversão.
          enviarUtmify({
            orderId:       transactionId,
            status:        "paid",
            criadoEm:      Date.now(),
            pagoEm:        Date.now(),
            valorCentavos: CONFIG.PLANO_CENTAVOS,
            cliente:       { nome: empPag.nome, email: empPag.email, ip: ip },
            utm:           null   // o rastreio já foi enviado na criação
          }).catch(e => secLog("utmify_erro", { message: e.message }));
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
      // Owner da Workap: sessão válida, mas sem empresa vinculada — o
      // app monta o menu completo a partir do role, sem depender de
      // dados de empresa nenhuma.
      if (authPayload.role === "owner_saas") {
        return jsonOk(res, {
          owner: { email: authPayload.email, nome: "Owner Workap" },
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

    // ── MÉTRICAS DA PLATAFORMA (somente owner) ───────
    // Substitui os números que estavam escritos à mão no HTML do painel
    // (47 empresas, R$ 1.170 de MRR, 312 usuários, 94% de retenção).
    // Eram números de maquete, mas apareciam com a mesma cara de dado
    // real — e a decisão de ligar tráfego pago sairia de olhar isso.
    if (method === "GET" && path === "/owner/metricas") {
      if (!hasPermission(authPayload, "saas:read")) {
        return jsonErr(res, "Apenas o owner da Workap pode ver isso", 403);
      }

      var todas = await DB.select("empresas", "select=id,nome,status,created_at,trial_fim,ramo,team_id,email");
      var lista = todas.body || [];

      var porStatus = { ativa: 0, trial: 0, inadimplente: 0, cancelada: 0, suspensa: 0 };
      lista.forEach(function (e) {
        if (porStatus[e.status] !== undefined) porStatus[e.status]++;
      });

      // Início do mês corrente, para "novas" e "cancelamentos no mês".
      var agora = new Date();
      var inicioDoMes = new Date(agora.getFullYear(), agora.getMonth(), 1);
      var novasNoMes = lista.filter(function (e) {
        return e.created_at && new Date(e.created_at) >= inicioDoMes;
      }).length;

      // Funcionários ativos de todas as empresas.
      var funcs = await DB.select("funcionarios", "select=id,status").catch(() => ({ body: [] }));
      var funcionariosAtivos = (funcs.body || []).filter(function (f) { return f.status === "ativo"; }).length;

      // MRR = quem paga de fato. Trial não entra: ainda não é receita,
      // e somar os dois foi o erro que fez o número da maquete parecer
      // bom. O valor sai de PLANO_CENTAVOS, mesma fonte da cobrança.
      var mrrCentavos = porStatus.ativa * CONFIG.PLANO_CENTAVOS;

      return jsonOk(res, {
        assinantes_pagos:     porStatus.ativa,
        assinantes_trial:     porStatus.trial,
        inadimplentes:        porStatus.inadimplente,
        cancelados:           porStatus.cancelada,
        suspensos:            porStatus.suspensa,
        total_empresas:       lista.length,
        novas_no_mes:         novasNoMes,
        funcionarios_ativos:  funcionariosAtivos,
        mrr_centavos:         mrrCentavos,
        mrr_reais:            centavosParaReais(mrrCentavos),
        valor_plano_reais:    centavosParaReais(CONFIG.PLANO_CENTAVOS)
      });
    }

    // ── LISTA DE ASSINANTES (somente owner) ──────────
    if (method === "GET" && path === "/owner/assinantes") {
      if (!hasPermission(authPayload, "saas:read")) {
        return jsonErr(res, "Apenas o owner da Workap pode ver isso", 403);
      }

      var emp = await DB.select("empresas",
        "select=id,nome,email,ramo,status,team_id,created_at,trial_fim&order=created_at.desc");
      var empresas = emp.body || [];

      // Uma consulta só de funcionários e a contagem feita aqui: uma
      // consulta por empresa faria N+1 chamadas ao banco, e o painel
      // ficaria mais lento a cada cliente novo — justo o contrário do
      // que se quer conforme a base cresce.
      var todosFuncs = await DB.select("funcionarios", "select=empresa_id,status").catch(() => ({ body: [] }));
      var contagem = {};
      (todosFuncs.body || []).forEach(function (f) {
        if (f.status !== "ativo") return;
        contagem[f.empresa_id] = (contagem[f.empresa_id] || 0) + 1;
      });

      return jsonOk(res, empresas.map(function (e) {
        var diasTrial = null;
        if (e.status === "trial" && e.trial_fim) {
          diasTrial = Math.ceil((new Date(e.trial_fim) - Date.now()) / (1000 * 60 * 60 * 24));
        }
        return {
          id: e.id, nome: e.nome, email: e.email, ramo: e.ramo || null,
          status: e.status, team_id: e.team_id, created_at: e.created_at,
          funcionarios: contagem[e.id] || 0,
          dias_trial_restantes: diasTrial
        };
      }));
    }

    // ── SAÚDE DA PLATAFORMA (somente owner) ──────────
    // Substitui os quadros de "99,8% de uptime, 142ms de latência,
    // 18.4k requisições/dia, 2.3GB de storage" e a lista de serviços
    // toda marcada como "Online" — nenhum daqueles valores era medido.
    // Aqui tudo é aferido na hora: o que dá para medir é medido, o que
    // não dá aparece como "não medido" em vez de um número inventado.
    if (method === "GET" && path === "/owner/saude") {
      if (!hasPermission(authPayload, "saas:read")) {
        return jsonErr(res, "Apenas o owner da Workap pode ver isso", 403);
      }

      // Latência real do banco: uma consulta mínima, cronometrada.
      var t0 = Date.now();
      var bancoOk = true, bancoErro = null;
      try { await supabase("GET", "empresas", { query: "select=id&limit=1" }); }
      catch (e) { bancoOk = false; bancoErro = e.message; }
      var latenciaBanco = Date.now() - t0;

      var cfgPlat = await lerConfigPlataforma();

      return jsonOk(res, {
        servidor: {
          no_ar_desde_segundos: Math.floor(process.uptime()),
          node:                 process.version,
          ambiente:             process.env.NODE_ENV || "development",
          memoria_mb:           Math.round(process.memoryUsage().rss / 1024 / 1024)
        },
        servicos: [
          { nome: "Banco de dados (Supabase)", ok: bancoOk,
            detalhe: bancoOk ? latenciaBanco + " ms" : (bancoErro || "sem resposta") },
          { nome: "E-mail (Resend)", ok: !!CONFIG.RESEND_KEY,
            detalhe: CONFIG.RESEND_KEY
              ? "Remetente: onboarding@resend.dev — em modo de teste só entrega no e-mail dono da conta Resend"
              : "Chave não configurada" },
          { nome: "Pagamento PIX (Duttyfy)", ok: !!CONFIG.PIX_URL,
            detalhe: CONFIG.PIX_URL ? "URL configurada" : "URL não configurada" },
          { nome: "Notificações push (VAPID)", ok: !!CONFIG.VAPID_PUBLIC,
            detalhe: CONFIG.VAPID_PUBLIC ? "Chaves válidas" : "Chaves ausentes ou inválidas" },
          { nome: "Rastreio de origem (Utmify)", ok: cfgPlat.utmify_ativo === "1" && !!cfgPlat.utmify_token,
            detalhe: cfgPlat.utmify_ativo === "1"
              ? (cfgPlat.utmify_token ? "Integração ligada" : "Ligada, mas sem token")
              : "Desligada" }
        ],
        // Uptime real do serviço e uso de disco do banco não são
        // medidos por este backend — dizer que não sabe é mais útil do
        // que devolver um número que ninguém apurou.
        nao_medido: ["Uptime histórico", "Requisições por dia", "Uso de armazenamento"]
      });
    }

    // ── CONFIGURAÇÃO DA PLATAFORMA (somente owner) ───
    if (method === "GET" && path === "/owner/config") {
      if (!hasPermission(authPayload, "saas:read")) {
        return jsonErr(res, "Apenas o owner da Workap pode ver isso", 403);
      }
      var cfgLida = await lerConfigPlataforma();
      var tokenUtm = cfgLida.utmify_token || "";
      return jsonOk(res, {
        // Valores que hoje vivem no código e só mudam com deploy —
        // mostrados como leitura, para o painel não fingir que um campo
        // editável muda alguma coisa.
        preco_reais:      centavosParaReais(CONFIG.PLANO_CENTAVOS),
        dias_trial:       7,
        remetente_email:  "onboarding@resend.dev",
        owner_email:      authPayload.email,
        utmify_ativo:     cfgLida.utmify_ativo === "1",
        // Nunca devolve o token inteiro: quem já está logado não
        // precisa vê-lo de novo, e um print de tela deixaria de ser
        // inofensivo.
        utmify_token_fim: tokenUtm ? "••••" + tokenUtm.slice(-4) : null,
        utmify_url:       cfgLida.utmify_url || UTMIFY_URL_PADRAO
      });
    }

    if (method === "PUT" && path === "/owner/config") {
      if (!hasPermission(authPayload, "saas:write")) {
        return jsonErr(res, "Apenas o owner da Workap pode alterar isso", 403);
      }
      var rawCfg = await getBody(req);
      var bodyCfg = parseBody(rawCfg);
      if (!bodyCfg) return jsonErr(res, "Dados inválidos");

      if (typeof bodyCfg.utmify_ativo === "boolean") {
        await gravarConfigPlataforma("utmify_ativo", bodyCfg.utmify_ativo ? "1" : "0");
      }
      if (typeof bodyCfg.utmify_token === "string" && bodyCfg.utmify_token.trim()) {
        await gravarConfigPlataforma("utmify_token", bodyCfg.utmify_token.trim());
      }
      if (typeof bodyCfg.utmify_url === "string" && bodyCfg.utmify_url.trim()) {
        var urlTeste = bodyCfg.utmify_url.trim();
        try { new URL(urlTeste); } catch (e) { return jsonErr(res, "URL da Utmify inválida"); }
        await gravarConfigPlataforma("utmify_url", urlTeste);
      }

      secLog("config_plataforma_alterada", {});
      return jsonOk(res, { ok: true });
    }

    // ── TESTAR A UTMIFY (somente owner) ──────────────
    // Manda um pedido marcado como teste e devolve o que a Utmify
    // respondeu, palavra por palavra. Sem isto, descobrir que a
    // integração não funciona levaria até a primeira venda real.
    if (method === "POST" && path === "/owner/utmify/testar") {
      if (!hasPermission(authPayload, "saas:write")) {
        return jsonErr(res, "Apenas o owner da Workap pode fazer isso", 403);
      }
      var cfgT = await lerConfigPlataforma();
      if (!cfgT.utmify_token) return jsonErr(res, "Cole o token da Utmify antes de testar.");

      var r = await enviarUtmify({
        orderId:       "teste-" + Date.now(),
        status:        "waiting_payment",
        criadoEm:      Date.now(),
        valorCentavos: CONFIG.PLANO_CENTAVOS,
        cliente:       { nome: "Pedido de teste", email: authPayload.email, ip: ip },
        utm:           { utm_source: "workap", utm_medium: "teste-painel", utm_campaign: "verificacao" },
        teste:         true
      });

      if (r.motivo === "integracao_desligada") {
        return jsonErr(res, "Ligue a integração antes de testar.");
      }
      return jsonOk(res, {
        sucesso:  r.enviado,
        status:   r.status,
        resposta: r.resposta || "(sem corpo na resposta)"
      });
    }

    if (method === "GET" && path === "/owner/utmify/envios") {
      if (!hasPermission(authPayload, "saas:read")) {
        return jsonErr(res, "Apenas o owner da Workap pode ver isso", 403);
      }
      var envios = await supabase("GET", "utmify_envios",
        { query: "select=*&order=created_at.desc&limit=30" }
      ).catch(() => ({ body: [] }));
      return jsonOk(res, envios.body || []);
    }

    // ── TROCAR A SENHA DO OWNER ──────────────────────
    // O formulário existia na tela e não fazia nada. Agora funciona,
    // porque a conta passou a viver no banco (migration 003).
    if (method === "POST" && path === "/owner/senha") {
      if (authPayload.role !== "owner_saas") {
        return jsonErr(res, "Apenas o owner pode trocar a própria senha", 403);
      }
      var rawS = await getBody(req);
      var bodyS = parseBody(rawS);
      if (!bodyS) return jsonErr(res, "Dados inválidos");

      var atual = typeof bodyS.senha_atual === "string" ? bodyS.senha_atual : "";
      var nova  = typeof bodyS.senha_nova  === "string" ? bodyS.senha_nova  : "";
      if (nova.length < 8) return jsonErr(res, "A nova senha precisa ter pelo menos 8 caracteres.");

      var ownerAtual = await buscarOwner(authPayload.email);
      if (!ownerAtual) return jsonErr(res, "Conta de owner não encontrada", 404);

      // A senha atual é exigida mesmo com sessão aberta: sem isso,
      // um celular desbloqueado por um minuto vira uma conta perdida.
      if (!(await verificarSenha(atual, ownerAtual.senha_hash))) {
        secLog("owner_troca_senha_negada", { ip });
        return jsonErr(res, "Senha atual incorreta.", 401);
      }
      if (ownerAtual.origem !== "banco") {
        return jsonErr(res, "Esta conta ainda está configurada por variável de ambiente. Rode a migration 003 para poder trocar a senha por aqui.", 409);
      }

      await supabase("PATCH", "owners_plataforma", {
        query: `id=eq.${ownerAtual.id}`,
        body: { senha_hash: await hashSenha(nova) }
      });

      secLog("owner_senha_alterada", {});
      return jsonOk(res, { ok: true, message: "Senha alterada. Use a nova no próximo login." });
    }

    // ── ATIVIDADE DA PLATAFORMA (somente owner) ──────
    // A rota /logs existente filtra por empresa_id, que o token de
    // owner não carrega — para ele, precisa ser a atividade de todas
    // as empresas junta.
    if (method === "GET" && path === "/owner/logs") {
      if (!hasPermission(authPayload, "saas:read")) {
        return jsonErr(res, "Apenas o owner da Workap pode ver isso", 403);
      }
      var limiteLog = SANITIZE.int(url.searchParams.get("limit"), 1, 200) || 60;
      var logs = await DB.select("logs_sistema",
        `select=tipo,descricao,created_at,empresa_id&order=created_at.desc&limit=${limiteLog}`
      ).catch(() => ({ body: [] }));
      return jsonOk(res, logs.body || []);
    }

    // ── COMUNICADOS DA PLATAFORMA (somente owner) ────
    // Envia um aviso da Workap para as empresas clientes, por e-mail e
    // push. Só o owner_saas pode: é comunicação da plataforma, não de
    // uma empresa para os funcionários dela.
    if (method === "POST" && path === "/owner/comunicados") {
      if (!hasPermission(authPayload, "saas:write")) {
        secLog("permission_denied", { role: authPayload.role, action: "comunicado_plataforma" });
        return jsonErr(res, "Apenas o owner da Workap pode enviar comunicados", 403);
      }
      var raw = await getBody(req);
      var body = parseBody(raw);
      if (!body) return jsonErr(res, "Dados inválidos");

      var tituloCom = SANITIZE.string(body.titulo, 150);
      var mensagemCom = SANITIZE.string(body.mensagem, 4000);
      if (!tituloCom) return jsonErr(res, "Informe o título do comunicado.");
      if (!mensagemCom) return jsonErr(res, "Informe a mensagem do comunicado.");

      var destinoCom = ["todas", "ativa", "trial", "inadimplente"].includes(body.destino)
        ? body.destino : "todas";

      // Monta o filtro por status. "todas" não filtra nada.
      var filtroEmpresas = "select=id,nome,email";
      if (destinoCom !== "todas") filtroEmpresas = `status=eq.${destinoCom}&` + filtroEmpresas;

      var alvo = await DB.select("empresas", filtroEmpresas);
      var empresasAlvo = (alvo.body || []).filter(e => e.email);

      if (empresasAlvo.length === 0) {
        return jsonErr(res, "Nenhuma empresa encontrada para esse destino.", 404);
      }

      // Envio sequencial de propósito: o Resend tem limite por segundo
      // e disparar tudo em paralelo com muitas empresas derrubaria os
      // envios em cascata. Cada falha é contada, não interrompe o resto.
      var enviados = 0;
      var falhas = 0;
      for (var emp of empresasAlvo) {
        try {
          await enviarEmail(emp.email, tituloCom, EMAIL_TEMPLATES.comunicadoPlataforma(tituloCom, mensagemCom));
          enviados++;
        } catch (e) {
          falhas++;
          secLog("comunicado_email_falhou", { empresa_id: emp.id, message: e.message });
        }
        // Push é complementar: quem não tiver aparelho inscrito
        // simplesmente não recebe, sem afetar a contagem de e-mails.
        enviarPush(emp.id, { title: tituloCom, body: mensagemCom.substring(0, 140), url: "worka-app.html" })
          .catch(() => {});
      }

      // Histórico: registra o que foi enviado para o owner poder
      // consultar depois, mesmo que o status das empresas mude.
      var registroCom = await DB.insert("comunicados_plataforma", {
        titulo: tituloCom,
        mensagem: mensagemCom,
        destino: destinoCom,
        total_enviado: enviados,
        total_falhou: falhas
      }).catch(e => {
        secLog("comunicado_historico_falhou", { message: e.message });
        return { body: [] };
      });

      secLog("comunicado_enviado", { destino: destinoCom, enviados, falhas });
      return jsonOk(res, {
        ok: true,
        enviados,
        falhas,
        total: empresasAlvo.length,
        comunicado: (registroCom.body && registroCom.body[0]) || null
      }, 201);
    }

    if (method === "GET" && path === "/owner/comunicados") {
      if (!hasPermission(authPayload, "saas:read")) {
        return jsonErr(res, "Apenas o owner da Workap pode ver comunicados", 403);
      }
      var historico = await DB.select("comunicados_plataforma", "select=*&order=created_at.desc&limit=50")
        .catch(e => {
          secLog("comunicados_listagem_falhou", { message: e.message });
          return { body: null };
        });
      if (historico.body === null) return jsonOk(res, { comunicados: [], tabela_ausente: true });
      return jsonOk(res, { comunicados: historico.body || [] });
    }

    // Quantas empresas receberiam um comunicado, por destino. Usado
    // para o painel mostrar "vai para N empresas" ANTES de enviar —
    // disparar e-mail para a base inteira não pode ser uma surpresa.
    if (method === "GET" && path === "/owner/comunicados/alcance") {
      if (!hasPermission(authPayload, "saas:read")) {
        return jsonErr(res, "Apenas o owner da Workap pode ver isso", 403);
      }
      var todasEmp = await DB.select("empresas", "select=id,status").catch(() => ({ body: [] }));
      var lista = todasEmp.body || [];
      return jsonOk(res, {
        todas:        lista.length,
        ativa:        lista.filter(e => e.status === "ativa").length,
        trial:        lista.filter(e => e.status === "trial").length,
        inadimplente: lista.filter(e => e.status === "inadimplente").length
      });
    }

    // ── CUPONS — GESTÃO (somente owner da Workap) ─────
    // Cupom vale para a assinatura da plataforma, não para nada dentro
    // da empresa cliente — por isso só o role owner_saas administra.
    if (method === "GET" && path === "/cupons") {
      if (!hasPermission(authPayload, "cupons:read")) {
        secLog("permission_denied", { role: authPayload.role, action: "cupons:read" });
        return jsonErr(res, "Apenas o owner da Workap pode ver cupons", 403);
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
        return jsonErr(res, "Apenas o owner da Workap pode criar cupons", 403);
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
        return jsonErr(res, "Apenas o owner da Workap pode alterar cupons", 403);
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
        return jsonErr(res, "Apenas o owner da Workap pode remover cupons", 403);
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
          url: "worka-app.html"
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
    // O financeiro atende os dois painéis. Para empresa cliente, os
    // lançamentos são os dela; para o owner da plataforma — que não tem
    // empresa — são os da própria Workap (servidor, domínio, gateway,
    // anúncios), gravados com empresa_id nulo. O filtro sai daqui, de um
    // lugar só, para não haver rota que esqueça de aplicá-lo e acabe
    // somando a conta de luz de um cliente no caixa da plataforma.
    function filtroFinanceiro(auth) {
      return auth.role === "owner_saas"
        ? "empresa_id=is.null"
        : `empresa_id=eq.${auth.empresa_id}`;
    }

    if (method === "GET" && path === "/financeiro/resumo") {
      if (!hasPermission(authPayload, "financeiro:read")) {
        return jsonErr(res, "Sem permissão para ver dados financeiros", 403);
      }
      var escopo = filtroFinanceiro(authPayload);

      var inicioMes = new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString();
      var lancamentos = await DB.select("lancamentos_financeiros",
        `${escopo}&data=gte.${inicioMes}&select=tipo,valor,categoria`
      );

      var entradas = (lancamentos.body || []).filter(l => l.tipo === "entrada").reduce((s, l) => s + parseFloat(l.valor), 0);
      var saidas   = (lancamentos.body || []).filter(l => l.tipo === "saida").reduce((s, l) => s + parseFloat(l.valor), 0);

      // Saldo = soma de TODOS os lançamentos históricos, não só do mês
      var todosLancamentos = await DB.select("lancamentos_financeiros", `${escopo}&select=tipo,valor`);
      var saldo = (todosLancamentos.body || []).reduce((s, l) =>
        s + (l.tipo === "entrada" ? parseFloat(l.valor) : -parseFloat(l.valor)), 0
      );

      return jsonOk(res, {
        saldo_atual: Math.round(saldo * 100) / 100,
        receita_mes: Math.round(entradas * 100) / 100,
        despesas_mes: Math.round(saidas * 100) / 100,
        lucro_mes: Math.round((entradas - saidas) * 100) / 100,
        escopo: authPayload.role === "owner_saas" ? "plataforma" : "empresa"
      });
    }

    // Lista os lançamentos para a tela poder mostrar o que foi
    // registrado. Sem isto, a pessoa lança uma despesa e ela some da
    // vista — só o total muda, sem como conferir nem lembrar o que foi.
    if (method === "GET" && path === "/financeiro/lancamentos") {
      if (!hasPermission(authPayload, "financeiro:read")) {
        return jsonErr(res, "Sem permissão para ver dados financeiros", 403);
      }
      var limite = SANITIZE.int(url.searchParams.get("limit"), 1, 200) || 50;
      var resultado = await DB.select("lancamentos_financeiros",
        `${filtroFinanceiro(authPayload)}&select=*&order=data.desc&limit=${limite}`
      );
      return jsonOk(res, resultado.body || []);
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

      // Data escolhida pela pessoa (uma despesa costuma ser lançada
      // depois de ter acontecido). Sem valor válido, cai em agora.
      var quando = new Date();
      if (body.data) {
        var informada = new Date(body.data);
        if (!isNaN(informada.getTime())) quando = informada;
      }

      var ehOwnerFin = authPayload.role === "owner_saas";
      var result = await DB.insert("lancamentos_financeiros", {
        empresa_id: ehOwnerFin ? null : authPayload.empresa_id,
        tipo, valor,
        descricao,
        categoria: SANITIZE.categoriaFinanceira(body.categoria),
        data: quando.toISOString()
      });

      secLog("lancamento_financeiro", {
        empresa_id: ehOwnerFin ? "plataforma" : authPayload.empresa_id, tipo, valor
      });
      return jsonOk(res, { lancamento: result.body[0] }, 201);
    }

    if (method === "DELETE" && path.startsWith("/financeiro/lancamento/")) {
      if (!hasPermission(authPayload, "financeiro:write")) {
        return jsonErr(res, "Sem permissão para remover lançamentos", 403);
      }
      var idLanc = SANITIZE.uuid(path.split("/")[3]);
      if (!idLanc) return jsonErr(res, "Lançamento inválido");

      // O escopo entra na própria consulta de remoção: sem ele, um id
      // adivinhado apagaria lançamento de outra empresa.
      var alvo = await DB.select("lancamentos_financeiros",
        `id=eq.${idLanc}&${filtroFinanceiro(authPayload)}&select=id`);
      if (!alvo.body || !alvo.body[0]) return jsonErr(res, "Lançamento não encontrado", 404);

      await DB.delete("lancamentos_financeiros", `id=eq.${idLanc}`);
      return jsonOk(res, { ok: true });
    }

    // ════════════════════════════════════════
    // MURAL / COMUNICADOS DA EMPRESA
    // ════════════════════════════════════════
    // A tabela `comunicados` existe desde o começo do projeto e nunca
    // teve uma rota. A tela dizia "em desenvolvimento" enquanto o
    // banco já estava pronto para receber.
    //
    // Não confundir com `comunicados_plataforma`: aquele é a Workap
    // falando com as empresas clientes; este é a empresa falando com
    // os próprios funcionários.
    if (method === "GET" && path === "/comunicados") {
      if (!hasPermission(authPayload, "mural:read")) {
        return jsonErr(res, "Sem permissão para ver o mural", 403);
      }
      var limMural = SANITIZE.int(url.searchParams.get("limit"), 1, 100) || 50;
      var mural = await DB.select("comunicados",
        `empresa_id=eq.${authPayload.empresa_id}&select=*&order=created_at.desc&limit=${limMural}`
      );
      return jsonOk(res, mural.body || []);
    }

    if (method === "POST" && path === "/comunicados") {
      if (!hasPermission(authPayload, "mural:write")) {
        return jsonErr(res, "Sem permissão para publicar no mural", 403);
      }
      var rawMural = await getBody(req);
      var bodyMural = parseBody(rawMural);
      if (!bodyMural) return jsonErr(res, "Dados inválidos");

      var tituloMural = SANITIZE.string(bodyMural.titulo, 120);
      var msgMural    = SANITIZE.string(bodyMural.mensagem, 2000);
      if (!tituloMural) return jsonErr(res, "Escreva um título.");
      if (!msgMural)    return jsonErr(res, "Escreva a mensagem.");

      var catsMural = ["geral", "operacional", "urgente", "financeiro"];
      var catMural = catsMural.includes(bodyMural.categoria) ? bodyMural.categoria : "geral";

      var novoMural = await DB.insert("comunicados", {
        empresa_id:    authPayload.empresa_id,
        autor_id:      authPayload.funcionario_id || null,
        titulo:        tituloMural,
        mensagem:      msgMural,
        categoria:     catMural,
        destinatarios: "todos"
      });

      // Avisa a equipe no celular. Um mural que ninguém abre não
      // comunica nada — é o push que faz a mensagem chegar.
      enviarPush(authPayload.empresa_id, {
        title: tituloMural,
        body:  msgMural.substring(0, 140),
        url:   "worka-app.html"
      }).catch(() => {});

      secLog("comunicado_publicado", { empresa_id: authPayload.empresa_id, categoria: catMural });
      return jsonOk(res, { comunicado: novoMural.body[0] }, 201);
    }

    if (method === "DELETE" && path.startsWith("/comunicados/")) {
      if (!hasPermission(authPayload, "mural:write")) {
        return jsonErr(res, "Sem permissão para remover comunicados", 403);
      }
      var idMural = SANITIZE.uuid(path.split("/")[2]);
      if (!idMural) return jsonErr(res, "Comunicado inválido");

      // A empresa entra na busca: sem isso, um id adivinhado apagaria
      // o comunicado de outra empresa.
      var achadoMural = await DB.select("comunicados",
        `id=eq.${idMural}&empresa_id=eq.${authPayload.empresa_id}&select=id`);
      if (!achadoMural.body || !achadoMural.body[0]) return jsonErr(res, "Comunicado não encontrado", 404);

      await DB.delete("comunicados", `id=eq.${idMural}`);
      return jsonOk(res, { ok: true });
    }

    // ════════════════════════════════════════
    // ESCALA DE TRABALHO
    // ════════════════════════════════════════
    // Uma linha por funcionário por dia da semana (0 = domingo).
    // A tabela `escalas` também já existia sem nenhuma rota.
    if (method === "GET" && path === "/escalas") {
      if (!hasPermission(authPayload, "escala:read")) {
        return jsonErr(res, "Sem permissão para ver a escala", 403);
      }

      var filtroEscala = `empresa_id=eq.${authPayload.empresa_id}`;
      // Funcionário só enxerga a própria escala. Sem esta linha, quem
      // bate ponto veria o horário de todo mundo da empresa.
      if (authPayload.role === "funcionario") {
        if (!authPayload.funcionario_id) return jsonOk(res, []);
        filtroEscala += `&funcionario_id=eq.${authPayload.funcionario_id}`;
      }

      var escalas = await DB.select("escalas", `${filtroEscala}&select=*&order=dia_semana.asc`);
      return jsonOk(res, escalas.body || []);
    }

    if (method === "POST" && path === "/escalas") {
      if (!hasPermission(authPayload, "escala:write")) {
        return jsonErr(res, "Sem permissão para montar a escala", 403);
      }
      var rawEsc = await getBody(req);
      var bodyEsc = parseBody(rawEsc);
      if (!bodyEsc) return jsonErr(res, "Dados inválidos");

      var funcEsc = SANITIZE.uuid(bodyEsc.funcionario_id);
      if (!funcEsc) return jsonErr(res, "Escolha o funcionário.");

      var diaEsc = SANITIZE.int(bodyEsc.dia_semana, 0, 6);
      if (diaEsc === null || diaEsc === undefined) return jsonErr(res, "Dia da semana inválido.");

      var folgaEsc = bodyEsc.folga === true;
      var entradaEsc = null, saidaEsc = null;

      if (!folgaEsc) {
        var horaValida = /^([01]\d|2[0-3]):[0-5]\d$/;
        entradaEsc = String(bodyEsc.horario_entrada || "").trim();
        saidaEsc   = String(bodyEsc.horario_saida || "").trim();
        if (!horaValida.test(entradaEsc) || !horaValida.test(saidaEsc)) {
          return jsonErr(res, "Informe os horários no formato 08:00.");
        }
      }

      // O funcionário precisa ser DESTA empresa. Sem conferir, daria
      // para montar escala para alguém de outra conta mandando o id.
      var donoFunc = await DB.select("funcionarios",
        `id=eq.${funcEsc}&empresa_id=eq.${authPayload.empresa_id}&select=id`);
      if (!donoFunc.body || !donoFunc.body[0]) return jsonErr(res, "Funcionário não encontrado", 404);

      // Um turno por funcionário por dia: gravar de novo substitui, em
      // vez de empilhar duas escalas contraditórias no mesmo dia.
      var jaTemEsc = await DB.select("escalas",
        `empresa_id=eq.${authPayload.empresa_id}&funcionario_id=eq.${funcEsc}&dia_semana=eq.${diaEsc}&select=id`);

      var corpoEsc = {
        empresa_id: authPayload.empresa_id,
        funcionario_id: funcEsc,
        dia_semana: diaEsc,
        horario_entrada: entradaEsc,
        horario_saida: saidaEsc,
        folga: folgaEsc
      };

      var salvoEsc;
      if (jaTemEsc.body && jaTemEsc.body[0]) {
        salvoEsc = await DB.update("escalas", `id=eq.${jaTemEsc.body[0].id}`, corpoEsc);
      } else {
        salvoEsc = await DB.insert("escalas", corpoEsc);
      }

      return jsonOk(res, { escala: (salvoEsc.body || [])[0] || corpoEsc }, 201);
    }

    if (method === "DELETE" && path.startsWith("/escalas/")) {
      if (!hasPermission(authPayload, "escala:write")) {
        return jsonErr(res, "Sem permissão para alterar a escala", 403);
      }
      var idEsc = SANITIZE.uuid(path.split("/")[2]);
      if (!idEsc) return jsonErr(res, "Escala inválida");

      var achadoEsc = await DB.select("escalas",
        `id=eq.${idEsc}&empresa_id=eq.${authPayload.empresa_id}&select=id`);
      if (!achadoEsc.body || !achadoEsc.body[0]) return jsonErr(res, "Escala não encontrada", 404);

      await DB.delete("escalas", `id=eq.${idEsc}`);
      return jsonOk(res, { ok: true });
    }

    // ════════════════════════════════════════
    // CARGOS E PERMISSÕES
    // ════════════════════════════════════════
    // A tela avisava que "criação de cargos customizados ainda não é
    // suportada pelo backend". A tabela `cargos` já existia, com uma
    // coluna booleana por permissão.
    var PERMISSOES_CARGO = [
      "ver_faturamento", "aprovar_funcionarios", "criar_tarefas",
      "editar_visual", "gerenciar_ponto", "acessar_api",
      "gerenciar_validade", "ver_relatorios", "gerenciar_salarios"
    ];

    if (method === "GET" && path === "/cargos") {
      if (!hasPermission(authPayload, "cargos:read")) {
        return jsonErr(res, "Sem permissão para ver cargos", 403);
      }
      var cargos = await DB.select("cargos",
        `empresa_id=eq.${authPayload.empresa_id}&select=*&order=nivel.desc`);
      return jsonOk(res, cargos.body || []);
    }

    if (method === "POST" && path === "/cargos") {
      if (!hasPermission(authPayload, "cargos:write")) {
        return jsonErr(res, "Sem permissão para criar cargos", 403);
      }
      var rawCargo = await getBody(req);
      var bodyCargo = parseBody(rawCargo);
      if (!bodyCargo) return jsonErr(res, "Dados inválidos");

      var nomeCargo = SANITIZE.string(bodyCargo.nome, 60);
      if (!nomeCargo) return jsonErr(res, "Dê um nome ao cargo.");

      var jaTemCargo = await DB.select("cargos",
        `empresa_id=eq.${authPayload.empresa_id}&nome=eq.${encodeURIComponent(nomeCargo)}&select=id`);
      if (jaTemCargo.body && jaTemCargo.body[0]) {
        return jsonErr(res, "Já existe um cargo com esse nome.", 409);
      }

      var corpoCargo = {
        empresa_id: authPayload.empresa_id,
        nome: nomeCargo,
        nivel: SANITIZE.int(bodyCargo.nivel, 1, 10) || 1
      };
      // Só as permissões conhecidas entram, e sempre como booleano:
      // o que vem do navegador nunca vira coluna nova nem valor solto.
      PERMISSOES_CARGO.forEach(function (perm) {
        corpoCargo[perm] = bodyCargo[perm] === true;
      });

      var novoCargo = await DB.insert("cargos", corpoCargo);
      secLog("cargo_criado", { empresa_id: authPayload.empresa_id });
      return jsonOk(res, { cargo: novoCargo.body[0] }, 201);
    }

    if (method === "PUT" && path.startsWith("/cargos/")) {
      if (!hasPermission(authPayload, "cargos:write")) {
        return jsonErr(res, "Sem permissão para alterar cargos", 403);
      }
      var idCargo = SANITIZE.uuid(path.split("/")[2]);
      if (!idCargo) return jsonErr(res, "Cargo inválido");

      var rawUp = await getBody(req);
      var bodyUp = parseBody(rawUp);
      if (!bodyUp) return jsonErr(res, "Dados inválidos");

      var achadoCargo = await DB.select("cargos",
        `id=eq.${idCargo}&empresa_id=eq.${authPayload.empresa_id}&select=id`);
      if (!achadoCargo.body || !achadoCargo.body[0]) return jsonErr(res, "Cargo não encontrado", 404);

      var updCargo = {};
      if (bodyUp.nome) updCargo.nome = SANITIZE.string(bodyUp.nome, 60);
      if (bodyUp.nivel !== undefined) updCargo.nivel = SANITIZE.int(bodyUp.nivel, 1, 10) || 1;
      PERMISSOES_CARGO.forEach(function (perm) {
        if (bodyUp[perm] !== undefined) updCargo[perm] = bodyUp[perm] === true;
      });

      var atualizado = await DB.update("cargos", `id=eq.${idCargo}`, updCargo);
      return jsonOk(res, { cargo: (atualizado.body || [])[0] });
    }

    if (method === "DELETE" && path.startsWith("/cargos/")) {
      if (!hasPermission(authPayload, "cargos:write")) {
        return jsonErr(res, "Sem permissão para remover cargos", 403);
      }
      var idDel = SANITIZE.uuid(path.split("/")[2]);
      if (!idDel) return jsonErr(res, "Cargo inválido");

      var achadoDel = await DB.select("cargos",
        `id=eq.${idDel}&empresa_id=eq.${authPayload.empresa_id}&select=id`);
      if (!achadoDel.body || !achadoDel.body[0]) return jsonErr(res, "Cargo não encontrado", 404);

      // Cargo em uso não é apagado: apagar deixaria funcionários
      // apontando para um cargo que não existe mais.
      var emUso = await DB.select("funcionarios",
        `cargo_id=eq.${idDel}&select=id&limit=1`).catch(() => ({ body: [] }));
      if (emUso.body && emUso.body[0]) {
        return jsonErr(res, "Há funcionários com este cargo. Troque o cargo deles antes de remover.", 409);
      }

      await DB.delete("cargos", `id=eq.${idDel}`);
      return jsonOk(res, { ok: true });
    }

    // ════════════════════════════════════════
    // CONFIGURAÇÃO DE FALTAS
    // ════════════════════════════════════════
    // Estava só no localStorage do navegador: o dono configurava o
    // desconto por falta no computador e o valor não existia no
    // celular — nem para o sistema, na hora de calcular. A tabela
    // config_faltas já existia e nunca tinha sido usada.
    if (method === "GET" && path === "/config-faltas") {
      if (!hasPermission(authPayload, "ausencias:read")) {
        return jsonErr(res, "Sem permissão", 403);
      }
      var cfgFalta = await DB.select("config_faltas",
        `empresa_id=eq.${authPayload.empresa_id}&select=*&limit=1`).catch(() => ({ body: [] }));

      var linhaFalta = (cfgFalta.body || [])[0] || {
        tipo_desconto: "fixo", valor_falta: 100, criar_tarefa_automatica: true
      };
      return jsonOk(res, linhaFalta);
    }

    if (method === "PUT" && path === "/config-faltas") {
      if (!hasPermission(authPayload, "ausencias:write")) {
        return jsonErr(res, "Sem permissão para alterar a configuração", 403);
      }
      var rawFalta = await getBody(req);
      var bodyFalta = parseBody(rawFalta);
      if (!bodyFalta) return jsonErr(res, "Dados inválidos");

      var tiposFalta = ["fixo", "diaria", "sem_desconto"];
      var tipoFalta = tiposFalta.includes(bodyFalta.tipo_desconto) ? bodyFalta.tipo_desconto : "fixo";

      var valorFalta = parseFloat(bodyFalta.valor_falta);
      if (isNaN(valorFalta) || valorFalta < 0 || valorFalta > 99999) valorFalta = 0;

      var corpoFalta = {
        empresa_id: authPayload.empresa_id,
        tipo_desconto: tipoFalta,
        valor_falta: valorFalta,
        criar_tarefa_automatica: bodyFalta.criar_tarefa_automatica === true,
        updated_at: new Date().toISOString()
      };

      // empresa_id é a chave primária desta tabela: existe no máximo
      // uma linha por empresa.
      var temFalta = await DB.select("config_faltas",
        `empresa_id=eq.${authPayload.empresa_id}&select=empresa_id&limit=1`).catch(() => ({ body: [] }));

      if (temFalta.body && temFalta.body[0]) {
        await DB.update("config_faltas", `empresa_id=eq.${authPayload.empresa_id}`, corpoFalta);
      } else {
        await DB.insert("config_faltas", corpoFalta);
      }
      return jsonOk(res, { ok: true, config: corpoFalta });
    }

    // ════════════════════════════════════════
    // RELATÓRIOS
    // ════════════════════════════════════════
    // A tela dizia "em desenvolvimento". Os dados sempre estiveram
    // lá — ponto, tarefas, ausências e folha —, faltava juntar.
    if (method === "GET" && path === "/relatorios") {
      if (!hasPermission(authPayload, "ponto:read")) {
        return jsonErr(res, "Sem permissão para ver relatórios", 403);
      }

      // Período: até 180 dias para trás. Sem teto, um pedido de "todo
      // o histórico" varreria a tabela inteira a cada abertura da tela.
      var dias = SANITIZE.int(url.searchParams.get("dias"), 1, 180) || 30;
      var desde = new Date(Date.now() - dias * 24 * 60 * 60 * 1000).toISOString();
      var empRel = authPayload.empresa_id;

      var [pontos, tarefasRel, ausenciasRel, funcsRel] = await Promise.all([
        DB.select("registros_ponto", `empresa_id=eq.${empRel}&created_at=gte.${desde}&select=tipo,funcionario_id,latitude,horario,created_at`).catch(() => ({ body: [] })),
        DB.select("tarefas",          `empresa_id=eq.${empRel}&created_at=gte.${desde}&select=status,responsavel_id,prazo,concluida_em`).catch(() => ({ body: [] })),
        DB.select("ausencias",        `empresa_id=eq.${empRel}&data=gte.${desde.substring(0,10)}&select=tipo,funcionario_id,desconto`).catch(() => ({ body: [] })),
        DB.select("funcionarios",     `empresa_id=eq.${empRel}&select=id,nome,status,salario_base`).catch(() => ({ body: [] }))
      ]);

      var listaPontos = pontos.body || [];
      var listaTarefas = tarefasRel.body || [];
      var listaAusencias = ausenciasRel.body || [];
      var listaFuncs = funcsRel.body || [];

      var entradas = listaPontos.filter(function (p) { return p.tipo === "entrada"; });
      var comGps = entradas.filter(function (p) { return p.latitude !== null && p.latitude !== undefined; }).length;

      // Por funcionário: quantos dias trabalhou, tarefas concluídas e
      // faltas. É a tabela que o dono realmente usa na conversa de fim
      // de mês, então vem pronta em vez de exigir cruzamento manual.
      var porFuncionario = listaFuncs.filter(function (f) { return f.status === "ativo"; }).map(function (f) {
        var diasTrabalhados = new Set(
          entradas.filter(function (p) { return p.funcionario_id === f.id; })
                  .map(function (p) { return (p.horario || p.created_at || "").substring(0, 10); })
        ).size;

        var minhasTarefas = listaTarefas.filter(function (t) { return t.responsavel_id === f.id; });
        var minhasAusencias = listaAusencias.filter(function (a) { return a.funcionario_id === f.id; });

        return {
          id: f.id,
          nome: f.nome,
          dias_trabalhados: diasTrabalhados,
          tarefas_total: minhasTarefas.length,
          tarefas_concluidas: minhasTarefas.filter(function (t) { return t.status === "concluida"; }).length,
          faltas: minhasAusencias.length,
          desconto_faltas: Math.round(minhasAusencias.reduce(function (s, a) { return s + (parseFloat(a.desconto) || 0); }, 0) * 100) / 100
        };
      }).sort(function (a, b) { return b.dias_trabalhados - a.dias_trabalhados; });

      var concluidas = listaTarefas.filter(function (t) { return t.status === "concluida"; }).length;
      var folhaMes = listaFuncs.filter(function (f) { return f.status === "ativo"; })
                               .reduce(function (s, f) { return s + (parseFloat(f.salario_base) || 0); }, 0);

      return jsonOk(res, {
        periodo_dias: dias,
        ponto: {
          registros:    listaPontos.length,
          entradas:     entradas.length,
          com_gps:      comGps,
          // Percentual de pontos com coordenada: é o número que mostra
          // se a equipe está batendo ponto com a localização ligada.
          percentual_gps: entradas.length ? Math.round((comGps / entradas.length) * 100) : 0
        },
        tarefas: {
          total:        listaTarefas.length,
          concluidas:   concluidas,
          pendentes:    listaTarefas.filter(function (t) { return t.status === "pendente"; }).length,
          atrasadas:    listaTarefas.filter(function (t) { return t.status === "atrasada"; }).length,
          percentual_conclusao: listaTarefas.length ? Math.round((concluidas / listaTarefas.length) * 100) : 0
        },
        ausencias: {
          total:        listaAusencias.length,
          desconto_total: Math.round(listaAusencias.reduce(function (s, a) { return s + (parseFloat(a.desconto) || 0); }, 0) * 100) / 100
        },
        equipe: {
          ativos: listaFuncs.filter(function (f) { return f.status === "ativo"; }).length,
          folha_mensal: Math.round(folhaMes * 100) / 100
        },
        por_funcionario: porFuncionario
      });
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
