const http = require("http");
const https = require("https");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const PIX_URL = process.env.DUTTYFY_PIX_URL_ENCRYPTED || "";
const GMAIL_USER = "workappoficial@gmail.com";
const GMAIL_PASS = "yzvjhzuxmfetviow";
const SUPABASE_URL = process.env.SUPABASE_URL || "";
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY || "";
const ENCRYPT_SECRET = process.env.ENCRYPT_SECRET || "worka-default-secret";

let nodemailer;
try { nodemailer = require("nodemailer"); } catch(e) {}
const transporter = nodemailer ? nodemailer.createTransport({ service: "gmail", auth: { user: GMAIL_USER, pass: GMAIL_PASS } }) : null;
const codigosMemoria = {};

function supabaseRequest(method, table, options) {
  options = options || {};
  return new Promise((resolve, reject) => {
    if (!SUPABASE_URL || !SUPABASE_KEY) return reject(new Error("Supabase não configurado"));
    var path = "/rest/v1/" + table;
    if (options.query) path += "?" + options.query;
    var bodyStr = options.body ? JSON.stringify(options.body) : null;
    var headers = { "apikey": SUPABASE_KEY, "Authorization": "Bearer " + SUPABASE_KEY, "Content-Type": "application/json", "Prefer": options.prefer || "return=representation" };
    if (bodyStr) headers["Content-Length"] = Buffer.byteLength(bodyStr);
    var u = new URL(SUPABASE_URL);
    var req = https.request({ hostname: u.hostname, path: path, method: method, headers: headers }, function(res) {
      var raw = "";
      res.on("data", c => raw += c);
      res.on("end", () => { try { resolve({ status: res.statusCode, body: JSON.parse(raw || "[]") }); } catch(e) { resolve({ status: res.statusCode, body: raw }); } });
    });
    req.on("error", reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

const DB = {
  select: (t, q) => supabaseRequest("GET", t, { query: q }),
  insert: (t, d) => supabaseRequest("POST", t, { body: d }),
  update: (t, id, d) => supabaseRequest("PATCH", t, { query: "id=eq." + id, body: d }),
  delete: (t, id) => supabaseRequest("DELETE", t, { query: "id=eq." + id })
};

function encrypt(text) {
  var iv = crypto.randomBytes(16);
  var key = crypto.createHash("sha256").update(ENCRYPT_SECRET).digest();
  var cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  var enc = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  var tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64");
}

function decrypt(b64) {
  var data = Buffer.from(b64, "base64");
  var iv = data.slice(0, 16); var tag = data.slice(16, 32); var enc = data.slice(32);
  var key = crypto.createHash("sha256").update(ENCRYPT_SECRET).digest();
  var d = crypto.createDecipheriv("aes-256-gcm", key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(enc), d.final()]).toString("utf8");
}

function hashSenha(s) { return crypto.createHash("sha256").update(s + ENCRYPT_SECRET).digest("hex"); }
function gerarCodigo() { return Math.floor(100000 + Math.random() * 900000).toString(); }
function gerarTeamId() { return "#WK-" + Math.floor(1000 + Math.random() * 9000); }

function httpsPost(url, body, headers) {
  return new Promise((resolve, reject) => {
    var u = new URL(url); var data = JSON.stringify(body);
    var opts = { hostname: u.hostname, path: u.pathname + u.search, method: "POST", headers: Object.assign({ "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) }, headers || {}) };
    var req = https.request(opts, res => { var raw = ""; res.on("data", c => raw += c); res.on("end", () => { try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); } catch(e) { resolve({ status: res.statusCode, body: raw }); } }); });
    req.on("error", reject); req.write(data); req.end();
  });
}

function httpsGet(url, headers) {
  return new Promise((resolve, reject) => {
    var u = new URL(url);
    var req = https.request({ hostname: u.hostname, path: u.pathname + u.search, method: "GET", headers: headers || {} }, res => { var raw = ""; res.on("data", c => raw += c); res.on("end", () => { try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); } catch(e) { resolve({ status: res.statusCode, body: raw }); } }); });
    req.on("error", reject); req.end();
  });
}

function getBody(req) {
  return new Promise((resolve, reject) => { var raw = ""; req.on("data", c => raw += c); req.on("end", () => resolve(raw)); req.on("error", reject); });
}

function enviarEmail(para, assunto, html) {
  return new Promise((resolve, reject) => {
    if (!transporter) return reject(new Error("nodemailer nao instalado"));
    transporter.sendMail({ from: '"Worka" <' + GMAIL_USER + '>', to: para, subject: assunto, html: html }, function(err, info) {
      if (err) return reject(err);
      resolve(info);
    });
  });
}

const server = http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Content-Type", "application/json");
  if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }

  var urlObj = new URL(req.url, "http://localhost:" + PORT);
  var path = urlObj.pathname;

  try {

    if (path === "/" || path === "/health") {
      res.writeHead(200);
      return res.end(JSON.stringify({ status: "ok", service: "worka-backend", supabase: !!SUPABASE_URL, gmail: !!GMAIL_USER }));
    }

    if (req.method === "POST" && path === "/empresas") {
      var data = JSON.parse(await getBody(req));
      if (!data.nome || !data.email || !data.senha) { res.writeHead(400); return res.end(JSON.stringify({ error: "nome, email e senha obrigatorios" })); }
      var result = await DB.insert("empresas", { nome: data.nome, email: data.email.toLowerCase(), senha_hash: hashSenha(data.senha), ramo: data.ramo || null, team_id: gerarTeamId() });
      res.writeHead(201); return res.end(JSON.stringify({ empresa: result.body[0] }));
    }

    if (req.method === "POST" && path === "/login/empresa") {
      var data = JSON.parse(await getBody(req));
      var result = await DB.select("empresas", "email=eq." + encodeURIComponent(data.email.toLowerCase()) + "&senha_hash=eq." + hashSenha(data.senha));
      if (!result.body.length) { res.writeHead(401); return res.end(JSON.stringify({ error: "Credenciais invalidas" })); }
      res.writeHead(200); return res.end(JSON.stringify({ empresa: result.body[0] }));
    }

    if (req.method === "POST" && path === "/login/funcionario") {
      var data = JSON.parse(await getBody(req));
      var emp = await DB.select("empresas", "team_id=eq." + encodeURIComponent(data.teamId));
      if (!emp.body.length) { res.writeHead(404); return res.end(JSON.stringify({ error: "ID de equipe nao encontrado" })); }
      var func = await DB.select("funcionarios", "empresa_id=eq." + emp.body[0].id + "&email=eq." + encodeURIComponent(data.email.toLowerCase()) + "&senha_hash=eq." + hashSenha(data.senha));
      if (!func.body.length) { res.writeHead(401); return res.end(JSON.stringify({ error: "Credenciais invalidas" })); }
      res.writeHead(200); return res.end(JSON.stringify({ funcionario: func.body[0], empresa: emp.body[0] }));
    }

    if (req.method === "POST" && path === "/funcionarios") {
      var data = JSON.parse(await getBody(req));
      var emp = await DB.select("empresas", "team_id=eq." + encodeURIComponent(data.teamId));
      if (!emp.body.length) { res.writeHead(404); return res.end(JSON.stringify({ error: "ID invalido" })); }
      var result = await DB.insert("funcionarios", { empresa_id: emp.body[0].id, nome: data.nome, email: data.email.toLowerCase(), senha_hash: hashSenha(data.senha), telefone: data.telefone || null, status: "pendente" });
      res.writeHead(201); return res.end(JSON.stringify({ funcionario: result.body[0] }));
    }

    if (req.method === "GET" && path === "/funcionarios") {
      var result = await DB.select("funcionarios", "empresa_id=eq." + urlObj.searchParams.get("empresa_id") + "&order=created_at.desc");
      res.writeHead(200); return res.end(JSON.stringify(result.body));
    }

    if (req.method === "PUT" && path.match(/^\/funcionarios\/[\w-]+\/status$/)) {
      var data = JSON.parse(await getBody(req));
      await DB.update("funcionarios", path.split("/")[2], { status: data.status });
      res.writeHead(200); return res.end(JSON.stringify({ ok: true }));
    }

    if (req.method === "DELETE" && path.match(/^\/funcionarios\/[\w-]+$/)) {
      await DB.delete("funcionarios", path.split("/")[2]);
      res.writeHead(200); return res.end(JSON.stringify({ ok: true }));
    }

    if (req.method === "POST" && path === "/ponto") {
      var data = JSON.parse(await getBody(req));
      var result = await DB.insert("registros_ponto", { funcionario_id: data.funcionario_id, empresa_id: data.empresa_id, tipo: data.tipo, latitude: data.latitude, longitude: data.longitude });
      res.writeHead(201); return res.end(JSON.stringify({ registro: result.body[0] }));
    }

    if (req.method === "GET" && path === "/ponto") {
      var hoje = new Date().toISOString().split("T")[0];
      var result = await DB.select("registros_ponto", "empresa_id=eq." + urlObj.searchParams.get("empresa_id") + "&horario=gte." + hoje + "&order=horario.desc");
      res.writeHead(200); return res.end(JSON.stringify(result.body));
    }

    if (req.method === "POST" && path === "/tarefas") {
      var data = JSON.parse(await getBody(req));
      var result = await DB.insert("tarefas", data);
      res.writeHead(201); return res.end(JSON.stringify({ tarefa: result.body[0] }));
    }

    if (req.method === "GET" && path === "/tarefas") {
      var result = await DB.select("tarefas", "empresa_id=eq." + urlObj.searchParams.get("empresa_id") + "&order=created_at.desc");
      res.writeHead(200); return res.end(JSON.stringify(result.body));
    }

    if (req.method === "PUT" && path.match(/^\/tarefas\/[\w-]+$/)) {
      var data = JSON.parse(await getBody(req));
      var result = await DB.update("tarefas", path.split("/")[2], data);
      res.writeHead(200); return res.end(JSON.stringify({ tarefa: result.body[0] }));
    }

    if (req.method === "POST" && path === "/validade") {
      var data = JSON.parse(await getBody(req));
      var result = await DB.insert("produtos_validade", data);
      res.writeHead(201); return res.end(JSON.stringify({ produto: result.body[0] }));
    }

    if (req.method === "GET" && path === "/validade") {
      var result = await DB.select("produtos_validade", "empresa_id=eq." + urlObj.searchParams.get("empresa_id") + "&order=data_vencimento.asc");
      res.writeHead(200); return res.end(JSON.stringify(result.body));
    }

    if (req.method === "POST" && path === "/salarios/ajuste") {
      var data = JSON.parse(await getBody(req));
      await DB.update("funcionarios", data.funcionario_id, { salario_base: data.salario_novo });
      await DB.insert("historico_salarios", { funcionario_id: data.funcionario_id, salario_anterior: data.salario_anterior, salario_novo: data.salario_novo, tipo: data.salario_novo > data.salario_anterior ? "aumento" : "reducao", motivo: data.motivo || null });
      res.writeHead(201); return res.end(JSON.stringify({ ok: true }));
    }

    if (req.method === "POST" && path === "/ausencias") {
      var data = JSON.parse(await getBody(req));
      var result = await DB.insert("ausencias", data);
      res.writeHead(201); return res.end(JSON.stringify({ ausencia: result.body[0] }));
    }

    if (req.method === "POST" && path === "/integracoes") {
      var data = JSON.parse(await getBody(req));
      var result = await DB.insert("integracoes", { empresa_id: data.empresa_id, nome: data.nome, tipo_sistema: data.tipo_sistema, base_url: data.base_url, auth_type: data.auth_type, credenciais_encrypted: data.token ? encrypt(data.token) : null, header_name: data.header_name || null });
      res.writeHead(201); return res.end(JSON.stringify({ integracao: result.body[0] }));
    }

    if (req.method === "GET" && path === "/integracoes") {
      var result = await DB.select("integracoes", "empresa_id=eq." + urlObj.searchParams.get("empresa_id"));
      var safe = result.body.map(i => { var c = Object.assign({}, i); delete c.credenciais_encrypted; return c; });
      res.writeHead(200); return res.end(JSON.stringify(safe));
    }

    if (req.method === "POST" && path === "/integracoes/proxy") {
      var data = JSON.parse(await getBody(req));
      var intRes = await DB.select("integracoes", "id=eq." + data.integracao_id);
      if (!intRes.body.length) { res.writeHead(404); return res.end(JSON.stringify({ error: "Integracao nao encontrada" })); }
      var integ = intRes.body[0];
      var headers = { "Content-Type": "application/json" };
      var token = integ.credenciais_encrypted ? decrypt(integ.credenciais_encrypted) : "";
      if (integ.auth_type === "bearer" || integ.auth_type === "jwt") headers["Authorization"] = "Bearer " + token;
      else if (integ.auth_type === "apikey") headers["x-api-key"] = token;
      else if (integ.auth_type === "basic") headers["Authorization"] = "Basic " + Buffer.from(token).toString("base64");
      else if (integ.auth_type === "custom" && integ.header_name) headers[integ.header_name] = token;
      var targetUrl = data.endpoint.startsWith("http") ? data.endpoint : integ.base_url + data.endpoint;
      var t0 = Date.now();
      try {
        var result = data.metodo === "GET" ? await httpsGet(targetUrl, headers) : await httpsPost(targetUrl, data.body || {}, headers);
        await DB.insert("integracao_logs", { empresa_id: integ.empresa_id, integracao_id: integ.id, metodo: data.metodo, endpoint: data.endpoint, status_code: result.status, duracao_ms: Date.now() - t0, mensagem: result.status < 400 ? "OK" : "Erro" }).catch(() => {});
        res.writeHead(result.status); return res.end(JSON.stringify(result.body));
      } catch(e) {
        res.writeHead(502); return res.end(JSON.stringify({ error: e.message }));
      }
    }

    if (req.method === "POST" && path === "/enviar-codigo") {
      var data = JSON.parse(await getBody(req));
      if (!data.email) { res.writeHead(400); return res.end(JSON.stringify({ error: "Email obrigatorio" })); }
      var codigo = gerarCodigo();
      var expiraEm = new Date(Date.now() + 10*60*1000).toISOString();
      if (SUPABASE_URL) {
        await DB.insert("codigos_verificacao", { email: data.email, codigo: codigo, expira_em: expiraEm }).catch(() => {});
      } else {
        codigosMemoria[data.email] = { codigo: codigo, expira: Date.now() + 10*60*1000 };
      }
      try {
        await enviarEmail(data.email, "Seu codigo Worka", '<div style="font-family:Arial;padding:32px;background:#f7f8f7;border-radius:16px;max-width:480px"><h2 style="color:#16622f">Ola, ' + (data.name||"Cliente") + '!</h2><p>Seu codigo de verificacao:</p><div style="background:#0a2e1a;border-radius:12px;padding:24px;text-align:center;margin:16px 0"><span style="font-size:2.5rem;font-weight:800;color:#3dd669;letter-spacing:8px">' + codigo + '</span></div><p style="color:#6b7068;font-size:.85rem">Expira em 10 minutos.</p></div>');
        res.writeHead(200); return res.end(JSON.stringify({ ok: true }));
      } catch(e) {
        console.error("Erro email:", e.message);
        res.writeHead(500); return res.end(JSON.stringify({ error: "Erro email: " + e.message }));
      }
    }

    if (req.method === "POST" && path === "/verificar-codigo") {
      var data = JSON.parse(await getBody(req));
      if (SUPABASE_URL) {
        var result = await DB.select("codigos_verificacao", "email=eq." + encodeURIComponent(data.email) + "&codigo=eq." + data.codigo + "&usado=eq.false&order=created_at.desc&limit=1");
        if (!result.body.length) { res.writeHead(400); return res.end(JSON.stringify({ error: "Codigo invalido" })); }
        if (new Date(result.body[0].expira_em) < new Date()) { res.writeHead(400); return res.end(JSON.stringify({ error: "Codigo expirado" })); }
        await DB.update("codigos_verificacao", result.body[0].id, { usado: true });
        res.writeHead(200); return res.end(JSON.stringify({ ok: true }));
      } else {
        var entry = codigosMemoria[data.email];
        if (!entry || entry.codigo !== data.codigo) { res.writeHead(400); return res.end(JSON.stringify({ error: "Codigo invalido" })); }
        if (Date.now() > entry.expira) { res.writeHead(400); return res.end(JSON.stringify({ error: "Codigo expirado" })); }
        delete codigosMemoria[data.email];
        res.writeHead(200); return res.end(JSON.stringify({ ok: true }));
      }
    }

    if (req.method === "POST" && path === "/pix") {
      var data = JSON.parse(await getBody(req));
      var payload = { amount: 2490, customer: { name: data.name, document: (data.document||"").replace(/\D/g,""), email: data.email, phone: (data.phone||"").replace(/\D/g,"") }, item: { title: "Plano Completo Worka", price: 2490, quantity: 1 }, paymentMethod: "PIX", utm: data.utm || "" };
      var result = await httpsPost(PIX_URL, payload, {});
      if (result.status >= 400) { res.writeHead(result.status); return res.end(JSON.stringify({ error: JSON.stringify(result.body) })); }
      if (SUPABASE_URL) await DB.insert("pagamentos_pix", { transaction_id: result.body.transactionId, amount: 2490, status: "PENDING", pix_code: result.body.pixCode, customer_name: data.name, customer_email: data.email, utm: data.utm || "" }).catch(() => {});
      res.writeHead(200); return res.end(JSON.stringify({ pixCode: result.body.pixCode, transactionId: result.body.transactionId, status: result.body.status }));
    }

    if (req.method === "GET" && path === "/pix") {
      var transactionId = urlObj.searchParams.get("transactionId");
      if (!transactionId) { res.writeHead(400); return res.end(JSON.stringify({ error: "transactionId obrigatorio" })); }
      var result = await httpsGet(PIX_URL + "?transactionId=" + encodeURIComponent(transactionId), {});
      if (result.body.status === "COMPLETED" && SUPABASE_URL) {
        var existing = await DB.select("pagamentos_pix", "transaction_id=eq." + transactionId);
        if (existing.body.length && existing.body[0].status !== "COMPLETED") await DB.update("pagamentos_pix", existing.body[0].id, { status: "COMPLETED", paid_at: new Date().toISOString() }).catch(() => {});
      }
      res.writeHead(result.status); return res.end(JSON.stringify(result.body));
    }

    res.writeHead(404); res.end(JSON.stringify({ error: "Rota nao encontrada" }));

  } catch(e) {
    console.error("Erro:", e.message);
    res.writeHead(500); res.end(JSON.stringify({ error: e.message }));
  }
});

server.listen(PORT, () => console.log("Worka backend rodando na porta " + PORT));
