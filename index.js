const http = require("http");
const https = require("https");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const PIX_URL = process.env.DUTTYFY_PIX_URL_ENCRYPTED || "";
const RESEND_KEY = "re_65QfAe5K_NEpzzwWYjSy9ei9tmeSuLPzs";
const SUPABASE_URL = "https://veqwewppgcyjrmtwnzai.supabase.co";
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY || "";
const ENCRYPT_SECRET = process.env.ENCRYPT_SECRET || "worka2026SecretKey!";
const codigosMemoria = {};

function supabaseRequest(method, table, options) {
  options = options || {};
  return new Promise((resolve, reject) => {
    var path = "/rest/v1/" + table;
    if (options.query) path += "?" + options.query;
    var bodyStr = options.body ? JSON.stringify(options.body) : null;
    var headers = { "apikey": SUPABASE_KEY, "Authorization": "Bearer " + SUPABASE_KEY, "Content-Type": "application/json", "Prefer": options.prefer || "return=representation" };
    if (bodyStr) headers["Content-Length"] = Buffer.byteLength(bodyStr);
    var req = https.request({ hostname: "veqwewppgcyjrmtwnzai.supabase.co", path: path, method: method, headers: headers }, function(res) {
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
    var data = JSON.stringify({ from: "Worka <onboarding@resend.dev>", to: [para], subject: assunto, html: html });
    var opts = { hostname: "api.resend.com", path: "/emails", method: "POST", headers: { "Authorization": "Bearer " + RESEND_KEY, "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) } };
    var req = https.request(opts, function(res) {
      var raw = "";
      res.on("data", c => raw += c);
      res.on("end", () => {
        if (res.statusCode >= 400) return reject(new Error("Resend erro " + res.statusCode + ": " + raw));
        resolve(JSON.parse(raw));
      });
    });
    req.on("error", reject);
    req.write(data);
    req.end();
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
      return res.end(JSON.stringify({ status: "ok", service: "worka-backend", supabase: !!SUPABASE_URL, resend: !!RESEND_KEY }));
    }

    if (req.method === "POST" && path === "/empresas") {
      var data = JSON.parse(await getBody(req));
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
      if (!emp.body.length) { res.writeHead(404); return res.end(JSON.stringify({ error: "ID nao encontrado" })); }
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

    if (req.method === "DELETE" && path.match(/^\/funcionarios\/[\w-]+$/)) {
      await DB.delete("funcionarios", path.split("/")[2]);
      res.writeHead(200); return res.end(JSON.stringify({ ok: true }));
    }

    if (req.method === "POST" && path === "/ponto") {
      var data = JSON.parse(await getBody(req));
      var result = await DB.insert("registros_ponto", { funcionario_id: data.funcionario_id, empresa_id: data.empresa_id, tipo: data.tipo, latitude: data.latitude, longitude: data.longitude });
      res.writeHead(201); return res.end(JSON.stringify({ registro: result.body[0] }));
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

    if (req.method === "POST" && path === "/validade") {
      var data = JSON.parse(await getBody(req));
      var result = await DB.insert("produtos_validade", data);
      res.writeHead(201); return res.end(JSON.stringify({ produto: result.body[0] }));
    }

    if (req.method === "POST" && path === "/salarios/ajuste") {
      var data = JSON.parse(await getBody(req));
      await DB.update("funcionarios", data.funcionario_id, { salario_base: data.salario_novo });
      res.writeHead(201); return res.end(JSON.stringify({ ok: true }));
    }

    if (req.method === "POST" && path === "/ausencias") {
      var data = JSON.parse(await getBody(req));
      var result = await DB.insert("ausencias", data);
      res.writeHead(201); return res.end(JSON.stringify({ ausencia: result.body[0] }));
    }

    if (req.method === "POST" && path === "/enviar-codigo") {
      var data = JSON.parse(await getBody(req));
      if (!data.email) { res.writeHead(400); return res.end(JSON.stringify({ error: "Email obrigatorio" })); }
      var codigo = gerarCodigo();
      codigosMemoria[data.email] = { codigo: codigo, expira: Date.now() + 10*60*1000 };
      console.log("Codigo gerado:", codigo, "para:", data.email);
      try {
        await enviarEmail(data.email, "Seu codigo Worka", '<div style="font-family:Arial;padding:32px;background:#f7f8f7;border-radius:16px;max-width:480px;margin:0 auto"><h2 style="color:#16622f">Ola, ' + (data.name||"Cliente") + '!</h2><p>Seu codigo:</p><div style="background:#0a2e1a;border-radius:12px;padding:24px;text-align:center"><span style="font-size:2.5rem;font-weight:800;color:#3dd669;letter-spacing:10px">' + codigo + '</span></div><p style="color:#6b7068;font-size:.85rem">Expira em 10 minutos.</p></div>');
        res.writeHead(200); return res.end(JSON.stringify({ ok: true }));
      } catch(e) {
        console.error("Erro email:", e.message);
        res.writeHead(500); return res.end(JSON.stringify({ error: e.message }));
      }
    }

    if (req.method === "POST" && path === "/verificar-codigo") {
      var data = JSON.parse(await getBody(req));
      var entry = codigosMemoria[data.email];
      if (!entry || entry.codigo !== data.codigo) { res.writeHead(400); return res.end(JSON.stringify({ error: "Codigo invalido" })); }
      if (Date.now() > entry.expira) { delete codigosMemoria[data.email]; res.writeHead(400); return res.end(JSON.stringify({ error: "Codigo expirado" })); }
      delete codigosMemoria[data.email];
      res.writeHead(200); return res.end(JSON.stringify({ ok: true }));
    }

    if (req.method === "POST" && path === "/pix") {
      var data = JSON.parse(await getBody(req));
      var payload = { amount: 2490, customer: { name: data.name, document: (data.document||"").replace(/\D/g,""), email: data.email, phone: (data.phone||"").replace(/\D/g,"") }, item: { title: "Plano Completo Worka", price: 2490, quantity: 1 }, paymentMethod: "PIX", utm: data.utm || "" };
      var result = await httpsPost(PIX_URL, payload, {});
      if (result.status >= 400) { res.writeHead(result.status); return res.end(JSON.stringify({ error: JSON.stringify(result.body) })); }
      res.writeHead(200); return res.end(JSON.stringify({ pixCode: result.body.pixCode, transactionId: result.body.transactionId, status: result.body.status }));
    }

    if (req.method === "GET" && path === "/pix") {
      var transactionId = urlObj.searchParams.get("transactionId");
      var result = await httpsGet(PIX_URL + "?transactionId=" + encodeURIComponent(transactionId), {});
      res.writeHead(result.status); return res.end(JSON.stringify(result.body));
    }

    res.writeHead(404); res.end(JSON.stringify({ error: "Rota nao encontrada" }));

  } catch(e) {
    console.error("Erro:", e.message);
    res.writeHead(500); res.end(JSON.stringify({ error: e.message }));
  }
});

server.listen(PORT, () => console.log("Worka backend rodando na porta " + PORT));
