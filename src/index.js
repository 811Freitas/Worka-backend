const http = require("http");
const https = require("https");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const PIX_URL = process.env.DUTTYFY_PIX_URL_ENCRYPTED || "";
const RESEND_KEY = "re_7dnBFbNw_GSfyyE5Wz6wruA52hXvs7vTS";
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
      var func = await DB.select("funcionarios", "empresa_id=eq." + emp.body[0].id +
