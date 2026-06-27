const http = require("http");
const https = require("https");

const PIX_URL = process.env.DUTTYFY_PIX_URL_ENCRYPTED || "";
const PORT = process.env.PORT || 3000;

function httpsPost(body) {
  return new Promise(function(resolve, reject) {
    const u = new URL(PIX_URL);
    const data = JSON.stringify(body);
    const opts = {
      hostname: u.hostname,
      path: u.pathname,
      method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) }
    };
    const req = https.request(opts, function(res) {
      let raw = "";
      res.on("data", function(c) { raw += c; });
      res.on("end", function() {
        try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); }
        catch(e) { resolve({ status: res.statusCode, body: raw }); }
      });
    });
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

function httpsGet(transactionId) {
  return new Promise(function(resolve, reject) {
    const u = new URL(PIX_URL);
    const opts = { hostname: u.hostname, path: u.pathname + "?transactionId=" + encodeURIComponent(transactionId), method: "GET" };
    const req = https.request(opts, function(res) {
      let raw = "";
      res.on("data", function(c) { raw += c; });
      res.on("end", function() {
        try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); }
        catch(e) { resolve({ status: res.statusCode, body: raw }); }
      });
    });
    req.on("error", reject);
    req.end();
  });
}

function getBody(req) {
  return new Promise(function(resolve, reject) {
    let raw = "";
    req.on("data", function(c) { raw += c; });
    req.on("end", function() { resolve(raw); });
    req.on("error", reject);
  });
}

const server = http.createServer(function(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Content-Type", "application/json");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    return res.end();
  }

  const urlObj = new URL(req.url, "http://localhost:" + PORT);

  if (req.method === "GET" && urlObj.pathname === "/pix") {
    const tid = urlObj.searchParams.get("transactionId");
    if (!tid) { res.writeHead(400); return res.end(JSON.stringify({ error: "transactionId obrigatorio." })); }
    httpsGet(tid).then(function(r) {
      res.writeHead(r.status);
      res.end(JSON.stringify(r.body));
    }).catch(function(e) { res.writeHead(502); res.end(JSON.stringify({ error: e.message })); });
    return;
  }

  if (req.method === "POST" && urlObj.pathname === "/pix") {
    getBody(req).then(function(raw) {
      console.log("Raw body recebido:", raw);
      let data;
      try { data = JSON.parse(raw); }
      catch(e) { res.writeHead(400); return res.end(JSON.stringify({ error: "JSON invalido: " + raw })); }

      console.log("Dados parseados:", JSON.stringify(data));

      var name = data.name || data.nome || "";
      var document = data.document || data.documento || "";
      var email = data.email || "";
      var phone = data.phone || data.telefone || "";
      var utm = data.utm || "";

      if (!name || !document || !email || !phone) {
        res.writeHead(400);
        return res.end(JSON.stringify({ error: "Faltando: name=" + name + " doc=" + document + " email=" + email + " phone=" + phone }));
      }

      var docDigits = document.replace(/\D/g, "");
      var phoneDigits = phone.replace(/\D/g, "");

      var payload = {
        amount: 2490,
        customer: { name: name.trim(), document: docDigits, email: email.trim(), phone: phoneDigits },
        item: { title: "Plano Completo Worka", price: 2490, quantity: 1 },
        paymentMethod: "PIX",
        utm: utm
      };

      console.log("Enviando Duttyfy:", JSON.stringify(payload));

      httpsPost(payload).then(function(r) {
        console.log("Duttyfy respondeu:", r.status, JSON.stringify(r.body));
        if (r.status >= 400) { res.writeHead(r.status); return res.end(JSON.stringify({ error: JSON.stringify(r.body) })); }
        res.writeHead(200);
        res.end(JSON.stringify({ pixCode: r.body.pixCode, transactionId: r.body.transactionId, status: r.body.status }));
      }).catch(function(e) { res.writeHead(502); res.end(JSON.stringify({ error: e.message })); });
    }).catch(function(e) { res.writeHead(500); res.end(JSON.stringify({ error: e.message })); });
    return;
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: "Rota nao encontrada." }));
});

server.listen(PORT, function() { console.log("Worka rodando na porta " + PORT); });
