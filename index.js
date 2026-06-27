const http = require("http");
const https = require("https");
const nodemailer = require("nodemailer");

const PIX_URL = process.env.DUTTYFY_PIX_URL_ENCRYPTED || "";
const PORT = process.env.PORT || 3000;
const GMAIL_USER = process.env.GMAIL_USER || "";
const GMAIL_PASS = process.env.GMAIL_PASS || "";

const codigos = {};

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: { user: GMAIL_USER, pass: GMAIL_PASS }
});

function gerarCodigo() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function httpsPost(body) {
  return new Promise(function(resolve, reject) {
    const u = new URL(PIX_URL);
    const data = JSON.stringify(body);
    const opts = {
      hostname: u.hostname, path: u.pathname, method: "POST",
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

  if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }

  const urlObj = new URL(req.url, "http://localhost:" + PORT);

  // Enviar código de verificação
  if (req.method === "POST" && urlObj.pathname === "/enviar-codigo") {
    getBody(req).then(function(raw) {
      var data = JSON.parse(raw);
      var email = data.email;
      var nome = data.name || "Cliente";
      if (!email) { res.writeHead(400); return res.end(JSON.stringify({ error: "Email obrigatorio." })); }
      var codigo = gerarCodigo();
      codigos[email] = { codigo: codigo, expira: Date.now() + 10 * 60 * 1000 };
      transporter.sendMail({
        from: '"Worka" <' + GMAIL_USER + '>',
        to: email,
        subject: "Seu código de verificação Worka",
        html: '<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#f7f8f7;border-radius:16px;">' +
          '<h2 style="color:#16622f;font-size:1.5rem;margin-bottom:8px;">Olá, ' + nome + '! 👋</h2>' +
          '<p style="color:#3a3d39;margin-bottom:24px;">Seu código de verificação para acessar o <strong>Worka</strong> é:</p>' +
          '<div style="background:#0a2e1a;border-radius:12px;padding:24px;text-align:center;margin-bottom:24px;">' +
          '<span style="font-size:2.5rem;font-weight:800;color:#3dd669;letter-spacing:8px;">' + codigo + '</span></div>' +
          '<p style="color:#6b7068;font-size:0.85rem;">Este código expira em <strong>10 minutos</strong>. Não compartilhe com ninguém.</p>' +
          '<p style="color:#6b7068;font-size:0.85rem;margin-top:16px;">Se você não solicitou este código, ignore este e-mail.</p>' +
          '</div>'
      }, function(err) {
        if (err) { res.writeHead(500); return res.end(JSON.stringify({ error: "Erro ao enviar email: " + err.message })); }
        res.writeHead(200);
        res.end(JSON.stringify({ ok: true }));
      });
    }).catch(function(e) { res.writeHead(500); res.end(JSON.stringify({ error: e.message })); });
    return;
  }

  // Verificar código
  if (req.method === "POST" && urlObj.pathname === "/verificar-codigo") {
    getBody(req).then(function(raw) {
      var data = JSON.parse(raw);
      var email = data.email;
      var codigo = data.codigo;
      var entry = codigos[email];
      if (!entry) { res.writeHead(400); return res.end(JSON.stringify({ error: "Código não encontrado. Solicite um novo." })); }
      if (Date.now() > entry.expira) { delete codigos[email]; res.writeHead(400); return res.end(JSON.stringify({ error: "Código expirado. Solicite um novo." })); }
      if (entry.codigo !== codigo) { res.writeHead(400); return res.end(JSON.stringify({ error: "Código incorreto. Tente novamente." })); }
      delete codigos[email];
      res.writeHead(200);
      res.end(JSON.stringify({ ok: true }));
    }).catch(function(e) { res.writeHead(500); res.end(JSON.stringify({ error: e.message })); });
    return;
  }

  // Status PIX
  if (req.method === "GET" && urlObj.pathname === "/pix") {
    const tid = urlObj.searchParams.get("transactionId");
    if (!tid) { res.writeHead(400); return res.end(JSON.stringify({ error: "transactionId obrigatorio." })); }
    httpsGet(tid).then(function(r) { res.writeHead(r.status); res.end(JSON.stringify(r.body)); })
    .catch(function(e) { res.writeHead(502); res.end(JSON.stringify({ error: e.message })); });
    return;
  }

  // Criar PIX
  if (req.method === "POST" && urlObj.pathname === "/pix") {
    getBody(req).then(function(raw) {
      var data = JSON.parse(raw);
      var name = data.name || "";
      var document = data.document || "";
      var email = data.email || "";
      var phone = data.phone || "";
      var utm = data.utm || "";
      if (!name || !document || !email || !phone) { res.writeHead(400); return res.end(JSON.stringify({ error: "Campos obrigatorios faltando." })); }
      var docDigits = document.replace(/\D/g, "");
      var phoneDigits = phone.replace(/\D/g, "");
      var payload = {
        amount: 2490,
        customer: { name: name.trim(), document: docDigits, email: email.trim(), phone: phoneDigits },
        item: { title: "Plano Completo Worka", price: 2490, quantity: 1 },
        paymentMethod: "PIX", utm: utm
      };
      httpsPost(payload).then(function(r) {
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
