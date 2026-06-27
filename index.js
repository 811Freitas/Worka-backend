const http = require("http");
const https = require("https");

const PIX_URL = process.env.DUTTYFY_PIX_URL_ENCRYPTED || "";
const PORT = process.env.PORT || 3000;

function httpsPost(body) {
  return new Promise(function(resolve, reject) {
    const u = new URL(PIX_URL);
    const data = JSON.stringify(body);
    const options = {
      hostname: u.hostname,
      path: u.pathname,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(data)
      }
    };
    const req = https.request(options, function(res) {
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
    const path = u.pathname + "?transactionId=" + encodeURIComponent(transactionId);
    const options = { hostname: u.hostname, path: path, method: "GET" };
    const req = https.request(options, function(res) {
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
    if (!tid) {
      res.writeHead(400);
      return res.end(JSON.stringify({ error: "transactionId obrigatorio." }));
    }
    httpsGet(tid).then(function(result) {
      res.writeHead(result.status);
      res.end(JSON.stringify(result.body));
    }).catch(function(e) {
      res.writeHead(502);
      res.end(JSON.stringify({ error: e.message }));
    });
    return;
  }

  if (req.method === "POST" && urlObj.pathname === "/pix") {
    let raw = "";
    req.on("data", function(c) { raw += c; });
    req.on("end", function() {
      let data;
      try { data = JSON.parse(raw); }
      catch(e) {
        res.writeHead(400);
        return res.end(JSON.stringify({ error: "Body invalido." }));
      }

      const name = data.name;
      const document = data.document;
      const email = data.email;
      const phone = data.phone;
      const utm = data.utm || "";

      if (!name || !document || !email || !phone) {
        res.writeHead(400);
        return res.end(JSON.stringify({ error: "Campos obrigatorios faltando." }));
      }

      const docDigits = document.replace(/\D/g, "");
      const phoneDigits = phone.replace(/\D/g, "");

      if (docDigits.length !== 11 && docDigits.length !== 14) {
        res.writeHead(400);
        return res.end(JSON.stringify({ error: "CPF 11 digitos ou CNPJ 14 digitos." }));
      }

      const payload = {
        amount: 2490,
        customer: { name: name.trim(), document: docDigits, email: email.trim(), phone: phoneDigits },
        item: { title: "Plano Completo Worka", price: 2490, quantity: 1 },
        paymentMethod: "PIX",
        utm: utm
      };

      httpsPost(payload).then(function(result) {
        if  (result.status >= 400) {
  res.writeHead(result.status);
  return res.end(JSON.stringify({ error: JSON.stringify(result.body) }));
      }

        res.writeHead(200);
        res.end(JSON.stringify({
          pixCode: result.body.pixCode,
          transactionId: result.body.transactionId,
          status: result.body.status
        }));
      }).catch(function(e) {
        res.writeHead(502);
        res.end(JSON.stringify({ error: e.message }));
      });
    });
    return;
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: "Rota nao encontrada." }));
});

server.listen(PORT, function() {
  console.log("Worka backend rodando na porta " + PORT);
});
