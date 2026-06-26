cat << 'ENDOFFILE'
const http = require("http");
const https = require("https");

const PIX_URL = process.env.DUTTYFY_PIX_URL_ENCRYPTED || "";
const PORT = process.env.PORT || 3000;

function httpsRequest(url, options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

async function fetchComRetry(url, options, body, tentativas = 3) {
  for (let i = 0; i < tentativas; i++) {
    try {
      const res = await httpsRequest(url, options, body);
      if (res.status < 500) return res;
    } catch (_) {}
    if (i < tentativas - 1)
      await new Promise((r) => setTimeout(r, Math.pow(2, i) * 1000));
  }
  throw new Error("Gateway indisponível.");
}

const server = http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Content-Type", "application/json");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    return res.end();
  }

  const url = new URL(req.url, `http://localhost:${PORT}`);

  // GET - status do pagamento
  if (req.method === "GET" && url.pathname === "/pix") {
    const transactionId = url.searchParams.get("transactionId");
    if (!transactionId) {
      res.writeHead(400);
      return res.end(JSON.stringify({ error: "transactionId obrigatório." }));
    }
    try {
      const pixUrl = new URL(PIX_URL);
      const result = await httpsRequest(
        PIX_URL + "?transactionId=" + encodeURIComponent(transactionId),
        { method: "GET", hostname: pixUrl.hostname, path: pixUrl.pathname + "?transactionId=" + encodeURIComponent(transactionId) },
        null
      );
      res.writeHead(result.status);
      return res.end(JSON.stringify(result.body));
    } catch (e) {
      res.writeHead(502);
      return res.end(JSON.stringify({ error: e.message }));
    }
  }

  // POST - criar cobrança PIX
  if (req.method === "POST" && url.pathname === "/pix") {
    let rawBody = "";
    req.on("data", (chunk) => (rawBody += chunk));
    req.on("end", async () => {
      let data;
      try { data = JSON.parse(rawBody); }
      catch {
        res.writeHead(400);
        return res.end(JSON.stringify({ error: "Body inválido." }));
      }

      const { name, document, email, phone, utm } = data;
      if (!name || !document || !email || !phone) {
        res.writeHead(400);
        return res.end(JSON.stringify({ error: "Campos obrigatórios faltando." }));
      }

      const docDigits   = document.replace(/\D/g, "");
      const phoneDigits = phone.replace(/\D/g, "");

      if (docDigits.length !== 11 && docDigits.length !== 14) {
        res.writeHead(400);
        return res.end(JSON.stringify({ error: "CPF deve ter 11 ou CNPJ 14 dígitos." }));
      }

      const payload = JSON.stringify({
        amount: 2490,
        customer: { name: name.trim(), document: docDigits, email: email.trim(), phone: phoneDigits },
        item: { title: "Plano Completo Worka", price: 2490, quantity: 1 },
        paymentMethod: "PIX",
        utm: utm || "",
      });

      try {
        const pixUrl = new URL(PIX_URL);
        const result = await fetchComRetry(
          PIX_URL,
          {
            method: "POST",
            hostname: pixUrl.hostname,
            path: pixUrl.pathname,
            headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) },
          },
          payload
        );

        if (result.status >= 400) {
          res.writeHead(result.status);
          return res.end(JSON.stringify({ error: result.body?.message || "Erro no gateway." }));
        }

        res.writeHead(200);
        return res.end(JSON.stringify({
          pixCode:       result.body.pixCode,
          transactionId: result.body.transactionId,
          status:        result.body.status,
        }));
      } catch (e) {
        res.writeHead(502);
        return res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: "Rota não encontrada." }));
});

server.listen(PORT, () => console.log("Worka PIX backend rodando na porta " + PORT));
ENDOFFILE
{
  "returncode" : 0,
  "stdout" : "const http = require(\"http\");\nconst https = require(\"https\");\n\nconst PIX_URL = process.env.DUTTYFY_PIX_URL_ENCRYPTED || \"\";\nconst PORT = process.env.PORT || 3000;\n\nfunction httpsRequest(url, options, body) {\n  return new Promise((resolve, reject) => {\n    const req = https.request(url, options, (res) => {\n      let data = \"\";\n      res.on(\"data\", (chunk) => (data += chunk));\n      res.on(\"end\", () => {\n        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }\n        catch { resolve({ status: res.statusCode, body: data }); }\n      });\n    });\n    req.on(\"error\", reject);\n    if (body) req.write(body);\n    req.end();\n  });\n}\n\nasync function fetchComRetry(url, options, body, tentativas = 3) {\n  for (let i = 0; i < tentativas; i++) {\n    try {\n      const res = await httpsRequest(url, options, body);\n      if (res.status < 500) return res;\n    } catch (_) {}\n    if (i < tentativas - 1)\n      await new Promise((r) => setTimeout(r, Math.pow(2, i) * 1000));\n  }\n  throw new Error(\"Gateway indisponível.\");\n}\n\nconst server = http.createServer(async (req, res) => {\n  res.setHeader(\"Access-Control-Allow-Origin\", \"*\");\n  res.setHeader(\"Access-Control-Allow-Methods\", \"POST, GET, OPTIONS\");\n  res.setHeader(\"Access-Control-Allow-Headers\", \"Content-Type\");\n  res.setHeader(\"Content-Type\", \"application\/json\");\n\n  if (req.method === \"OPTIONS\") {\n    res.writeHead(204);\n    return res.end();\n  }\n\n  const url = new URL(req.url, `http:\/\/localhost:${PORT}`);\n\n  \/\/ GET - status do pagamento\n  if (req.method === \"GET\" && url.pathname === \"\/pix\") {\n    const transactionId = url.searchParams.get(\"transactionId\");\n    if (!transactionId) {\n      res.writeHead(400);\n      return res.end(JSON.stringify({ error: \"transactionId obrigatório.\" }));\n    }\n    try {\n      const pixUrl = new URL(PIX_URL);\n      const result = await httpsRequest(\n        PIX_URL + \"?transactionId=\" + encodeURIComponent(transactionId),\n        { method: \"GET\", hostname: pixUrl.hostname, path: pixUrl.pathname + \"?transactionId=\" + encodeURIComponent(transactionId) },\n        null\n      );\n      res.writeHead(result.status);\n      return res.end(JSON.stringify(result.body));\n    } catch (e) {\n      res.writeHead(502);\n      return res.end(JSON.stringify({ error: e.message }));\n    }\n  }\n\n  \/\/ POST - criar cobrança PIX\n  if (req.method === \"POST\" && url.pathname === \"\/pix\") {\n    let rawBody = \"\";\n    req.on(\"data\", (chunk) => (rawBody += chunk));\n    req.on(\"end\", async () => {\n      let data;\n      try { data = JSON.parse(rawBody); }\n      catch {\n        res.writeHead(400);\n        return res.end(JSON.stringify({ error: \"Body inválido.\" }));\n      }\n\n      const { name, document, email, phone, utm } = data;\n      if (!name || !document || !email || !phone) {\n        res.writeHead(400);\n        return res.end(JSON.stringify({ error: \"Campos obrigatórios faltando.\" }));\n      }\n\n      const docDigits   = document.replace(\/\\D\/g, \"\");\n      const phoneDigits = phone.replace(\/\\D\/g, \"\");\n\n      if (docDigits.length !== 11 && docDigits.length !== 14) {\n        res.writeHead(400);\n        return res.end(JSON.stringify({ error: \"CPF deve ter 11 ou CNPJ 14 dígitos.\" }));\n      }\n\n      const payload = JSON.stringify({\n        amount: 2490,\n        customer: { name: name.trim(), document: docDigits, email: email.trim(), phone: phoneDigits },\n        item: { title: \"Plano Completo Worka\", price: 2490, quantity: 1 },\n        paymentMethod: \"PIX\",\n        utm: utm || \"\",\n      });\n\n      try {\n        const pixUrl = new URL(PIX_URL);\n        const result = await fetchComRetry(\n          PIX_URL,\n          {\n            method: \"POST\",\n            hostname: pixUrl.hostname,\n            path: pixUrl.pathname,\n            headers: { \"Content-Type\": \"application\/json\", \"Content-Length\": Buffer.byteLength(payload) },\n          },\n          payload\n        );\n\n        if (result.status >= 400) {\n          res.writeHead(result.status);\n          return res.end(JSON.stringify({ error: result.body?.message || \"Erro no gateway.\" }));\n        }\n\n        res.writeHead(200);\n        return res.end(JSON.stringify({\n          pixCode:       result.body.pixCode,\n          transactionId: result.body.transactionId,\n          status:        result.body.status,\n        }));\n      } catch (e) {\n        res.writeHead(502);\n        return res.end(JSON.stringify({ error: e.message }));\n      }\n    });\n    return;\n  }\n\n  res.writeHead(404);\n  res.end(JSON.stringify({ error: \"Rota não encontrada.\" }));\n});\n\nserver.listen(PORT, () => console.log(\"Worka PIX backend rodando na porta \" + PORT));\n",
  "stderr" : ""
}

