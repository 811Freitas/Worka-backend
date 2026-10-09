'use strict';
const MAX_BODY = 4096;
const PLANS = new Set(['Starter', 'Pro', 'Enterprise']);
function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0, chunks = [], ended = false;
    const fail = (status, message) => { if (ended) return; ended = true; clearTimeout(timer); reject(Object.assign(new Error(message), { status })); };
    const timer = setTimeout(() => fail(408, 'Tempo de envio excedido.'), 10000);
    req.on('data', chunk => { if (ended) return; size += Buffer.byteLength(chunk); if (size > MAX_BODY) return fail(413, 'Formulário muito grande.'); chunks.push(Buffer.from(chunk)); });
    req.on('end', () => { if (ended) return; clearTimeout(timer); try { const value = JSON.parse(Buffer.concat(chunks).toString('utf8')); ended = true; resolve(value); } catch { fail(400, 'JSON inválido.'); } });
    req.on('aborted', () => fail(400, 'Envio interrompido.'));
    req.on('error', () => fail(400, 'Falha na leitura.'));
  });
}
function validateLead(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return null;
  if (typeof data.name !== 'string' || typeof data.email !== 'string' || data.consent !== true || !PLANS.has(data.plan)) return null;
  const name = data.name.trim(), email = data.email.trim().toLowerCase();
  if (name.length < 2 || name.length > 100 || /[\x00-\x1f<>]/.test(name)) return null;
  if (email.length > 254 || !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(email)) return null;
  if (data.website !== undefined && typeof data.website !== 'string') return null;
  return { name, email, plan: data.plan, consent_version: 'workap-bots-launch-2026-10-09' };
}
function createLeadsHandler({ database, origins }) {
  return async function handle(req, res) {
    const send = (status, data) => { res.writeHead(status, { 'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store' }); res.end(JSON.stringify(data)); };
    if (req.method !== 'POST') return send(405, {error:'Método não permitido.'});
    if (!origins.includes(req.headers.origin)) return send(403, {error:'Origem não permitida.'});
    if (!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] || '')) return send(415, {error:'Envie JSON.'});
    if (Number(req.headers['content-length'] || 0) > MAX_BODY) return send(413, {error:'Formulário muito grande.'});
    try {
      const body = await readJson(req);
      const lead = validateLead(body);
      if (!lead) return send(400, {error:'Verifique nome, e-mail, plano e consentimento.'});
      if (body.website) return send(202, {ok:true});
      await database('POST', 'worka_bots_leads', { query:'on_conflict=email', body:lead, prefer:'resolution=ignore-duplicates,return=minimal' });
      return send(202, {ok:true});
    } catch (error) {
      // No personal data or database error details in responses/logs.
      return send(error.status || 503, {error:error.status ? error.message : 'Cadastro temporariamente indisponível. Tente novamente.'});
    }
  };
}
module.exports = { createLeadsHandler, validateLead };
