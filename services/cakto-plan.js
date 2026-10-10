'use strict';
// Billing must not use the legacy normalizer, which substitutes unknown plans.
function exactPlan(value, catalog) {
  if (typeof value !== 'string') return null;
  const slug = value.trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(catalog, slug) ? slug : null;
}
async function purchasablePlan(value, { catalog, masterActive, chatbotActive }) {
  const slug = exactPlan(value, catalog);
  if (!slug) return { error: 'Plano inválido. Selecione um plano disponível.', status: 400 };
  if (slug === 'master' && !await masterActive()) return { error: 'Plano indisponível para contratação.', status: 409 };
  if (slug === 'chatbot' && !await chatbotActive()) return { error: 'Plano indisponível para contratação.', status: 409 };
  return { slug };
}
module.exports = { exactPlan, purchasablePlan };
