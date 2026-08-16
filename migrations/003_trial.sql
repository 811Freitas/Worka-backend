-- ════════════════════════════════════════════════════════════
-- ZAPFY — Trial de 7 dias
-- ════════════════════════════════════════════════════════════
-- Mesma mecânica do Workap: toda conta nova ganha 7 dias de uso
-- completo, sem cartão. Sem trial, a primeira pergunta de quem chega é
-- "preciso pagar antes de nem saber se funciona?" — e a resposta certa
-- para conversão é não.

alter table contas
  -- Quando o trial acaba. Null para conta que nunca teve trial (criada
  -- direto num plano pago, pelo painel de owner).
  add column if not exists trial_fim timestamptz,

  -- As duas travas de "já avisei" — sem elas, o cron rodando a cada
  -- hora mandaria o mesmo aviso de novo a cada hora, para sempre.
  add column if not exists aviso_trial_sent    boolean not null default false,
  add column if not exists aviso_expirado_sent boolean not null default false;

-- status ganha dois valores novos, além de 'ativa'/'suspensa' que já
-- existiam: 'trial' (contando os 7 dias) e 'inadimplente' (trial
-- acabou sem virar plano pago). Não há constraint de enum no banco —
-- `status` sempre foi texto livre — e é assim de propósito: uma
-- constraint exigiria migration toda vez que um estado novo nascesse.
-- Quem define os valores válidos é o código, em CONTA_ATIVA no
-- servidor.

create index if not exists idx_contas_trial_fim on contas (trial_fim)
  where status = 'trial';
