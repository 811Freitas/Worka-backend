-- ════════════════════════════════════════════════════════════
-- WORKAP — Assinatura recorrente pela Stripe (sai o Duttyfy)
-- ════════════════════════════════════════════════════════════
-- Rode uma única vez no projeto Supabase ATIVO
-- ("Worka1" — vtkmqykwyilcdnigaxsr), em: SQL Editor > New query.
-- ════════════════════════════════════════════════════════════
--
-- O PROBLEMA QUE ISTO RESOLVE
--
-- O fluxo PIX cobrava UMA VEZ. Ele marcava a empresa como `ativa` e
-- pronto: não existia nenhuma rotina que, 30 dias depois, cobrasse de
-- novo ou revogasse o acesso. Na prática o cliente pagava R$ 49,99 uma
-- única vez e usava o Workap para sempre — o mês 2 nunca chegava.
--
-- Com a Stripe a cobrança é da Stripe: ela guarda o cartão, cobra todo
-- mês sozinha e avisa este backend por webhook. O que muda aqui é a
-- memória necessária para isso funcionar.

alter table public.empresas
  -- Cliente e assinatura do lado da Stripe. Guardar os dois é o que
  -- permite abrir o portal de cobrança do cliente, trocar cartão e
  -- cancelar sem ninguém precisar entrar no painel da Stripe.
  add column if not exists stripe_customer_id     text,
  add column if not exists stripe_subscription_id text,

  -- Fim do período pago atual, copiado do current_period_end da Stripe.
  --
  -- É a fonte da verdade do acesso. `status = 'ativa'` sozinho é o que
  -- deixava a empresa ativa para sempre: sem uma data para comparar,
  -- não existe "parou de pagar". A verificação diária compara isto com
  -- agora e derruba quem venceu.
  add column if not exists assinatura_ate         timestamptz,

  -- Cliente pediu cancelamento mas o período já pago continua valendo.
  -- Sem esta coluna, cancelar significaria cortar o acesso na hora de
  -- alguém que pagou o mês inteiro.
  add column if not exists cancelamento_agendado  boolean not null default false;

-- Índices parciais: o webhook chega com o id da Stripe e precisa achar
-- a empresa. Únicos porque duas empresas com o mesmo cliente Stripe
-- seria um erro de dados que vale barrar no banco.
create unique index if not exists idx_empresas_stripe_customer
  on public.empresas (stripe_customer_id) where stripe_customer_id is not null;
create unique index if not exists idx_empresas_stripe_sub
  on public.empresas (stripe_subscription_id) where stripe_subscription_id is not null;

comment on column public.empresas.assinatura_ate is
  'Fim do periodo pago atual, vindo do current_period_end da Stripe. E a fonte da verdade do acesso: sem isso, uma empresa que parou de pagar continuaria ativa para sempre.';

-- ── EVENTOS DA STRIPE ───────────────────────────────────────
--
-- Duas razões, e a primeira é obrigatória:
--
-- 1. IDEMPOTÊNCIA. A Stripe reenvia o mesmo evento quando não recebe
--    200 — e reenvia mesmo depois de ter recebido, em casos de rede.
--    Sem guardar o id já processado, um "invoice.paid" reenviado
--    somaria 30 dias de acesso de novo, de graça. A chave primária ser
--    o id do evento faz o banco recusar a duplicata sozinho.
--
-- 2. Auditoria: quando um cliente disser que pagou e o acesso não
--    abriu, a resposta está aqui, não no painel da Stripe.
create table if not exists public.eventos_stripe (
  id          text primary key,      -- evt_... da própria Stripe
  tipo        text not null,
  recebido_em timestamptz not null default now(),
  empresa_id  uuid,
  payload     jsonb
);

create index if not exists idx_eventos_stripe_ts on public.eventos_stripe (recebido_em desc);

alter table public.eventos_stripe enable row level security;
