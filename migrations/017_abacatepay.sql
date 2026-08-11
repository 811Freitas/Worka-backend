-- ════════════════════════════════════════════════════════════
-- WORKAP — AbacatePay no lugar da Stripe (e colunas genéricas)
-- ════════════════════════════════════════════════════════════
-- Rode uma única vez no projeto Supabase ATIVO
-- ("Worka1" — vtkmqykwyilcdnigaxsr), em: SQL Editor > New query.
-- ════════════════════════════════════════════════════════════
--
-- POR QUE GENÉRICO AGORA
--
-- O gateway mudou duas vezes: Duttyfy → Stripe → AbacatePay. Colunas
-- com o nome do fornecedor (`stripe_customer_id`) obrigam uma migração
-- a cada troca, e obrigam a caçar o nome espalhado pelo código inteiro.
-- Com nomes genéricos + uma coluna dizendo QUAL gateway, a próxima
-- troca é só código.
--
-- POR QUE ABACATEPAY
--
-- PIX a R$ 0,80 fixo contra ~R$ 2,38 do cartão na Stripe. Em R$ 49,99
-- isso é R$ 1,55 por cliente por mês que deixa de virar taxa. Cartão dá
-- empate entre as duas; o PIX é que decide. E a V2 tem assinatura, que
-- era a condição para não repetir o erro do Duttyfy (cobrar uma vez e
-- nunca mais).

alter table public.empresas
  -- 'abacatepay' hoje. Guardado explicitamente porque, numa troca, as
  -- assinaturas antigas continuam vivas no gateway anterior — e o
  -- backend precisa saber para quem perguntar.
  add column if not exists pagamento_gateway       text,
  add column if not exists pagamento_cliente_id    text,
  add column if not exists pagamento_assinatura_id text;

-- Preserva o que existia da Stripe em vez de descartar: se alguém já
-- tivesse assinado, apagar o id do cliente deixaria a cobrança órfã.
update public.empresas
   set pagamento_gateway    = 'stripe',
       pagamento_cliente_id = stripe_customer_id,
       pagamento_assinatura_id = stripe_subscription_id
 where stripe_customer_id is not null;

alter table public.empresas
  drop column if exists stripe_customer_id,
  drop column if exists stripe_subscription_id;

drop index if exists public.idx_empresas_stripe_customer;
drop index if exists public.idx_empresas_stripe_sub;

create unique index if not exists idx_empresas_pag_cliente
  on public.empresas (pagamento_cliente_id) where pagamento_cliente_id is not null;
create unique index if not exists idx_empresas_pag_assinatura
  on public.empresas (pagamento_assinatura_id) where pagamento_assinatura_id is not null;

-- `assinatura_ate` e `cancelamento_agendado` continuam como estavam:
-- não têm nada de específico da Stripe e seguem sendo a fonte da
-- verdade do acesso.

-- ── EVENTOS DO GATEWAY ──────────────────────────────────────
--
-- Mesma função da tabela anterior, agora com o gateway na linha.
-- A chave primária continua sendo o id do evento: é o que faz o
-- Postgres recusar a duplicata sozinho quando o gateway reenvia um
-- aviso já processado. Sem isso, um "pago" repetido somaria mais um
-- mês de acesso de graça.
create table if not exists public.eventos_pagamento (
  id          text primary key,
  gateway     text not null,
  tipo        text not null,
  recebido_em timestamptz not null default now(),
  empresa_id  uuid,
  payload     jsonb
);

create index if not exists idx_eventos_pag_ts on public.eventos_pagamento (recebido_em desc);
alter table public.eventos_pagamento enable row level security;

drop table if exists public.eventos_stripe;
