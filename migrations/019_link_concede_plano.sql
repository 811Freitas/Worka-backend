-- ════════════════════════════════════════════════════════════
-- WORKAP — Link de pagamento que libera o plano
-- ════════════════════════════════════════════════════════════
-- Rode uma única vez no projeto Supabase ATIVO
-- ("Worka1" — vtkmqykwyilcdnigaxsr), em: SQL Editor > New query.
-- ════════════════════════════════════════════════════════════
--
-- O link deixa de ser só uma cobrança e vira uma VENDA: pagou, o acesso
-- abre sozinho. É o que permite negociar preço com o cliente (plano
-- anual, desconto de lançamento, valor combinado no boca a boca) sem
-- precisar liberar a conta na mão depois.

alter table public.links_pagamento
  -- 'completo', 'pro' ou NULO. Nulo é o padrão e significa cobrança
  -- pura: implantação, consultoria, treinamento — coisas que não têm
  -- nada a ver com o plano do cliente.
  add column if not exists plano_concedido  text,

  -- Quantos dias de acesso o pagamento vale. 30 é o mês normal; 365
  -- cobre o plano anual, que é o principal motivo desta coluna existir.
  add column if not exists dias_acesso      integer not null default 30,

  -- O acesso já foi concedido?
  --
  -- Separado de `status = 'pago'` por causa do caso que acontece de
  -- verdade: o dono negocia com uma padaria que AINDA NÃO TEM CONTA,
  -- manda o link, e a pessoa paga antes de se cadastrar. Nesse momento
  -- não existe empresa para receber o plano.
  --
  -- Sem esta coluna, o pagamento entraria e o acesso nunca abriria —
  -- e o cliente teria pago por nada até alguém perceber. Com ela, a
  -- concessão fica PENDENTE e é aplicada no cadastro, quando o e-mail
  -- bater.
  add column if not exists acesso_aplicado  boolean not null default false,

  -- Preenchido quando o acesso é concedido. Serve de rastro: dado um
  -- pagamento, saber qual conta foi liberada por ele.
  add column if not exists empresa_id       uuid;

-- Índice para a busca feita em todo cadastro novo: existe pagamento
-- pendente para este e-mail? Parcial porque só interessa a linha paga,
-- com plano, ainda não aplicada — que é uma fração mínima da tabela.
create index if not exists idx_links_acesso_pendente
  on public.links_pagamento (cliente_email)
  where plano_concedido is not null and status = 'pago' and acesso_aplicado = false;
