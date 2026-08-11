-- ════════════════════════════════════════════════════════════
-- WORKAP — Links de pagamento avulsos (painel Owner)
-- ════════════════════════════════════════════════════════════
-- Rode uma única vez no projeto Supabase ATIVO
-- ("Worka1" — vtkmqykwyilcdnigaxsr), em: SQL Editor > New query.
-- ════════════════════════════════════════════════════════════
--
-- Serve para cobrar o que NÃO passa pela assinatura: setup, consultoria,
-- plano anual combinado por fora, cliente que quer pagar de outro jeito.
-- Hoje isso teria que ser feito no painel da AbacatePay, sem registro
-- nenhum do lado do Workap — ou seja, sem saber depois quem pagou o quê.
--
-- Não confundir com `empresas.pagamento_assinatura_id`: aquilo é a
-- assinatura recorrente do plano. Aqui é cobrança única.

create table if not exists public.links_pagamento (
  id             uuid primary key default gen_random_uuid(),

  descricao      text not null,

  -- Em CENTAVOS, como todo dinheiro neste projeto. Reais com vírgula
  -- viram erro de arredondamento em toda soma, e em cobrança isso
  -- aparece como o cliente pagando um centavo a menos do que deve.
  valor_centavos integer not null check (valor_centavos > 0),

  -- Quais meios aparecem na tela de pagamento. PIX primeiro porque é o
  -- mais barato para a Workap (R$ 0,80 fixo contra 3,5% + R$ 0,60 do
  -- cartão e R$ 2,50 do boleto).
  metodos        text[] not null default array['PIX','CARD','BOLETO'],

  -- Para quem é a cobrança. Livre, sem FK: boa parte destes links vai
  -- para gente que ainda não é cliente — é justamente assim que vira.
  cliente_nome   text,
  cliente_email  text,

  gateway        text not null default 'abacatepay',
  gateway_id     text,
  url            text,

  -- aberto | pago | expirado | cancelado
  status         text not null default 'aberto',
  pago_em        timestamptz,

  -- O valor que o gateway confirmou, separado do valor pedido. Se
  -- divergirem, é isso que revela — e divergência silenciosa em
  -- cobrança é o tipo de coisa que só se descobre no fim do mês.
  valor_pago_centavos integer,

  -- Sumir da lista sem apagar: link pago é registro financeiro e não
  -- pode ser removido só porque poluiu a tela.
  arquivado      boolean not null default false,

  criado_em      timestamptz not null default now()
);

create index if not exists idx_links_criado   on public.links_pagamento (criado_em desc);
-- O webhook chega com o id do gateway e precisa achar o link por ele.
create index if not exists idx_links_gateway  on public.links_pagamento (gateway_id) where gateway_id is not null;
create index if not exists idx_links_status   on public.links_pagamento (status, criado_em desc);

alter table public.links_pagamento enable row level security;
