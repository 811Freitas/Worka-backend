-- 024 — Registro de uso de IA, por empresa e por mês
--
-- Existe por uma razão só: IA é o único custo do Workap que cresce com
-- o uso e não com o número de assinantes. Uma assinatura de R$ 49,99
-- não sobrevive a uma conta de IA que ninguém está olhando.
--
-- Guardar TOKENS, e não só a contagem de chamadas: duas chamadas podem
-- custar 50x uma da outra dependendo do tamanho do que entrou. Contar
-- chamada é contar a coisa errada.
--
-- Não guarda o texto enviado nem a resposta. O que a empresa escreve
-- nos comunicados e nas anotações não precisa virar um segundo lugar
-- onde esse dado mora — aqui fica só quanto custou.

create table if not exists public.ia_usos (
  id         uuid primary key default gen_random_uuid(),
  empresa_id uuid not null references public.empresas(id) on delete cascade,

  -- 'resumo_diario' | 'escrever'. Serve para saber QUAL uso puxa o
  -- custo antes de decidir cortar ou cobrar.
  tipo       text not null,

  tokens_entrada integer not null default 0,
  tokens_saida   integer not null default 0,

  -- Custo em micro-dólares (milionésimos). Inteiro de propósito: o
  -- resto do projeto guarda dinheiro em centavos inteiros pela mesma
  -- razão, e aqui os valores são pequenos demais para centavos —
  -- um resumo custa cerca de 3000 micro-dólares (US$ 0,003).
  custo_microdolares integer not null default 0,

  modelo     text,
  criado_em  timestamptz not null default now()
);

-- A consulta que importa é "quanto esta empresa gastou neste mês".
create index if not exists idx_ia_usos_empresa_mes
  on public.ia_usos (empresa_id, criado_em desc);

alter table public.ia_usos enable row level security;

comment on table public.ia_usos is
  'Quanto de IA cada empresa consumiu. Só números — não guarda o texto enviado nem a resposta.';
