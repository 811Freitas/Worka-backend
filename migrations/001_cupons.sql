-- ════════════════════════════════════════════════════════════
-- WORKA — Tabela de cupons de desconto
-- ════════════════════════════════════════════════════════════
-- Rode este SQL uma única vez no projeto Supabase ATIVO
-- ("Worka1" — vtkmqykwyilcdnigaxsr), em: SQL Editor > New query.
--
-- Sem esta tabela, as rotas de cupom respondem erro e o campo de
-- cupom no checkout simplesmente não encontra nenhum código —
-- o pagamento continua funcionando normalmente, sem desconto.
-- ════════════════════════════════════════════════════════════

create table if not exists public.cupons (
  id           uuid primary key default gen_random_uuid(),

  -- Código que o cliente digita no checkout. Sempre gravado em
  -- MAIÚSCULAS pelo backend para a comparação não depender de como
  -- a pessoa digitou ("promo10" e "PROMO10" são o mesmo cupom).
  codigo       text not null unique,

  -- 'percentual' = desconto de N% sobre o valor do plano
  -- 'valor'      = desconto de N reais sobre o valor do plano
  tipo         text not null check (tipo in ('percentual', 'valor')),

  -- Percentual (1 a 100) ou valor em reais, conforme "tipo".
  valor        numeric(10,2) not null check (valor > 0),

  descricao    text,
  ativo        boolean not null default true,

  -- Data de expiração (opcional). NULL = não expira.
  validade     date,

  -- Limite total de usos (opcional). NULL = ilimitado.
  usos_max     integer,
  usos         integer not null default 0,

  created_at   timestamptz not null default now()
);

-- Busca por código é a operação mais frequente (todo checkout que
-- aplica cupom faz exatamente isso).
create index if not exists idx_cupons_codigo on public.cupons (codigo);

-- ── Segurança ───────────────────────────────────────────────
-- O backend acessa o banco com a service_role key, que ignora RLS.
-- Mesmo assim habilitamos RLS sem nenhuma policy permissiva: assim,
-- se algum dia a chave pública (anon) for usada no navegador por
-- engano, ninguém consegue ler nem escrever cupons direto do
-- frontend — só através das rotas do backend, que checam permissão.
alter table public.cupons enable row level security;

-- ── Exemplos (opcional — descomente para criar cupons de teste) ──
-- insert into public.cupons (codigo, tipo, valor, descricao) values
--   ('LANCAMENTO20', 'percentual', 20, 'Promoção de lançamento — 20% off'),
--   ('BEMVINDO10',   'valor',      10, 'R$ 10 de desconto na primeira mensalidade');
