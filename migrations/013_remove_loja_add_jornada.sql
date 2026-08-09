-- ════════════════════════════════════════════════════════════
-- WORKAP — Sai a loja online, entra o espelho de ponto
-- ════════════════════════════════════════════════════════════
-- Rode este SQL uma única vez no projeto Supabase ATIVO
-- ("Worka1" — vtkmqykwyilcdnigaxsr), em: SQL Editor > New query.
-- ════════════════════════════════════════════════════════════
--
-- Decisão de produto: a loja online (vitrine pública, fila de pedidos
-- e comanda térmica) saiu do Workap. O plano de cima passa a se
-- chamar "Pro" e a valer pelo espelho de ponto, pelo banco de horas e
-- pelos relatórios prontos para o contador.
--
-- O raciocínio: a loja competia com iFood, Anota AI e afins, e exigia
-- do lojista montar catálogo e divulgar link — trabalho ANTES de ver
-- valor. O fechamento do ponto é o oposto: a dor já existe, acontece
-- todo mês sem falta, e o dado que alimenta o relatório já está no
-- banco porque a equipe bate ponto todo dia.

-- ── 1. TABELAS DA LOJA SAEM ─────────────────────────────────
-- `pedidos` antes de `loja_config` por causa da referência ao cargo.
drop table if exists public.pedidos     cascade;
drop table if exists public.loja_config cascade;

-- ── 2. COLUNAS DE CATÁLOGO SAEM DO ESTOQUE ──────────────────
-- Só existiam para a vitrine. `descricao` fica: é campo útil para
-- qualquer item de estoque, com ou sem loja.
alter table public.produtos_validade
  drop column if exists preco_centavos,
  drop column if exists no_catalogo;

drop index if exists public.idx_produtos_catalogo;

-- ── 3. O PLANO "pedidos" VIRA "pro" ─────────────────────────
update public.empresas
   set plano = 'pro'
 where plano = 'pedidos';

comment on column public.empresas.plano is
  'completo (R$ 49,99) ou pro (R$ 89,90 — espelho de ponto, banco de horas e relatórios do contador).';

-- ── 4. JORNADA DE TRABALHO ──────────────────────────────────
--
-- Sem saber quantas horas a pessoa DEVE fazer, não existe hora extra,
-- não existe falta e não existe banco de horas — só um monte de
-- batidas soltas. É esta tabela que transforma registro de ponto em
-- fechamento de mês.
--
-- Uma linha por empresa é o padrão (funcionario_id null); linha com
-- funcionario_id preenchido é a exceção de quem tem jornada diferente
-- (meio período, escala 12x36). Assim o dono configura uma vez e só
-- mexe em quem foge da regra.
create table if not exists public.config_jornada (
  id             uuid primary key default gen_random_uuid(),
  empresa_id     uuid not null references public.empresas(id) on delete cascade,
  funcionario_id uuid references public.funcionarios(id) on delete cascade,

  -- Minutos por dia. 8h = 480. Em minutos inteiros porque hora em
  -- decimal (7,5h) reintroduz o erro de ponto flutuante em toda soma
  -- do mês, e o resultado disso é o espelho fechando com 1 minuto de
  -- diferença que ninguém consegue explicar para o funcionário.
  minutos_diarios integer not null default 480,

  -- Dias da semana trabalhados. 0 = domingo … 6 = sábado.
  -- Padrão seg–sex; comércio costuma incluir o sábado.
  dias_semana integer[] not null default array[1,2,3,4,5],

  -- Tolerância legal: até 5 minutos por marcação e 10 no dia não
  -- contam como extra nem como atraso (CLT art. 58, §1º). Configurável
  -- porque acordo coletivo pode mudar.
  tolerancia_minutos integer not null default 10,

  -- Intervalo mínimo obrigatório. Serve para apontar no espelho quem
  -- não fez a pausa — que é irregularidade trabalhista, não detalhe.
  intervalo_minimo_minutos integer not null default 60,

  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  -- Uma configuração por funcionário, e uma padrão por empresa.
  unique (empresa_id, funcionario_id)
);

-- Índice parcial para achar a linha padrão da empresa (a que tem
-- funcionario_id nulo) sem varrer as exceções.
create unique index if not exists idx_jornada_padrao
  on public.config_jornada (empresa_id) where funcionario_id is null;

alter table public.config_jornada enable row level security;
