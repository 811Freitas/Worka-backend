-- ════════════════════════════════════════════════════════════
-- WORKAP — Chat, férias/folgas, metas e desligamento
-- ════════════════════════════════════════════════════════════
-- Rode este SQL uma única vez no projeto Supabase ATIVO
-- ("Worka1" — vtkmqykwyilcdnigaxsr), em: SQL Editor > New query.
-- ════════════════════════════════════════════════════════════

-- ── 1. CHAT ─────────────────────────────────────────────────
-- Conversa direta entre duas pessoas da mesma empresa. Não é o
-- Mural (que é aviso de um para todos) nem os Comunicados da
-- plataforma (que é a Workap falando com as empresas).
--
-- remetente/destinatario guardam o funcionario_id. Quando o DONO
-- conversa, ele não tem linha em `funcionarios` — por isso os dois
-- campos aceitam NULL, e NULL significa "o dono da empresa".
create table if not exists public.mensagens (
  id            uuid primary key default gen_random_uuid(),
  empresa_id    uuid not null references public.empresas(id),

  remetente_id    uuid references public.funcionarios(id),
  destinatario_id uuid references public.funcionarios(id),

  texto         text not null,
  lida          boolean not null default false,
  lida_em       timestamptz,
  created_at    timestamptz not null default now()
);

-- A tela de conversa busca por (empresa, os dois lados, ordem
-- cronológica). Sem índice, cada abertura de conversa varre a tabela
-- inteira de mensagens da empresa.
create index if not exists idx_mensagens_conversa
  on public.mensagens (empresa_id, remetente_id, destinatario_id, created_at desc);

-- Contador de não lidas na lista de conversas.
create index if not exists idx_mensagens_nao_lidas
  on public.mensagens (empresa_id, destinatario_id, lida);

-- ── 2. FÉRIAS, FOLGAS E LICENÇAS ────────────────────────────
-- A tabela `ausencias` já existia, mas guarda UM dia (coluna `data`)
-- e serve para falta e atestado. Férias é período, tem começo e fim,
-- e é combinada antes — não é ausência a justificar depois. Misturar
-- as duas faria "faltas do mês" contar as férias de alguém.
create table if not exists public.periodos_afastamento (
  id             uuid primary key default gen_random_uuid(),
  empresa_id     uuid not null references public.empresas(id),
  funcionario_id uuid not null references public.funcionarios(id),

  tipo           text not null default 'ferias'
                 check (tipo in ('ferias','folga','licenca','afastamento')),

  data_inicio    date not null,
  data_fim       date not null,
  observacao     text,

  -- Quem registrou fica no histórico: férias é assunto que volta em
  -- conversa meses depois.
  registrado_por uuid,
  created_at     timestamptz not null default now(),

  check (data_fim >= data_inicio)
);

create index if not exists idx_afastamento_empresa
  on public.periodos_afastamento (empresa_id, data_inicio desc);

create index if not exists idx_afastamento_funcionario
  on public.periodos_afastamento (funcionario_id, data_fim);

-- ── 3. METAS ────────────────────────────────────────────────
-- Meta da empresa (funcionario_id nulo) ou de uma pessoa.
create table if not exists public.metas (
  id             uuid primary key default gen_random_uuid(),
  empresa_id     uuid not null references public.empresas(id),
  funcionario_id uuid references public.funcionarios(id),

  titulo         text not null,
  descricao      text,

  -- 'valor' mostra em reais, 'quantidade' em número puro. É só o
  -- formato de exibição: o cálculo do progresso é o mesmo.
  tipo           text not null default 'valor'
                 check (tipo in ('valor','quantidade')),

  alvo           numeric not null check (alvo > 0),
  atual          numeric not null default 0,

  periodo_inicio date not null,
  periodo_fim    date not null,

  status         text not null default 'ativa'
                 check (status in ('ativa','concluida','cancelada')),

  created_at     timestamptz not null default now(),
  check (periodo_fim >= periodo_inicio)
);

create index if not exists idx_metas_empresa
  on public.metas (empresa_id, status, periodo_fim desc);

-- ── 4. DESLIGAMENTO ─────────────────────────────────────────
-- `funcionarios.status` já aceita 'inativo'. O que faltava era o
-- registro de QUANDO e POR QUÊ — sem isso, "demitir" apagaria a
-- história da pessoa e ninguém saberia responder daqui a seis meses.
alter table public.funcionarios
  add column if not exists desligado_em timestamptz;

alter table public.funcionarios
  add column if not exists motivo_desligamento text;

-- ── Segurança ───────────────────────────────────────────────
-- O backend usa a service_role key, que ignora RLS. RLS ligado sem
-- policy permissiva: se a chave pública (anon) for usada no navegador
-- por engano, ninguém lê conversa de empresa nenhuma pelo frontend.
alter table public.mensagens             enable row level security;
alter table public.periodos_afastamento  enable row level security;
alter table public.metas                 enable row level security;
