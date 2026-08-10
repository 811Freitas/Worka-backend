-- ════════════════════════════════════════════════════════════
-- WORKAP — Central de suporte
-- ════════════════════════════════════════════════════════════
-- Rode uma única vez no projeto Supabase ATIVO
-- ("Worka1" — vtkmqykwyilcdnigaxsr), em: SQL Editor > New query.
-- ════════════════════════════════════════════════════════════
--
-- Até agora o Workap não tinha NENHUM canal de suporte. Nem WhatsApp,
-- nem e-mail de contato, em lugar nenhum do site ou do app. Quando o
-- primeiro cliente pagante tivesse um problema, não teria com quem
-- falar — e cliente que não consegue falar cancela e não volta.
--
-- A escolha por chamado dentro do produto, em vez de um link de
-- WhatsApp, tem uma razão prática: o chamado chega com empresa, plano e
-- histórico junto. No WhatsApp chega "oi, não tá funcionando" de um
-- número que ninguém sabe de quem é.

create table if not exists public.chamados (
  id             uuid primary key default gen_random_uuid(),
  empresa_id     uuid not null references public.empresas(id) on delete cascade,

  -- Quem abriu. Nulo quando foi o próprio dono (que não tem linha em
  -- `funcionarios`). O nome e o e-mail ficam copiados abaixo de
  -- propósito: se a pessoa for desligada, o chamado precisa continuar
  -- dizendo quem escreveu aquilo.
  funcionario_id uuid references public.funcionarios(id) on delete set null,
  autor_nome     text not null,
  autor_email    text not null,

  assunto        text not null,

  -- duvida | problema | sugestao | cobranca
  categoria      text not null default 'duvida',

  -- aberto | respondido | resolvido | fechado
  --
  -- "respondido" é diferente de "resolvido": respondido é a bola no
  -- campo do cliente, resolvido é o suporte dando por encerrado. Juntar
  -- os dois num só faria a fila do suporte mentir sobre o que ainda
  -- precisa de atenção.
  status         text not null default 'aberto',

  -- normal | urgente
  prioridade     text not null default 'normal',

  -- Falso quando o suporte respondeu e o cliente ainda não abriu. É o
  -- que acende a bolinha no menu do app.
  lido_pelo_dono boolean not null default true,

  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);

create index if not exists idx_chamados_empresa on public.chamados (empresa_id, updated_at desc);
create index if not exists idx_chamados_status  on public.chamados (status, updated_at desc);

-- Conversa do chamado. Tabela separada em vez de um campo de texto que
-- vai crescendo: assim cada fala tem autor e horário, e dá para saber
-- quanto tempo o cliente esperou — que é a métrica que importa em
-- suporte.
create table if not exists public.chamado_mensagens (
  id         uuid primary key default gen_random_uuid(),
  chamado_id uuid not null references public.chamados(id) on delete cascade,

  -- 'cliente' ou 'suporte'. Não é derivado do funcionario_id porque o
  -- suporte é a Workap, que não tem linha em `funcionarios`.
  autor_tipo text not null,
  autor_nome text not null,
  mensagem   text not null,
  created_at timestamptz not null default now()
);

create index if not exists idx_chamado_msgs on public.chamado_mensagens (chamado_id, created_at);

alter table public.chamados          enable row level security;
alter table public.chamado_mensagens enable row level security;
