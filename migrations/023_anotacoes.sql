-- 023 — Anotações da empresa
--
-- O que faltava: um lugar para registrar o que acontece com a equipe e
-- que hoje vive no WhatsApp do dono ou num caderno. "Chegou atrasado
-- de novo", "cliente elogiou o atendimento", "conversar sobre o
-- uniforme na segunda".
--
-- Não é o mural (comunicados/) nem o chat: aqueles são para FALAR com
-- a equipe. Isto é a memória do dono — o funcionário não lê. Uma
-- anotação de ocorrência que a pessoa anotada consegue ler não seria
-- escrita com franqueza, e um registro que ninguém escreve com
-- franqueza não serve para decidir nada depois.
--
-- Por que importa: quando chega a hora de promover, advertir ou
-- desligar alguém, a pergunta é sempre "o que aconteceu nos últimos
-- meses?". Sem registro, a resposta é memória — e memória vira
-- discussão.

create table if not exists public.anotacoes (
  id           uuid primary key default gen_random_uuid(),
  empresa_id   uuid not null references public.empresas(id) on delete cascade,

  -- Opcional: anotação SOBRE alguém (ocorrência, elogio) ou sobre o
  -- negócio em geral (ideia, lembrete). on delete set null porque
  -- desligar um funcionário não pode apagar o histórico do que
  -- aconteceu — que é justamente o que se consulta depois.
  funcionario_id uuid references public.funcionarios(id) on delete set null,

  titulo     text not null,
  texto      text,

  -- geral | ocorrencia | elogio | ideia | lembrete
  -- Texto e não enum: enum no Postgres exige migração para adicionar
  -- um valor, e a lista vai crescer. Quem valida é o backend.
  categoria  text not null default 'geral',

  -- Sobe para o topo da lista. O que está fixado é o que o dono não
  -- quer perder de vista nesta semana.
  fixada     boolean not null default false,

  -- Data em que a anotação vira aviso (push + e-mail). É o que separa
  -- um caderno de anotações de um sistema: o caderno não avisa nada.
  lembrar_em        date,
  lembrete_enviado  boolean not null default false,

  -- Quem escreveu, em texto: pode ter sido o dono (que não está na
  -- tabela de funcionários) ou um gerente. Guardar o nome resolve os
  -- dois sem um segundo campo de id.
  autor      text,

  created_at timestamptz not null default now(),
  updated_at timestamptz
);

-- A consulta padrão é "as anotações desta empresa, mais recentes
-- primeiro, fixadas no topo".
create index if not exists idx_anotacoes_empresa
  on public.anotacoes (empresa_id, fixada desc, created_at desc);

-- "O que já foi anotado sobre esta pessoa" — a consulta que se faz
-- antes de promover, advertir ou desligar alguém.
create index if not exists idx_anotacoes_funcionario
  on public.anotacoes (funcionario_id) where funcionario_id is not null;

-- A rotina diária procura só o que vence hoje e ainda não avisou.
-- Parcial: anotação sem lembrete é a maioria e não precisa ocupar
-- espaço no índice.
create index if not exists idx_anotacoes_lembrete
  on public.anotacoes (lembrar_em)
  where lembrar_em is not null and lembrete_enviado = false;

-- Mesma postura do resto do projeto: RLS ligado e NENHUMA política =
-- nega tudo por padrão. Quem acessa é o backend com a service key,
-- que passa por cima do RLS e filtra por empresa_id em toda rota.
alter table public.anotacoes enable row level security;

comment on table  public.anotacoes is
  'Memória do dono sobre a equipe e o negócio. Não é visível para o funcionário.';
comment on column public.anotacoes.lembrar_em is
  'Data em que a anotação vira aviso. Nulo = anotação sem lembrete.';
