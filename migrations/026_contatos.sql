-- 026 — Agenda de contatos do negócio
--
-- Fornecedor, contador, prestador de serviço, banco. Hoje isso vive na
-- agenda do celular do dono — que ninguém mais da empresa acessa, e
-- que some junto com o aparelho.
--
-- O que faz valer mais que um caderno de telefones:
--
--  1. o telefone vira link de WhatsApp de um toque. É assim que se
--     fala com fornecedor no Brasil, e "copiar número, abrir WhatsApp,
--     colar" é o atrito que faz o dono usar a agenda do celular;
--  2. conta a pagar aponta para o fornecedor (contas_pagar.contato_id),
--     então "de quem é essa conta de R$ 800?" tem resposta;
--  3. o contador entra aqui com categoria própria — é para ele que o
--     Plano Pro gera o espelho e a planilha todo mês.

create table if not exists public.contatos (
  id         uuid primary key default gen_random_uuid(),
  empresa_id uuid not null references public.empresas(id) on delete cascade,

  nome       text not null,
  -- Razão social, quando diferente do apelido pelo qual se conhece.
  -- "Distribuidora Sol" no dia a dia, "Sol Comércio de Alimentos LTDA"
  -- na nota fiscal.
  razao_social text,

  -- fornecedor | contador | cliente | servico | banco | outro
  -- Texto e não enum: adicionar valor a um enum exige migração.
  categoria  text not null default 'fornecedor',

  documento  text,           -- CNPJ ou CPF, só dígitos
  telefone   text,           -- vira link de WhatsApp
  telefone2  text,           -- fixo, ou o do vendedor que atende
  email      text,
  site       text,

  endereco   text,
  cidade     text,
  uf         text,

  -- O que ESTE fornecedor traz. É o campo que responde "quem entrega
  -- pão?" sem abrir um por um.
  fornece    text,

  -- "toda terça e sexta", "dia 10". Texto livre de propósito: cada
  -- fornecedor combina de um jeito, e um seletor de dias da semana não
  -- cobre "quinzenal" nem "sob encomenda".
  entrega    text,
  prazo_pagamento text,      -- "28 dias", "à vista", "boleto 30/60"

  observacoes text,

  favorito   boolean not null default false,
  ativo      boolean not null default true,

  criado_em    timestamptz not null default now(),
  atualizado_em timestamptz
);

-- A lista padrão: ativos, favoritos no topo, alfabética.
create index if not exists idx_contatos_empresa
  on public.contatos (empresa_id, favorito desc, nome);

create index if not exists idx_contatos_categoria
  on public.contatos (empresa_id, categoria);

alter table public.contatos enable row level security;

-- De quem é a conta. on delete set null: apagar um fornecedor não pode
-- apagar o histórico financeiro — a conta foi paga de qualquer jeito, e
-- é ela que fecha o caixa do mês.
alter table public.contas_pagar
  add column if not exists contato_id uuid references public.contatos(id) on delete set null;

create index if not exists idx_contas_contato
  on public.contas_pagar (contato_id) where contato_id is not null;

comment on table  public.contatos is
  'Agenda do negócio: fornecedor, contador, prestador. O telefone vira link de WhatsApp.';
comment on column public.contas_pagar.contato_id is
  'De quem é a conta. Nulo em conta sem fornecedor definido.';
