-- 029 — iFood: o pedido que entra vira tarefa da equipe
--
-- O que o Workap acrescenta ao aviso que o próprio app do iFood já dá:
-- a tarefa tem RESPONSÁVEL, tem prazo, fica na mesma lista de tudo que
-- a equipe faz no dia, e — opcionalmente — só fecha com FOTO do pedido
-- embalado. Item errado e item faltando são a reclamação número um de
-- delivery, e a foto é o que resolve a discussão depois.
--
-- ATENÇÃO ao pré-requisito de negócio: o iFood exige homologação antes
-- de qualquer loja real conectar (conta CNPJ no portal do
-- desenvolvedor, app pronto e uma validação agendada com eles). Este
-- código fica pronto e testável por dentro, mas não recebe pedido de
-- verdade enquanto essa aprovação não sair.

-- ════════════════════════════════════════════════════════════
-- 1. QUAL LOJA DO IFOOD É DE QUEM
-- ════════════════════════════════════════════════════════════
alter table public.empresas
  add column if not exists ifood_merchant_id text,
  -- Exigir a foto do pedido embalado é escolha de cada dono: numa
  -- pizzaria com dois funcionários isso atrasa a saída; numa operação
  -- com quatro entregadores é o que evita o pedido trocado.
  add column if not exists ifood_exigir_foto boolean not null default false,
  add column if not exists ifood_ligado_em timestamptz;

comment on column public.empresas.ifood_merchant_id is
  'Id da loja no iFood (merchantId). É por ele que o webhook descobre de quem é o pedido.';

-- Único: dois cadastros com o mesmo merchantId fariam o pedido de uma
-- loja virar tarefa na equipe de outra empresa.
create unique index if not exists idx_empresas_ifood_merchant
  on public.empresas (ifood_merchant_id)
  where ifood_merchant_id is not null;

-- ════════════════════════════════════════════════════════════
-- 2. EVENTOS RECEBIDOS
-- ════════════════════════════════════════════════════════════
-- Existe por dois motivos, e o segundo é o que salva a operação:
--
-- 1) Idempotência. O iFood reenvia o evento quando não recebe 2xx
--    rápido o bastante. Sem a trava, um pedido viraria três tarefas
--    iguais e a cozinha faria o prato três vezes.
--
-- 2) Diagnóstico. Guardamos o corpo cru. No dia em que o formato deles
--    mudar — e muda — a diferença entre "está quebrado, não sei por
--    quê" e "chegou este JSON aqui" é ter guardado o que chegou.
create table if not exists public.ifood_eventos (
  id           uuid primary key default uuid_generate_v4(),
  evento_id    text not null,
  empresa_id   uuid references public.empresas(id) on delete cascade,
  merchant_id  text,
  order_id     text,
  full_code    text,
  tarefa_id    uuid references public.tarefas(id) on delete set null,
  situacao     text not null default 'recebido',
  detalhe      text,
  corpo        jsonb,
  recebido_em  timestamptz not null default now()
);

-- O mesmo evento não entra duas vezes. É a trava da idempotência.
create unique index if not exists idx_ifood_evento_unico
  on public.ifood_eventos (evento_id);

create index if not exists idx_ifood_eventos_empresa
  on public.ifood_eventos (empresa_id, recebido_em desc);

alter table public.ifood_eventos enable row level security;

comment on table public.ifood_eventos is
  'Tudo que o iFood mandou: trava a repetição e guarda o corpo cru para quando o formato deles mudar.';
