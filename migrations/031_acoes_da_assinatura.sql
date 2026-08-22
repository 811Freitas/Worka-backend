-- 031 — O owner passa a poder agir sobre uma assinatura
--
-- POR QUE ISTO EXISTE. Um cliente pagou e o acesso não abriu. A causa
-- foi o webhook da Cakto não chegar (a tabela eventos_pagamento estava
-- ZERADA desde sempre), e o efeito foi pior do que o defeito: não havia
-- NADA no painel para destravar a conta. O owner via o cliente
-- bloqueado, sabia que ele tinha pago, e a única saída era mexer no
-- banco na mão.
--
-- Um sistema que cobra tem que ter os dois botões: liberar quem pagou e
-- cortar quem foi reembolsado. Sem eles, todo caso fora do trilho vira
-- suporte manual — e caso fora do trilho, num gateway, é rotina.

create table if not exists public.assinatura_acoes (
  id          uuid primary key default uuid_generate_v4(),
  empresa_id  uuid not null references public.empresas(id) on delete cascade,
  -- liberacao  = destravou quem pagou e o webhook não confirmou
  -- reembolso  = devolveu o dinheiro e cortou o acesso
  -- corte      = bloqueou sem devolver (fraude, abuso)
  acao        text not null check (acao in ('liberacao','reembolso','corte')),
  -- Quem mandou. É o e-mail do owner logado, não um uuid: a conta de
  -- owner não é linha da tabela de empresas, e daqui a um ano o que
  -- importa saber é QUEM decidiu, não qual id ele tinha.
  feito_por   text,
  -- Obrigatório na tela. Dinheiro devolvido sem motivo escrito é
  -- discussão garantida três meses depois.
  motivo      text,
  -- Em centavos, como todo dinheiro neste sistema.
  valor_centavos integer,
  -- O estado ANTES, para dar para desfazer no olho se alguém errar.
  status_antes   text,
  status_depois  text,
  criado_em   timestamptz not null default now()
);

create index if not exists idx_assinatura_acoes_empresa
  on public.assinatura_acoes (empresa_id, criado_em desc);

alter table public.assinatura_acoes enable row level security;

comment on table public.assinatura_acoes is
  'Toda vez que o owner liberou, reembolsou ou cortou uma assinatura na mão — com motivo e estado anterior.';

-- Marca a conta reembolsada. Separado do status porque o status conta o
-- ACESSO (ativa, inadimplente, cancelada) e este campo conta o
-- DINHEIRO: uma conta pode ser reembolsada e voltar a assinar depois, e
-- as duas informações precisam conviver.
alter table public.empresas
  add column if not exists reembolsada_em timestamptz;

comment on column public.empresas.reembolsada_em is
  'Quando o último reembolso foi feito. Preenchido não impede voltar a assinar.';
