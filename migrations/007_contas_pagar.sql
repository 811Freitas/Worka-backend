-- ════════════════════════════════════════════════════════════
-- WORKAP — Contas a pagar com lembrete automático
-- ════════════════════════════════════════════════════════════
-- Rode este SQL uma única vez no projeto Supabase ATIVO
-- ("Worka1" — vtkmqykwyilcdnigaxsr), em: SQL Editor > New query.
--
-- O sistema já registrava despesa DEPOIS de paga (lancamentos_
-- financeiros). O que faltava era o antes: a conta que vence semana
-- que vem e ninguém lembrou. Esta tabela guarda o compromisso; o
-- lançamento financeiro continua sendo o registro do dinheiro que
-- saiu — são coisas diferentes e ficam separadas de propósito.
--
-- empresa_id nulo = conta da própria Workap (servidor, domínio,
-- gateway), mesma convenção de lancamentos_financeiros.
-- ════════════════════════════════════════════════════════════

create table if not exists public.contas_pagar (
  id            uuid primary key default gen_random_uuid(),
  empresa_id    uuid references public.empresas(id),

  descricao     text not null,
  valor         numeric not null check (valor > 0),
  vencimento    date not null,
  categoria     text default 'despesa_fixa',

  -- 'mensal' faz a conta se repetir: ao marcar como paga, a do mês
  -- seguinte é criada sozinha. Sem isso, aluguel e energia viram
  -- cadastro manual todo mês — e é justamente o que se esquece.
  recorrencia   text not null default 'nenhuma'
                check (recorrencia in ('nenhuma','mensal')),

  status        text not null default 'pendente'
                check (status in ('pendente','paga')),
  pago_em       timestamptz,

  -- Quantos dias antes avisar. Cada conta tem o seu: boleto de água
  -- pede 2 dias, imposto pede 10.
  dias_aviso    integer not null default 3,

  -- Trava para o lembrete sair uma vez só. Sem ela, o job de hora em
  -- hora mandaria o mesmo aviso 24 vezes por dia — e a pessoa
  -- aprenderia a ignorar a notificação do Workap.
  aviso_enviado boolean not null default false,

  -- Lançamento financeiro criado quando a conta foi paga, para dar
  -- para voltar do caixa até a conta que o originou.
  lancamento_id uuid,

  created_at    timestamptz not null default now()
);

-- O job de lembrete varre por vencimento e status a cada hora.
create index if not exists idx_contas_vencimento
  on public.contas_pagar (vencimento, status);

create index if not exists idx_contas_empresa
  on public.contas_pagar (empresa_id, status, vencimento);

-- ── Segurança ───────────────────────────────────────────────
-- O backend usa a service_role key, que ignora RLS. RLS ligado sem
-- policy permissiva: se a chave pública (anon) for usada no navegador
-- por engano, ninguém lê as contas de nenhuma empresa pelo frontend.
alter table public.contas_pagar enable row level security;
