-- ════════════════════════════════════════════════════════════
-- WORKAP — Erros da plataforma e auditoria de RLS
-- ════════════════════════════════════════════════════════════
-- Rode uma única vez no projeto Supabase ATIVO
-- ("Worka1" — vtkmqykwyilcdnigaxsr), em: SQL Editor > New query.
-- ════════════════════════════════════════════════════════════

-- ── 1. ERROS DA PLATAFORMA ──────────────────────────────────
--
-- Hoje todo erro de rota, falha de e-mail e falha de PIX vai só para o
-- console. Isso quer dizer três coisas ruins: some quando a Render
-- reinicia, não aparece em lugar nenhum do painel, e quem precisa da
-- informação (o dono da plataforma) teria que abrir o log de deploy
-- para descobrir que o sistema está quebrado.
--
-- `logs_sistema` não serve: ela guarda auditoria de NEGÓCIO por
-- empresa (ponto batido, salário alterado) e exige empresa_id. Erro de
-- plataforma normalmente não tem empresa — o cadastro que falhou nem
-- chegou a criar uma.
create table if not exists public.erros_plataforma (
  id         uuid primary key default gen_random_uuid(),
  ts         timestamptz not null default now(),

  -- 'rota' (500 não tratado), 'email', 'pix', 'banco' ou 'externo'.
  -- Texto livre de propósito: um enum obrigaria migração para cada
  -- categoria nova, e o custo de um valor inesperado aqui é zero.
  tipo       text not null,

  rota       text,
  metodo     text,
  status     integer,
  mensagem   text not null,

  -- Contexto extra já filtrado pelo backend (senha, token e código
  -- nunca chegam aqui — o registrarErro reaproveita a mesma lista de
  -- campos bloqueados do secLog).
  detalhe    jsonb,

  -- Quando dá para saber de quem era a sessão. Sem FK de propósito:
  -- um erro não pode sumir do histórico porque a empresa foi apagada,
  -- e é justamente no cadastro que falha que a empresa não existe.
  empresa_id uuid
);

create index if not exists idx_erros_ts   on public.erros_plataforma (ts desc);
create index if not exists idx_erros_tipo on public.erros_plataforma (tipo, ts desc);

alter table public.erros_plataforma enable row level security;

-- ── 2. AUDITORIA DE RLS ─────────────────────────────────────
--
-- O painel de segurança precisa responder "existe alguma tabela sem
-- RLS?" sem que ninguém tenha que lembrar de conferir na mão. O
-- PostgREST não expõe o catálogo do Postgres, então a checagem vira
-- uma função chamada por RPC.
--
-- SECURITY DEFINER porque ler pg_class exige privilégio que o papel da
-- API não tem. Por isso mesmo o acesso é revogado de todo mundo e
-- concedido só ao service_role: com anon podendo executar, qualquer
-- visitante listaria o esquema inteiro do banco.
create or replace function public.auditoria_rls()
returns table (tabela text, rls_ativo boolean, politicas integer, politicas_abertas integer)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select c.relname::text,
         c.relrowsecurity,
         (select count(*)::int from pg_policy p where p.polrelid = c.oid),
         -- Política cujo USING não é literalmente "false" concede algum
         -- acesso. Contar isso separado é o que diferencia "tem política"
         -- (normal, o deny_all_default que este projeto usa em tudo) de
         -- "tem porta aberta" — que é o que o painel precisa gritar.
         (select count(*)::int from pg_policy p
           where p.polrelid = c.oid
             and coalesce(pg_get_expr(p.polqual, p.polrelid), 'true') <> 'false')
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
   where n.nspname = 'public'
     and c.relkind = 'r'
   order by c.relname;
$$;

revoke all on function public.auditoria_rls() from public;
revoke all on function public.auditoria_rls() from anon;
revoke all on function public.auditoria_rls() from authenticated;
grant execute on function public.auditoria_rls() to service_role;

-- ── 3. LIMPEZA ──────────────────────────────────────────────
-- Erro velho não ajuda ninguém e a tabela cresce sozinha. O backend
-- apaga o que passou de 30 dias de vez em quando; este delete só zera
-- o que já estiver acumulado quando a migração rodar.
delete from public.erros_plataforma where ts < now() - interval '30 days';
