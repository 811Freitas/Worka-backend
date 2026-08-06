-- ════════════════════════════════════════════════════════════
-- WORKAP — Configuração da plataforma e integração com a Utmify
-- ════════════════════════════════════════════════════════════
-- Rode este SQL uma única vez no projeto Supabase ATIVO
-- ("Worka1" — vtkmqykwyilcdnigaxsr), em: SQL Editor > New query.
--
-- Duas tabelas:
--
-- 1) config_plataforma — guarda ajustes que o owner precisa mudar sem
--    esperar um deploy. Hoje o token da Utmify e o liga/desliga da
--    integração; amanhã qualquer outro. É chave/valor de propósito:
--    uma coluna nova a cada ajuste vira uma migration a cada ajuste.
--
-- 2) utmify_envios — o que foi mandado para a Utmify e o que ela
--    respondeu. Sem isso, uma integração que para de funcionar falha
--    em silêncio: as vendas continuam acontecendo, o rastreio para, e
--    ninguém descobre até o relatório de anúncios não bater.
-- ════════════════════════════════════════════════════════════

create table if not exists public.config_plataforma (
  chave      text primary key,
  valor      text,
  updated_at timestamptz not null default now()
);

create table if not exists public.utmify_envios (
  id             uuid primary key default gen_random_uuid(),

  transaction_id text,
  evento         text not null,          -- waiting_payment | paid
  status_http    integer,
  sucesso        boolean not null default false,

  -- Resposta da Utmify, guardada como texto. Se o formato do payload
  -- estiver errado, é aqui que a mensagem dela aparece — em vez de o
  -- erro sumir num catch.
  resposta       text,
  payload_resumo text,

  created_at     timestamptz not null default now()
);

create index if not exists idx_utmify_envios_data
  on public.utmify_envios (created_at desc);

-- ── Segurança ───────────────────────────────────────────────
-- config_plataforma guarda o token da Utmify. RLS ligado sem policy
-- permissiva: se a chave pública (anon) for usada no navegador por
-- engano, ninguém lê o token pelo frontend.
alter table public.config_plataforma enable row level security;
alter table public.utmify_envios      enable row level security;
