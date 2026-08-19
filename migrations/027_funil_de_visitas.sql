-- 027 — Funil: quem chega no site e onde desiste
--
-- A pergunta que isto responde é a que decide o dinheiro de anúncio:
-- "de cada 100 que entram no site, quantos viram cliente — e em que
-- passo eu perco os outros?".
--
-- Hoje o painel do owner só sabe contar quem TERMINOU o cadastro. Quem
-- abriu o site e foi embora, ou parou no meio do formulário, não
-- aparece em lugar nenhum — e é justamente quem custou dinheiro no
-- anúncio.
--
-- ═══ PRIVACIDADE ═══
--
-- NÃO guarda o IP. Guarda um HASH dele (sha256 com o segredo do
-- servidor como sal). Isso permite CONTAR pessoas distintas sem
-- guardar quem elas são — que é exatamente o necessário aqui e nada
-- além. Um IP é dado pessoal sob a LGPD; um hash com sal secreto não
-- volta a ser IP nem para quem tem o banco.
--
-- O unique (dia, etapa, ip_hash) é o que faz a conta ser de PESSOAS e
-- não de cliques: a mesma pessoa recarregando a página cinco vezes
-- conta uma.

create table if not exists public.visitas_funil (
  id        uuid primary key default gen_random_uuid(),

  dia       date not null default current_date,

  -- visita | abriu_cadastro | preencheu_dados | pediu_codigo | criou_conta
  --
  -- As cinco etapas ficam na MESMA tabela de propósito. Calcular as
  -- duas últimas a partir de `empresas` e `codigos_verificacao` daria
  -- números com semântica diferente das três primeiras (retenção
  -- diferente, limpeza diferente) — e um funil onde cada linha é
  -- contada de um jeito não serve para comparar uma linha com a outra.
  etapa     text not null,

  ip_hash   text not null,

  -- De qual anúncio veio, quando veio de um. Mesmas colunas que
  -- `empresas` já usa, para dar para cruzar "campanha X trouxe 40
  -- visitas e 2 clientes".
  utm_source   text,
  utm_campaign text,

  criado_em timestamptz not null default now(),

  unique (dia, etapa, ip_hash)
);

-- A consulta é sempre "as etapas dos últimos N dias".
create index if not exists idx_visitas_funil_dia
  on public.visitas_funil (dia desc, etapa);

alter table public.visitas_funil enable row level security;

comment on table public.visitas_funil is
  'Funil do site por dia. Guarda hash do IP, nunca o IP — conta pessoas sem identificar.';
comment on column public.visitas_funil.ip_hash is
  'sha256(ip + segredo do servidor). Não reversível. Serve só para não contar a mesma pessoa duas vezes.';
