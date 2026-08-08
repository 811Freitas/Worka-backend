-- ════════════════════════════════════════════════════════════
-- WORKAP — Loja online sem pagamento + fila de pedidos
-- ════════════════════════════════════════════════════════════
-- Rode este SQL uma única vez no projeto Supabase ATIVO
-- ("Worka1" — vtkmqykwyilcdnigaxsr), em: SQL Editor > New query.
-- ════════════════════════════════════════════════════════════
--
-- A ideia: o cliente do estabelecimento monta um carrinho numa página
-- pública e ENVIA O PEDIDO — sem pagar nada ali. O pedido cai numa
-- fila dentro do Workap e é encaminhado para o cargo responsável
-- (entrega, cozinha, balcão). O pagamento acontece na entrega ou na
-- retirada, como já acontece hoje no WhatsApp da maioria desses
-- negócios — só que sem conversa perdida e sem pedido anotado errado.
--
-- Não processar pagamento é decisão de produto, não limitação: tirar o
-- dinheiro do fluxo elimina gateway, taxa, estorno, chargeback e
-- responsabilidade sobre dado de cartão. O ganho para o lojista é o
-- pedido chegar organizado, não o dinheiro entrar por aqui.

-- ── 1. PLANOS ───────────────────────────────────────────────
--
-- `plano` já existia com default 'completo', mas `valor_mensal` ainda
-- guardava 24,90 — preço de duas mudanças atrás. Corrigido para não
-- servir de base a nenhum cálculo errado no painel owner.
alter table public.empresas
  alter column valor_mensal set default 49.99;

update public.empresas
   set valor_mensal = 49.99
 where plano = 'completo' and (valor_mensal is null or valor_mensal = 24.90);

comment on column public.empresas.plano is
  'completo (R$ 49,99) ou pedidos (R$ 89,90 — inclui loja online e fila de pedidos).';

-- ── 2. PREÇO E VITRINE DO ITEM ──────────────────────────────
--
-- Preço em CENTAVOS inteiros. Guardar dinheiro em ponto flutuante
-- transforma 0,10 + 0,20 em 0,30000000000000004 e, somado item a item
-- num carrinho, o total exibido acaba diferente do cobrado.
--
-- `no_catalogo` é opt-in: nada aparece na vitrine sem alguém marcar.
-- Um estoque tem coisa que não se vende (embalagem, material de
-- limpeza, insumo de cozinha), e publicar tudo por padrão exporia isso.
alter table public.produtos_validade
  add column if not exists preco_centavos integer,
  add column if not exists no_catalogo    boolean not null default false,
  add column if not exists descricao      text;

comment on column public.produtos_validade.preco_centavos is
  'Preço de venda em centavos. Fonte da verdade do carrinho — o total nunca vem do navegador.';
comment on column public.produtos_validade.no_catalogo is
  'Se aparece na loja pública. Opt-in: estoque tem item que não se vende.';

create index if not exists idx_produtos_catalogo
  on public.produtos_validade (empresa_id) where no_catalogo = true;

-- ── 3. CONFIGURAÇÃO DA LOJA ─────────────────────────────────
create table if not exists public.loja_config (
  empresa_id  uuid primary key references public.empresas(id) on delete cascade,

  -- Endereço público da loja: workap.com.br/loja/?l=slug
  -- Único no sistema inteiro, porque é o que identifica a loja para
  -- quem chega de fora sem estar logado.
  slug        text not null unique,
  ativa       boolean not null default false,

  nome_exibicao text,
  descricao     text,
  whatsapp      text,
  endereco      text,

  -- Valores em centavos, mesma razão do preço do item.
  taxa_entrega_centavos integer not null default 0,
  pedido_minimo_centavos integer not null default 0,

  aceita_entrega boolean not null default true,
  aceita_retirada boolean not null default true,

  -- Formas de pagamento aceitas NA ENTREGA. É informação para o
  -- entregador levar troco ou maquininha, não cobrança.
  formas_pagamento text[] not null default array['dinheiro','pix','cartao'],

  horario text,
  aviso   text,

  -- Cargo que recebe os pedidos. NULL = só o dono vê, que é o estado
  -- inicial de quem ainda não montou a equipe de entrega.
  cargo_destino uuid references public.cargos(id) on delete set null,

  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- ── 4. PEDIDOS ──────────────────────────────────────────────
create table if not exists public.pedidos (
  id         uuid primary key default gen_random_uuid(),
  empresa_id uuid not null references public.empresas(id) on delete cascade,

  -- Número curto e sequencial POR EMPRESA. O cliente lê "pedido 47" no
  -- telefone; ninguém dita um uuid.
  numero integer not null,

  cliente_nome    text not null,
  cliente_telefone text not null,
  -- Nome do estabelecimento de quem pede — bar, restaurante, mercado
  -- comprando de um distribuidor. Vazio quando é pessoa física.
  cliente_estabelecimento text,

  tipo            text not null default 'entrega',   -- entrega | retirada
  endereco        text,
  forma_pagamento text,                              -- dinheiro | pix | cartao
  troco_para_centavos integer,
  observacoes     text,

  -- Fotografia dos itens no momento do pedido: nome, preço unitário e
  -- quantidade. Guardar só o id do produto faria o histórico mudar
  -- sozinho quando o lojista corrigisse um preço meses depois.
  itens jsonb not null default '[]'::jsonb,

  subtotal_centavos integer not null default 0,
  taxa_centavos     integer not null default 0,
  total_centavos    integer not null default 0,

  -- novo → aceito → em_rota → entregue, ou cancelado a qualquer momento
  status text not null default 'novo',

  cargo_destino  uuid references public.cargos(id) on delete set null,
  funcionario_id uuid references public.funcionarios(id) on delete set null,
  motivo_cancelamento text,

  created_at  timestamptz not null default now(),
  aceito_em   timestamptz,
  entregue_em timestamptz,

  unique (empresa_id, numero)
);

create index if not exists idx_pedidos_empresa_status
  on public.pedidos (empresa_id, status, created_at desc);

-- ── 5. RLS ──────────────────────────────────────────────────
--
-- Ligada e sem policy permissiva, igual às outras tabelas: todo acesso
-- passa pelo backend com a service key, que já filtra por empresa_id.
-- A loja é pública para LER, mas quem lê é o servidor — a chave nunca
-- chega ao navegador de quem está montando o carrinho.
alter table public.loja_config enable row level security;
alter table public.pedidos     enable row level security;
