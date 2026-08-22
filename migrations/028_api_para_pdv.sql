-- 028 — API do cliente: integrar o Workap com PDV ou sistema de estoque
--
-- O plano Pro vendia "acessar API" como permissão de cargo, e API
-- nenhuma existia. Isto é a API de verdade.
--
-- UNIVERSAL quer dizer duas decisões concretas:
--
-- 1) O produto é endereçado pelo CÓDIGO DO CLIENTE, não pelo nosso
--    uuid. O PDV da loja já conhece o produto por um código de barras
--    ou um SKU próprio; exigir que ele guarde e mapeie um uuid nosso
--    obrigaria cada integração a manter uma tabela de-para. Com
--    `codigo`, quem integra manda o que já tem na mão.
--
-- 2) Toda mudança de estoque passa por um lançamento (movimentos_estoque)
--    com uma REFERÊNCIA do sistema de origem — o número do cupom, o id
--    da venda. É o que impede o erro clássico de integração: a rede cai
--    depois que o servidor gravou, o PDV não recebe resposta, reenvia a
--    mesma venda, e o estoque baixa duas vezes. Com a referência única,
--    o reenvio devolve o mesmo resultado sem descontar de novo.

-- ════════════════════════════════════════════════════════════
-- 1. CÓDIGO DO PRODUTO NO SISTEMA DO CLIENTE
-- ════════════════════════════════════════════════════════════
alter table public.produtos_validade
  add column if not exists codigo text;

comment on column public.produtos_validade.codigo is
  'Código do produto no sistema do cliente (SKU, código de barras). É por ele que a API encontra o produto.';

-- Único por empresa, e só quando preenchido: quem não integra continua
-- cadastrando produto sem código nenhum. Sem o unique, dois produtos
-- com o mesmo código fariam a baixa de estoque acertar o errado.
create unique index if not exists idx_produtos_codigo_empresa
  on public.produtos_validade (empresa_id, codigo)
  where codigo is not null;

-- ════════════════════════════════════════════════════════════
-- 2. CHAVES DE API
-- ════════════════════════════════════════════════════════════
create table if not exists public.chaves_api (
  id            uuid primary key default uuid_generate_v4(),
  empresa_id    uuid not null references public.empresas(id) on delete cascade,
  nome          text not null,
  -- Só o hash. A chave em texto aparece UMA vez, na hora de criar, e
  -- some. Guardar o texto seria guardar a senha do cliente em claro:
  -- quem lesse o banco entraria no estoque de todas as lojas.
  chave_hash    text not null unique,
  -- Os primeiros caracteres, para a pessoa reconhecer qual chave é qual
  -- na tela sem que isso sirva para autenticar.
  prefixo       text not null,
  -- Chave só de leitura é o padrão seguro para dashboard e BI; a de
  -- escrita é a que o PDV usa para dar baixa.
  escrita       boolean not null default false,
  ultimo_uso    timestamptz,
  usos          bigint not null default 0,
  revogada_em   timestamptz,
  criada_em     timestamptz not null default now()
);

create index if not exists idx_chaves_empresa
  on public.chaves_api (empresa_id, criada_em desc);

-- A busca do caminho quente (toda requisição da API) é por hash, e só
-- interessa chave viva.
create index if not exists idx_chaves_hash_ativa
  on public.chaves_api (chave_hash) where revogada_em is null;

alter table public.chaves_api enable row level security;

comment on table public.chaves_api is
  'Chaves que o cliente gera para integrar o PDV/estoque dele. Guardadas como hash — o texto aparece uma vez só.';

-- ════════════════════════════════════════════════════════════
-- 3. LANÇAMENTOS DE ESTOQUE
-- ════════════════════════════════════════════════════════════
create table if not exists public.movimentos_estoque (
  id            uuid primary key default uuid_generate_v4(),
  empresa_id    uuid not null references public.empresas(id) on delete cascade,
  produto_id    uuid not null references public.produtos_validade(id) on delete cascade,
  tipo          text not null check (tipo in ('entrada','saida','ajuste')),
  quantidade    numeric not null,
  -- O saldo depois do lançamento fica gravado na linha. Sem isso,
  -- explicar "por que o estoque está em 7" exige somar a tabela inteira
  -- e torcer para nenhum lançamento ter sido apagado.
  saldo_depois  numeric not null,
  origem        text not null default 'api',
  chave_api_id  uuid references public.chaves_api(id) on delete set null,
  -- A referência do sistema de origem (nº do cupom, id da venda).
  referencia    text,
  observacao    text,
  criado_em     timestamptz not null default now()
);

create index if not exists idx_movimentos_produto
  on public.movimentos_estoque (produto_id, criado_em desc);

create index if not exists idx_movimentos_empresa
  on public.movimentos_estoque (empresa_id, criado_em desc);

-- O coração da proteção contra baixa dupla: a mesma referência não
-- entra duas vezes na mesma empresa. Parcial porque lançamento feito
-- na mão pelo app não tem referência, e vários nulos violariam um
-- unique comum.
create unique index if not exists idx_movimentos_referencia
  on public.movimentos_estoque (empresa_id, referencia)
  where referencia is not null;

alter table public.movimentos_estoque enable row level security;

comment on table public.movimentos_estoque is
  'Extrato do estoque. Cada linha diz quanto entrou ou saiu, quem mandou e qual o saldo depois.';

-- ════════════════════════════════════════════════════════════
-- 4. MOVIMENTAR ESTOQUE — ATÔMICO E IDEMPOTENTE
-- ════════════════════════════════════════════════════════════
-- Por que isto é uma função no banco e não código no servidor:
--
-- Ler a quantidade, somar e gravar de volta em três chamadas separadas
-- tem uma corrida. Dois caixas vendendo o mesmo produto no mesmo
-- segundo leem 10, cada um calcula 9, e os dois gravam 9 — vendeu duas
-- unidades e o estoque baixou uma. Numa loja parada isso nunca
-- aparece; num sábado à tarde acontece o tempo todo, e o erro é
-- invisível até alguém contar a prateleira.
--
-- Dentro da função o `for update` segura a linha do produto até o fim
-- da transação, então o segundo caixa espera, lê 9 e grava 8. A leitura,
-- a conta e a gravação viram uma coisa só.
create or replace function public.api_movimentar_estoque(
  p_empresa_id   uuid,
  p_codigo       text,
  p_tipo         text,
  p_quantidade   numeric,
  p_referencia   text default null,
  p_observacao   text default null,
  p_chave_id     uuid default null,
  p_permitir_negativo boolean default false
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_produto  public.produtos_validade%rowtype;
  v_existente public.movimentos_estoque%rowtype;
  v_novo_saldo numeric;
  v_mov_id   uuid;
begin
  if p_tipo not in ('entrada','saida','ajuste') then
    return jsonb_build_object('ok', false, 'erro', 'tipo_invalido');
  end if;
  if p_quantidade is null or (p_tipo <> 'ajuste' and p_quantidade <= 0) then
    return jsonb_build_object('ok', false, 'erro', 'quantidade_invalida');
  end if;

  -- Reenvio: mesma referência, mesma empresa. Devolve o resultado de
  -- antes em vez de descontar de novo, e avisa que foi repetido para
  -- quem integra conseguir distinguir nos logs.
  if p_referencia is not null then
    select * into v_existente
      from public.movimentos_estoque
     where empresa_id = p_empresa_id and referencia = p_referencia
     limit 1;
    if found then
      return jsonb_build_object(
        'ok', true, 'repetido', true,
        'movimento_id', v_existente.id,
        'saldo', v_existente.saldo_depois
      );
    end if;
  end if;

  -- Segura a linha do produto até o commit.
  select * into v_produto
    from public.produtos_validade
   where empresa_id = p_empresa_id and codigo = p_codigo
   for update;

  if not found then
    return jsonb_build_object('ok', false, 'erro', 'produto_nao_encontrado');
  end if;

  v_novo_saldo := case p_tipo
    when 'entrada' then coalesce(v_produto.quantidade, 0) + p_quantidade
    when 'saida'   then coalesce(v_produto.quantidade, 0) - p_quantidade
    else p_quantidade                       -- ajuste: define o valor
  end;

  -- Estoque negativo em geral é erro de cadastro, não venda real. Mas
  -- quem começa a integrar no meio do expediente tem o Workap
  -- desatualizado, e recusar a venda do PDV por causa disso trava o
  -- caixa da loja. Por isso a escolha fica com quem chama.
  if v_novo_saldo < 0 and not p_permitir_negativo then
    return jsonb_build_object(
      'ok', false, 'erro', 'saldo_insuficiente',
      'saldo', coalesce(v_produto.quantidade, 0), 'pedido', p_quantidade
    );
  end if;

  insert into public.movimentos_estoque
    (empresa_id, produto_id, tipo, quantidade, saldo_depois, origem,
     chave_api_id, referencia, observacao)
  values
    (p_empresa_id, v_produto.id, p_tipo, p_quantidade, v_novo_saldo, 'api',
     p_chave_id, p_referencia, p_observacao)
  returning id into v_mov_id;

  update public.produtos_validade
     set quantidade = v_novo_saldo
   where id = v_produto.id;

  return jsonb_build_object(
    'ok', true, 'repetido', false,
    'movimento_id', v_mov_id,
    'produto_id', v_produto.id,
    'produto', v_produto.nome,
    'saldo', v_novo_saldo
  );
end;
$$;

-- security definer roda como dona da função, então precisa ser
-- inalcançável por quem não passou pelo servidor. anon e authenticated
-- não chamam; só a service key do backend, que já valida a chave de API
-- e de qual empresa ela é.
revoke all on function public.api_movimentar_estoque(uuid,text,text,numeric,text,text,uuid,boolean) from public, anon, authenticated;

comment on function public.api_movimentar_estoque is
  'Movimenta estoque em uma transação só: trava o produto, aplica idempotência por referência e grava o extrato.';
