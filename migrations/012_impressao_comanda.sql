-- ════════════════════════════════════════════════════════════
-- WORKAP — Impressão da comanda em impressora térmica
-- ════════════════════════════════════════════════════════════
-- Rode este SQL uma única vez no projeto Supabase ATIVO
-- ("Worka1" — vtkmqykwyilcdnigaxsr), em: SQL Editor > New query.
-- ════════════════════════════════════════════════════════════
--
-- IMPORTANTE — O QUE ISTO É E O QUE NÃO É
--
-- Isto imprime a COMANDA do pedido: o papel que sai na cozinha e vai
-- junto com a entrega, com número do pedido, itens, endereço e forma
-- de pagamento. É exatamente o papel que o iFood imprime.
--
-- NÃO é cupom fiscal. Cupom fiscal no Brasil (NFC-e ou SAT/CF-e) é
-- documento regulado: exige CNPJ com Inscrição Estadual, certificado
-- digital A1/A3, autorização da SEFAZ do estado, XML assinado e regra
-- de contingência quando a SEFAZ cai. Nada disso se resolve com
-- impressão — é integração com o fisco, e sem os requisitos acima o
-- documento simplesmente não existe perante a Receita.
--
-- Por isso a comanda impressa carrega, em letras claras, o aviso de
-- que não tem valor fiscal. Um papel que se parece com cupom fiscal e
-- não é cria problema para o lojista, não para nós.

alter table public.loja_config
  -- Largura do papel. 80mm é o padrão de balcão; 58mm é o das
  -- impressoras pequenas e das portáteis de entregador. A diferença
  -- muda quantos caracteres cabem por linha, então precisa ser
  -- escolha do lojista e não chute nosso.
  add column if not exists impressao_largura text not null default '80',

  -- Linha final da comanda: "Obrigado! Volte sempre", instrução de
  -- troca, telefone do delivery.
  add column if not exists impressao_rodape text,

  -- CNPJ do estabelecimento, se ele quiser identificar a loja no
  -- papel. É informativo — de novo, não torna o papel fiscal.
  add column if not exists impressao_cnpj text,

  -- Abrir a janela de impressão sozinho quando o pedido é aceito.
  -- Só funciona a partir do clique em "Aceitar", porque navegador
  -- nenhum deixa uma página imprimir sem ação da pessoa.
  add column if not exists impressao_auto boolean not null default false,

  -- Quantas vias. Duas é o comum: uma fica na cozinha, outra vai com
  -- o entregador.
  add column if not exists impressao_vias integer not null default 1;

comment on column public.loja_config.impressao_largura is
  'Largura do papel térmico: 58 ou 80 (mm).';
comment on column public.loja_config.impressao_auto is
  'Abre a impressão ao aceitar o pedido. Depende do clique — navegador não imprime sozinho.';
