-- 036 — O bot deixa de exigir a palavra exata
--
-- O DEFEITO QUE ISTO CONSERTA, dito sem rodeio: o motor casava palavra
-- por palavra. O dono cadastrava "horário" e o cliente escrevia "vcs
-- abrem sábado?" — nenhuma palavra em comum, e a resposta era "não
-- entendi". Ninguém consegue prever todo jeito de perguntar a mesma
-- coisa, e é exatamente por isso que bot de menu numerado tem fama de
-- ruim. Em produção, o primeiro bot ligado passou o dia inteiro sem
-- conseguir responder nada.
--
-- A partir daqui o menu continua existindo — quem manda "2" continua
-- recebendo a opção 2, instantâneo e de graça — mas quando NADA casa,
-- em vez do fallback seco, a IA responde lendo o que a empresa
-- escreveu sobre si. O fallback vira o último recurso de verdade:
-- IA sem chave, sem teto, ou fora do ar.

alter table public.chatbots
  -- O texto livre que a empresa escreve sobre ela: horário, preço,
  -- endereço, o que faz, o que não faz. É a ÚNICA fonte da IA.
  --
  -- Uma caixa de texto e não vinte campos: cada campo a mais é um
  -- campo em branco a mais, e um bot que só sabe o que coube no
  -- formulário. Aqui o dono escreve do jeito dele, e o que ele
  -- escrever é o que o cliente recebe.
  add column if not exists contexto text,

  -- Desligável por bot. Existe porque IA custa por mensagem, e há
  -- quem prefira um bot que responde só o menu e cala no resto — o
  -- que é uma escolha legítima, não um defeito.
  add column if not exists usa_ia boolean not null default true;

comment on column public.chatbots.contexto is
  'O que a IA sabe sobre o negócio. Fonte única — ela não inventa fora daqui.';
comment on column public.chatbots.usa_ia is
  'Desligado, o bot só responde menu e gatilhos; o resto cai no fallback.';

-- `como` ganha mais um valor. Não há CHECK na coluna, então isto é só
-- documentação — mas a lista importa para quem lê a tela de conversas:
--   opcao    — respondeu pelo número do menu
--   gatilho  — casou uma palavra-chave
--   menu     — mostrou o menu
--   ia       — a IA respondeu lendo o contexto do negócio
--   fallback — não soube, e disse que não soube
comment on column public.chatbot_atendimentos.como is
  'opcao | gatilho | menu | ia | fallback. Ver a migração 036.';


-- ════════════════════════════════════════════════════════════
-- O TETO DE GASTO PASSA A VALER PARA O BOT DA WORKAP TAMBÉM
-- ════════════════════════════════════════════════════════════
-- `ia_usos.empresa_id` era obrigatório, com chave estrangeira para
-- `empresas`. O bot da plataforma (migração 033) não pertence a
-- empresa nenhuma — então o registro de gasto dele simplesmente
-- falhava, em silêncio, e o teto mensal nunca disparava.
--
-- Justo o bot que mais vai gastar: é ele que atende todo interessado
-- que escreve para a Workap. Sem teto, o custo de IA só apareceria na
-- fatura — que é exatamente o que o teto existe para evitar.
alter table public.ia_usos alter column empresa_id drop not null;

comment on column public.ia_usos.empresa_id is
  'Nulo = uso da própria plataforma (o chatbot da Workap). Ver a migração 036.';
