-- 037 — De "responde perguntas" para "atende"
--
-- O que existia até aqui: cada mensagem era respondida SOZINHA, sem
-- saber o que veio antes. A pessoa escreve "quanto custa?", recebe o
-- preço, e emenda "e pra três lojas?" — e essa segunda pergunta chega
-- ao bot sem contexto nenhum, como se fosse a primeira coisa que
-- alguém disse na vida. É o que faz um bot parecer máquina de vender
-- refrigerante: cada moeda é uma transação nova.
--
-- Duas coisas mudam isso, e as duas moram aqui:
--   1. a conversa passa a ter FIO — o bot lê as últimas trocas com
--      aquela mesma pessoa antes de responder;
--   2. o bot passa a poder CONSULTAR, em vez de só recitar: olhar o
--      estoque da empresa, e chamar um humano quando não resolve.

-- ════════════════════════════════════════════════════════════
-- 1. O FIO DA CONVERSA
-- ════════════════════════════════════════════════════════════
-- `contato` já existia, mas guarda "Maria Cliente · 5511999998888" —
-- e o nome do perfil MUDA quando a pessoa troca o nome no WhatsApp.
-- Agrupar por ele quebraria o histórico no meio da conversa, do nada.
--
-- Esta coluna guarda só o identificador estável (o endereço de onde a
-- mensagem veio). É por ele que o histórico é buscado.
alter table public.chatbot_atendimentos
  add column if not exists contato_chave text;

-- O índice é o que torna a busca do histórico barata: ela acontece
-- em TODA mensagem recebida, e sem ele viraria varredura da tabela
-- inteira a cada "oi".
create index if not exists idx_chatbot_atend_fio
  on public.chatbot_atendimentos (chatbot_id, contato_chave, criado_em desc);

comment on column public.chatbot_atendimentos.contato_chave is
  'Identificador estável de quem escreveu. É por ele que o histórico da conversa é montado — `contato` tem o nome do perfil, que muda.';

-- ════════════════════════════════════════════════════════════
-- 2. O BOT PODE CONSULTAR
-- ════════════════════════════════════════════════════════════
-- Desligável, e o padrão é ligado. Existe porque nem todo dono quer o
-- bot falando de estoque com cliente — e porque cada consulta é uma
-- ida a mais ao modelo, que custa.
--
-- IMPORTANTE, e vale escrever: as ferramentas são de LEITURA e de
-- pedido de ajuda. O bot não dá baixa em estoque, não cadastra, não
-- apaga. Quem conversa com ele é um desconhecido do outro lado do
-- WhatsApp — e a superfície que um desconhecido alcança tem que ser a
-- menor possível.
alter table public.chatbots
  add column if not exists usa_ferramentas boolean not null default true;

comment on column public.chatbots.usa_ferramentas is
  'Ligado, o bot pode consultar o estoque e chamar um humano. Só leitura — nunca escreve nos dados da empresa.';
