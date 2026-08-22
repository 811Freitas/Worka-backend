-- 030 — Plano Master: chatbot no canal que já existe
--
-- O Master é o Pro mais o chatbot. "Mais", não "outro": quem assina
-- Master continua com espelho de ponto, banco de horas e API — por
-- isso planoAvancado() passa a valer para os dois, e não virou uma
-- terceira trilha de permissão que teria que ser lembrada em cada
-- rota nova.
--
-- QUAL CANAL. O chatbot não inventa um canal novo: ele atende no chat
-- interno que o Workap já tem. Quando o funcionário escreve para a
-- Administração (destinatario_id nulo), o bot responde. É o único
-- canal com autenticação, histórico e notificação push já resolvidos —
-- criar um widget público exigiria refazer os três, e ninguém do
-- WhatsApp entra aqui sem a API deles, que é outro projeto.

-- ════════════════════════════════════════════════════════════
-- 1. O CHATBOT DA EMPRESA
-- ════════════════════════════════════════════════════════════
create table if not exists public.chatbots (
  id            uuid primary key default uuid_generate_v4(),
  empresa_id    uuid not null unique references public.empresas(id) on delete cascade,
  nome          text not null default 'Assistente',
  ativo         boolean not null default false,
  -- Primeira coisa que a pessoa lê. Sem ela o bot responderia do nada,
  -- e quem mandou "oi" para o dono levaria um susto.
  boas_vindas   text not null default 'Olá! Sou o assistente da equipe. Escolha uma opção pelo número:',
  -- Quando nada casa. Sem esta saída o bot fica mudo e a pessoa acha
  -- que a mensagem não chegou a ninguém.
  fallback      text not null default 'Não entendi. Digite *menu* para ver as opções, ou espere que alguém da administração responde.',
  criado_em     timestamptz not null default now(),
  atualizado_em timestamptz not null default now()
);

alter table public.chatbots enable row level security;

comment on table public.chatbots is
  'Um chatbot por empresa. Atende no chat interno, quando alguém escreve para a Administração.';

-- ════════════════════════════════════════════════════════════
-- 2. O QUE O BOT SABE RESPONDER
-- ════════════════════════════════════════════════════════════
-- Opção de menu e gatilho por palavra-chave na MESMA tabela, separados
-- por `tipo`. As duas coisas são "um jeito de casar com o que a pessoa
-- escreveu, e uma resposta" — duas tabelas seriam a mesma estrutura
-- duplicada, e toda consulta de atendimento teria que ler as duas e
-- juntar na mão.
create table if not exists public.chatbot_itens (
  id          uuid primary key default uuid_generate_v4(),
  chatbot_id  uuid not null references public.chatbots(id) on delete cascade,
  empresa_id  uuid not null references public.empresas(id) on delete cascade,
  tipo        text not null check (tipo in ('opcao','gatilho')),
  -- opcao:   o texto que aparece no menu numerado
  -- gatilho: rótulo interno, só para o dono se achar na lista
  rotulo      text not null,
  -- Só para gatilho: as palavras que disparam, separadas por vírgula.
  palavras    text,
  resposta    text not null,
  ordem       integer not null default 0,
  ativo       boolean not null default true,
  criado_em   timestamptz not null default now()
);

create index if not exists idx_chatbot_itens_bot
  on public.chatbot_itens (chatbot_id, tipo, ordem);

create index if not exists idx_chatbot_itens_empresa
  on public.chatbot_itens (empresa_id);

alter table public.chatbot_itens enable row level security;

comment on column public.chatbot_itens.tipo is
  'opcao = item do menu numerado; gatilho = responde quando a mensagem contém uma das palavras.';

-- ════════════════════════════════════════════════════════════
-- 3. O QUE O BOT JÁ RESPONDEU
-- ════════════════════════════════════════════════════════════
-- A CONVERSA em si continua na tabela `mensagens` — é o mesmo chat de
-- sempre, e duplicá-la aqui criaria duas versões da mesma história,
-- que é como histórico de conversa começa a divergir.
--
-- Esta tabela guarda o ATENDIMENTO: o que a pessoa perguntou, qual
-- item casou e o que o bot respondeu. É o que responde "por que o bot
-- respondeu isso?" — pergunta impossível de resolver só olhando o chat.
create table if not exists public.chatbot_atendimentos (
  id             uuid primary key default uuid_generate_v4(),
  empresa_id     uuid not null references public.empresas(id) on delete cascade,
  chatbot_id     uuid references public.chatbots(id) on delete cascade,
  funcionario_id uuid references public.funcionarios(id) on delete set null,
  pergunta       text,
  item_id        uuid references public.chatbot_itens(id) on delete set null,
  -- menu | opcao | gatilho | fallback — como a resposta foi escolhida.
  como           text,
  resposta       text,
  criado_em      timestamptz not null default now()
);

create index if not exists idx_chatbot_atend_empresa
  on public.chatbot_atendimentos (empresa_id, criado_em desc);

alter table public.chatbot_atendimentos enable row level security;

comment on table public.chatbot_atendimentos is
  'Cada resposta do bot: o que perguntaram, o que casou e o que respondeu. A conversa fica em mensagens.';

-- ════════════════════════════════════════════════════════════
-- 4. QUAL MENSAGEM DO CHAT VEIO DO BOT
-- ════════════════════════════════════════════════════════════
-- Sem esta coluna, a resposta do bot é indistinguível de uma resposta
-- que o dono digitou — e o funcionário fica sem saber se falou com uma
-- pessoa ou com uma máquina, que é exatamente o que gera desconfiança.
alter table public.mensagens
  add column if not exists por_bot boolean not null default false;

comment on column public.mensagens.por_bot is
  'true quando quem respondeu foi o chatbot, não uma pessoa da administração.';
