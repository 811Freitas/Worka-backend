-- ════════════════════════════════════════════════════════════
-- ZAPFY — Esquema inicial
-- ════════════════════════════════════════════════════════════
-- Rodar com: npm run migrar
--
-- Regra que atravessa o arquivo inteiro: TODA tabela que guarda dado de
-- cliente carrega `conta_id`, e toda consulta do sistema filtra por ele.
-- Não é redundância — é o que separa um cliente do outro. Uma tabela sem
-- `conta_id` (por exemplo, `mensagens` só com `conversa_id`) obrigaria a
-- consulta a fazer JOIN para saber de quem é a linha, e o dia em que
-- alguém esquecesse o JOIN a mensagem de um cliente apareceria no painel
-- de outro. Com a coluna repetida, esquecer o filtro devolve VAZIO, não
-- o dado do vizinho.
-- ════════════════════════════════════════════════════════════

create extension if not exists pgcrypto;


-- ════════════════════════════════════════
-- CONTAS — o inquilino (tenant)
-- ════════════════════════════════════════
-- Uma conta é uma empresa cliente da plataforma. Tudo o que existe no
-- sistema pendura aqui.
create table if not exists contas (
  id            uuid primary key default gen_random_uuid(),
  nome          text not null,

  -- gratis | pro. O plano não trava funcionalidade nesta versão; ele
  -- existe para os limites (LIMITES_PLANO no código) terem onde morar
  -- quando a cobrança entrar. Deixar a coluna para depois significaria
  -- migrar dado de produção para adicionar uma palavra.
  plano         text not null default 'gratis',

  -- ativa | suspensa. Suspensa continua logando (para a pessoa ver a
  -- própria conta e regularizar), mas o bot para de responder — a
  -- suspensão precisa ser visível para o dono da conta, não silenciosa.
  status        text not null default 'ativa',

  criado_em     timestamptz not null default now(),
  atualizado_em timestamptz not null default now()
);


-- ════════════════════════════════════════
-- USUÁRIOS — quem faz login
-- ════════════════════════════════════════
-- Separado de `contas` de propósito. Juntar os dois (uma linha = empresa
-- + login) funciona no primeiro mês e cobra caro depois: quando o
-- cliente quiser dar acesso a um funcionário para atender no chat, não
-- há onde colocar essa pessoa, e o histórico de "quem respondeu esta
-- conversa" fica sem dono. Aqui já nasce certo.
create table if not exists usuarios (
  id             uuid primary key default gen_random_uuid(),
  conta_id       uuid not null references contas(id) on delete cascade,
  nome           text not null,
  email          text not null,

  -- bcrypt, custo 12. Nunca a senha.
  senha_hash     text not null,

  -- dono | operador
  --   dono     — configura bot, conecta WhatsApp, vê tudo
  --   operador — atende conversas e vê histórico, não mexe na conexão
  papel          text not null default 'dono',

  ativo          boolean not null default true,
  ultimo_login_em timestamptz,
  criado_em      timestamptz not null default now()
);

-- E-mail é a identidade do login: precisa ser único no sistema INTEIRO,
-- não por conta. Índice em lower() porque "Joao@x.com" e "joao@x.com"
-- são a mesma pessoa — sem isso, dois cadastros com a mesma caixa de
-- e-mail conviveriam e o "esqueci a senha" mandaria o código para a
-- conta errada.
create unique index if not exists idx_usuarios_email on usuarios (lower(email));
create index if not exists idx_usuarios_conta on usuarios (conta_id);


-- ════════════════════════════════════════
-- CONEXÕES DE WHATSAPP
-- ════════════════════════════════════════
-- Uma conexão = um número de WhatsApp ligado à API oficial da Meta
-- (Cloud API). Uma por conta.
--
-- Por que Cloud API e não QR Code: o QR Code (Baileys / whatsapp-web.js)
-- exige um socket VIVO por cliente dentro do servidor. Com 200 clientes
-- são 200 sockets, e qualquer deploy, reinício ou queda derruba os 200
-- ao mesmo tempo — cada um precisando de um QR Code novo, lido a mão,
-- pelo cliente. Além do risco real de banimento do número.
--
-- Na Cloud API quem guarda a sessão é a Meta. O servidor só recebe
-- webhook e responde por HTTP. Reiniciar o processo não desconecta
-- ninguém: é isso que faz o "24/7" ser verdade em vez de promessa.
create table if not exists conexoes (
  id                uuid primary key default gen_random_uuid(),
  conta_id          uuid not null unique references contas(id) on delete cascade,

  -- Hoje só 'cloud_api'. A coluna existe para o dia em que entrar um
  -- segundo provedor: o motor do bot não sabe qual é, e é assim que ele
  -- continua não sabendo.
  provedor          text not null default 'cloud_api',

  -- Identificadores que a Meta dá ao cliente no painel do Business.
  phone_number_id   text,
  waba_id           text,
  numero_exibicao   text,
  nome_exibicao     text,

  -- Token permanente e app secret, cifrados em AES-256-GCM (lib/cripto).
  -- Em texto puro, um SELECT vazado no banco daria a quem lesse o poder
  -- de mandar mensagem em nome de todos os clientes da plataforma.
  token_cifrado     text,
  app_secret_cifrado text,

  -- Segredo do handshake do webhook. É a Meta que o envia de volta em
  -- `hub.verify_token` na hora de validar a URL — e como a URL é a mesma
  -- para todos os clientes, é POR ESTE VALOR que descobrimos de qual
  -- conta é o webhook sendo verificado. Daí ser único.
  verify_token      text not null unique,

  -- desconectado | aguardando_webhook | conectado | pausado | erro
  --
  -- 'pausado' é diferente de 'desconectado': pausado mantém as
  -- credenciais e continua RECEBENDO (a mensagem entra no histórico),
  -- só não responde. É o botão de "cala o bot agora" quando o cliente
  -- vai atender na mão, sem que ele perca a conexão e tenha que refazer
  -- tudo na Meta depois.
  status            text not null default 'desconectado',

  ultimo_erro       text,
  ultimo_erro_em    timestamptz,

  -- Última vez que o monitor confirmou, contra a Meta, que o token
  -- ainda vale. É a diferença entre "estava conectado quando você
  -- configurou" e "está conectado agora".
  verificado_em     timestamptz,
  conectado_em      timestamptz,

  -- Quando a Meta validou a URL do webhook.
  --
  -- Separado do `status` porque são duas metades independentes da
  -- conexão: as credenciais dizem se conseguimos ENVIAR, o webhook diz
  -- se conseguimos RECEBER. Sem esta coluna, trocar o token de um
  -- cliente que já tinha o webhook validado o jogaria de volta para
  -- "aguardando webhook" — e ele ficaria preso ali para sempre, porque
  -- a Meta só chama o GET de verificação quando a URL muda.
  webhook_verificado_em timestamptz,

  total_enviadas    bigint not null default 0,
  total_recebidas   bigint not null default 0,

  criado_em         timestamptz not null default now(),
  atualizado_em     timestamptz not null default now()
);

-- O webhook chega dizendo apenas para qual phone_number_id a mensagem
-- foi. Esta é a busca do caminho quente — roda em toda mensagem que
-- entra, de todos os clientes.
create unique index if not exists idx_conexoes_phone on conexoes (phone_number_id)
  where phone_number_id is not null;


-- ════════════════════════════════════════
-- BOTS
-- ════════════════════════════════════════
create table if not exists bots (
  id                    uuid primary key default gen_random_uuid(),
  conta_id              uuid not null references contas(id) on delete cascade,
  nome                  text not null default 'Meu atendimento',

  ativo                 boolean not null default true,

  -- As quatro falas que o cliente edita sem entender de fluxo nenhum.
  -- Ficam aqui, e não como blocos, porque não são um passo da conversa:
  -- são o comportamento do bot quando algo acontece.
  mensagem_boas_vindas  text not null default 'Olá! 👋 Sou o assistente virtual. Como posso ajudar?',
  mensagem_fallback     text not null default 'Não entendi. Escolha uma das opções abaixo:',
  mensagem_fora_horario text not null default 'Estamos fora do horário de atendimento. Deixe sua mensagem que respondemos assim que abrirmos.',
  mensagem_transbordo   text not null default 'Certo! Vou chamar um atendente. Aguarde um instante. 🙂',

  -- Horário de atendimento. Quando desligado, o bot responde 24h — que
  -- é o padrão de propósito: o motivo de existir um bot é justamente
  -- responder quando não tem ninguém.
  atendimento_ativo     boolean not null default false,
  atendimento_inicio    time not null default '08:00',
  atendimento_fim       time not null default '18:00',
  -- 0=domingo ... 6=sábado. Segunda a sexta por padrão.
  atendimento_dias      int[] not null default '{1,2,3,4,5}',
  -- Fuso do cliente. Guardado como nome IANA porque offset fixo erra no
  -- horário de verão — e um bot que erra o horário de atendimento duas
  -- vezes por ano é um bot que ninguém confia.
  fuso                  text not null default 'America/Sao_Paulo',

  -- Depois de quanto tempo parado a conversa recomeça do zero. Sem
  -- isso, quem voltasse três dias depois cairia no meio do menu antigo,
  -- sem contexto nenhum, e responderia "3" para uma pergunta que já não
  -- estava na tela.
  expirar_apos_minutos  int not null default 60,

  criado_em             timestamptz not null default now(),
  atualizado_em         timestamptz not null default now()
);

create index if not exists idx_bots_conta on bots (conta_id);

-- Um bot ativo por conta. Índice parcial em vez de unique(conta_id):
-- permite guardar rascunhos e versões antigas desligadas, mas garante
-- que o webhook nunca fique escolhendo entre dois bots ligados.
create unique index if not exists idx_bots_um_ativo on bots (conta_id) where ativo;


-- ════════════════════════════════════════
-- BLOCOS — os nós do fluxo de conversa
-- ════════════════════════════════════════
-- O fluxo é um grafo: cada bloco manda uma mensagem e aponta para o
-- próximo. Guardar como linhas (e não um JSON gigante no bot) é o que
-- permite editar um bloco sem reescrever o fluxo inteiro, e é o que faz
-- "editar o chatbot sem reconectar o WhatsApp" ser trivial: o motor lê
-- os blocos a cada mensagem, então a edição vale na mensagem seguinte.
create table if not exists blocos (
  id            uuid primary key default gen_random_uuid(),
  conta_id      uuid not null references contas(id) on delete cascade,
  bot_id        uuid not null references bots(id) on delete cascade,

  -- Identificador legível ('menu', 'precos', 'horario'). É por ele que
  -- um bloco aponta para o outro, e não pelo uuid, por um motivo
  -- prático: o cliente exporta/duplica o fluxo e os vínculos continuam
  -- fazendo sentido; num dump com uuid, nada é legível nem portável.
  chave         text not null,
  titulo        text not null,

  -- menu     — manda a mensagem e espera o cliente escolher uma opção
  -- texto    — manda a mensagem e segue direto para `proxima_chave`
  -- pergunta — manda a mensagem, GUARDA a resposta em `salvar_em`, segue
  -- humano   — para o bot e chama um atendente (transbordo)
  -- encerrar — despede e fecha a conversa
  tipo          text not null default 'menu',

  mensagem      text not null default '',

  -- Palavras que levam a este bloco de QUALQUER ponto da conversa
  -- ("preço", "valor", "quanto custa"). É o atalho de quem não quer
  -- navegar menu: digita o que quer e chega lá.
  gatilhos      text[] not null default '{}',

  -- Por onde a conversa começa.
  inicial       boolean not null default false,

  -- [{ "rotulo": "Ver preços", "proxima": "precos" }, ...]
  -- jsonb e não tabela filha: opção não tem vida própria fora do bloco,
  -- nunca é consultada isoladamente, e some junto com ele.
  opcoes        jsonb not null default '[]',

  proxima_chave text,
  salvar_em     text,
  ordem         int not null default 0,

  criado_em     timestamptz not null default now(),
  atualizado_em timestamptz not null default now()
);

-- A chave é o endereço do bloco dentro do bot: dois blocos com a mesma
-- chave tornariam "para onde vai a opção 1" uma pergunta sem resposta.
create unique index if not exists idx_blocos_chave on blocos (bot_id, chave);
create index if not exists idx_blocos_bot on blocos (bot_id, ordem);
-- Um único ponto de entrada por bot, pelo mesmo motivo do bot ativo.
create unique index if not exists idx_blocos_um_inicial on blocos (bot_id) where inicial;


-- ════════════════════════════════════════
-- CONTATOS
-- ════════════════════════════════════════
create table if not exists contatos (
  id         uuid primary key default gen_random_uuid(),
  conta_id   uuid not null references contas(id) on delete cascade,

  -- Só dígitos, com DDI (5511987654321). Normalizado na entrada — a
  -- Meta manda neste formato, mas o envio manual pelo painel aceita o
  -- que a pessoa digitar, e sem normalizar o mesmo contato viraria três
  -- linhas diferentes.
  telefone   text not null,

  -- Nome do perfil do WhatsApp, quando a Meta envia.
  nome       text,
  criado_em  timestamptz not null default now()
);

create unique index if not exists idx_contatos_tel on contatos (conta_id, telefone);


-- ════════════════════════════════════════
-- CONVERSAS
-- ════════════════════════════════════════
create table if not exists conversas (
  id                 uuid primary key default gen_random_uuid(),
  conta_id           uuid not null references contas(id) on delete cascade,
  contato_id         uuid not null references contatos(id) on delete cascade,
  bot_id             uuid references bots(id) on delete set null,

  -- Onde a pessoa está no fluxo AGORA. É o estado da conversa, e é por
  -- isso que ele mora no banco e não na memória do processo: um deploy
  -- no meio do atendimento não pode fazer o cliente recomeçar do menu.
  bloco_chave        text,

  -- Respostas guardadas pelos blocos do tipo 'pergunta' — {"nome":"Ana"}.
  -- Usadas na interpolação {{nome}} das mensagens seguintes.
  variaveis          jsonb not null default '{}',

  -- bot | humano | encerrada
  status             text not null default 'bot',

  iniciada_em        timestamptz not null default now(),
  ultima_interacao_em timestamptz not null default now()
);

-- Uma conversa ABERTA por contato. O índice é parcial para que o
-- histórico continue existindo: conversas encerradas se acumulam, e é
-- delas que sai o "histórico de conversas" do painel.
create unique index if not exists idx_conversas_aberta
  on conversas (conta_id, contato_id) where status <> 'encerrada';
create index if not exists idx_conversas_conta on conversas (conta_id, ultima_interacao_em desc);


-- ════════════════════════════════════════
-- MENSAGENS — o histórico
-- ════════════════════════════════════════
create table if not exists mensagens (
  id          uuid primary key default gen_random_uuid(),
  conta_id    uuid not null references contas(id) on delete cascade,
  conversa_id uuid not null references conversas(id) on delete cascade,

  -- entrada (cliente → bot) | saida (bot/atendente → cliente)
  direcao     text not null,

  -- texto | interativa | sistema
  tipo        text not null default 'texto',
  texto       text not null default '',

  -- Corpo cru enviado/recebido, para depurar o que a Meta realmente
  -- viu quando algo não bate com o que o painel mostra.
  payload     jsonb,

  -- ID da mensagem na Meta (wamid...). Guardado nos dois sentidos: na
  -- entrada é o que garante idempotência, na saída é o que permite
  -- casar o recibo de entrega ("status") com a mensagem certa.
  wa_id       text,

  -- pendente | enviada | entregue | lida | falha
  status      text not null default 'enviada',
  erro        text,

  criado_em   timestamptz not null default now()
);

create index if not exists idx_mensagens_conversa on mensagens (conversa_id, criado_em);
create index if not exists idx_mensagens_conta on mensagens (conta_id, criado_em desc);
create index if not exists idx_mensagens_wa on mensagens (wa_id) where wa_id is not null;


-- ════════════════════════════════════════
-- EVENTOS RECEBIDOS — idempotência do webhook
-- ════════════════════════════════════════
-- A Meta REENVIA o webhook quando não recebe 200 rápido o bastante, e
-- reenvia de novo depois. Sem esta tabela, uma lentidão de rede faz o
-- cliente receber a mesma resposta duas ou três vezes — o defeito mais
-- visível e mais constrangedor que um bot pode ter.
--
-- A chave primária é o próprio wamid: inserir duas vezes é violação de
-- unicidade, e é o BANCO quem garante isso, não uma checagem em
-- JavaScript que duas requisições simultâneas passariam juntas.
create table if not exists eventos_recebidos (
  wa_id     text primary key,
  conta_id  uuid references contas(id) on delete cascade,
  criado_em timestamptz not null default now()
);


-- ════════════════════════════════════════
-- REGISTROS — log operacional por cliente
-- ════════════════════════════════════════
-- Diferente do log do servidor: este é o log que o CLIENTE lê, na
-- linguagem dele ("mensagem enviada para 5511...", "token recusado pela
-- Meta"). Sem ele, "meu bot não respondeu" não tem como ser
-- investigado por quem não tem acesso ao servidor — ou seja, por todo
-- mundo que paga.
create table if not exists registros (
  id        uuid primary key default gen_random_uuid(),
  conta_id  uuid not null references contas(id) on delete cascade,

  -- info | aviso | erro
  nivel     text not null default 'info',
  evento    text not null,
  mensagem  text not null default '',
  detalhe   jsonb,
  criado_em timestamptz not null default now()
);

create index if not exists idx_registros_conta on registros (conta_id, criado_em desc);


-- ════════════════════════════════════════
-- NOTIFICAÇÕES — avisos para o dono da conta
-- ════════════════════════════════════════
-- Alimentada pelo monitor de saúde. "O token do seu WhatsApp expirou"
-- precisa chegar ao cliente sem ele ter que abrir a tela de logs por
-- acaso: um bot mudo é indistinguível de um bot sem clientes.
create table if not exists notificacoes (
  id        uuid primary key default gen_random_uuid(),
  conta_id  uuid not null references contas(id) on delete cascade,

  -- conexao_caiu | conexao_voltou | erro_envio | info
  tipo      text not null default 'info',
  titulo    text not null,
  mensagem  text not null default '',
  lida      boolean not null default false,
  criado_em timestamptz not null default now()
);

create index if not exists idx_notificacoes_conta on notificacoes (conta_id, criado_em desc);
create index if not exists idx_notificacoes_nao_lidas on notificacoes (conta_id) where not lida;
