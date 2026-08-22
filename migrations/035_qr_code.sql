-- 035 — Conectar lendo o QR code, como no WhatsApp Web
--
-- ATENÇÃO, E ESTÁ AQUI PARA QUEM LER O CÓDIGO DAQUI A UM ANO:
-- este caminho NÃO é a API oficial. Ele entra como "dispositivo
-- conectado", do mesmo jeito que o WhatsApp Web, e isso está fora dos
-- termos de uso da Meta. O número pode ser banido, e banimento de
-- número não se reverte. Foi uma decisão explícita do dono da Workap,
-- ciente disso; os dois caminhos oficiais (Cloud API colada na mão e
-- Embedded Signup pelo botão) continuam existindo lado a lado.
--
-- POR QUE UMA TABELA NOVA, e não mais colunas em `chatbots`: a sessão
-- do WhatsApp Web não é configuração, é ESTADO VIVO — chaves de
-- criptografia que mudam a cada mensagem, e que o processo reescreve
-- sozinho o tempo todo. Misturar isso com nome, boas-vindas e menu
-- faria toda salvada da tela disputar linha com o soquete.

create table if not exists public.whatsapp_sessoes (
  id            uuid primary key default uuid_generate_v4(),
  -- Uma sessão por bot. O bot é que tem menu e gatilhos; a sessão é só
  -- o cano por onde ele fala.
  chatbot_id    uuid not null unique references public.chatbots(id) on delete cascade,
  -- Nulo quando é o bot da própria Workap — mesma regra da migração 033.
  empresa_id    uuid references public.empresas(id) on delete cascade,

  -- O estado inteiro do Baileys num campo só: credenciais e chaves de
  -- sessão, serializados com o BufferJSON deles (os valores são
  -- Buffers, e JSON puro os destruiria).
  --
  -- UM CAMPO, e não uma linha por chave, porque cada consulta aqui é
  -- uma requisição HTTPS ao PostgREST: a biblioteca lê e escreve
  -- dezenas de chaves por mensagem recebida, e uma linha por chave
  -- viraria uma tempestade de requisições a cada "oi" que chega.
  estado        jsonb,

  status        text not null default 'desconectado',
  -- O texto do QR atual. Vale cerca de 20 segundos e a biblioteca gera
  -- outro sozinha enquanto ninguém lê — por isso fica aqui e não numa
  -- resposta guardada: a tela busca sempre o mais novo.
  qr            text,
  qr_em         timestamptz,

  -- Qual número acabou conectado. Só para a tela dizer "conectado no
  -- (11) 99999-8888" em vez de um "conectado" que não se confere.
  numero        text,
  conectado_em  timestamptz,
  atualizado_em timestamptz not null default now()
);

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'whatsapp_sessoes_status_check') then
    alter table public.whatsapp_sessoes
      add constraint whatsapp_sessoes_status_check
      check (status in ('desconectado','aguardando_qr','conectando','conectado','banido'));
  end if;
end $$;

create index if not exists idx_whatsapp_sessoes_status
  on public.whatsapp_sessoes (status) where status = 'conectado';

alter table public.whatsapp_sessoes enable row level security;

comment on table public.whatsapp_sessoes is
  'Sessão do WhatsApp Web (QR code). Caminho NÃO oficial — ver o cabeçalho da migração 035.';
comment on column public.whatsapp_sessoes.estado is
  'Credenciais e chaves do Baileys, serializadas com BufferJSON. Segredo: quem tiver isto fala pelo número.';

-- ════════════════════════════════════════════════════════════
-- A ORIGEM GANHA UM TERCEIRO VALOR
-- ════════════════════════════════════════════════════════════
-- manual e embedded são oficiais e falam pela Graph API. qr fala pelo
-- soquete do WhatsApp Web, e não tem webhook nenhum — as mensagens
-- chegam pelo processo, não por requisição HTTP. Quem lê `wa_origem`
-- precisa saber disso.
alter table public.chatbots drop constraint if exists chatbots_wa_origem_check;
alter table public.chatbots
  add constraint chatbots_wa_origem_check
  check (wa_origem in ('manual','embedded','qr'));
