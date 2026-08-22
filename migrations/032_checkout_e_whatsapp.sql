-- 032 — O checkout que cobra o que foi anunciado, e o chatbot no WhatsApp
--
-- Duas coisas na mesma migração porque as duas nasceram do mesmo
-- pedido: "o checkout tem que ser do Workap" e "o chatbot é para o
-- WhatsApp". Uma migração por pedido do dono, não por tabela.

-- ════════════════════════════════════════════════════════════
-- 1. QUAL CUPOM PAGOU MENOS
-- ════════════════════════════════════════════════════════════
-- O cupom era validado, o desconto aparecia na tela e a cobrança saía
-- pelo preço cheio: `cupomAplicado` nunca era enviado ao servidor, e
-- `cupons.usos` nunca subia — o limite de usos, portanto, nunca valia.
--
-- Estas colunas são o que faltava para o desconto ser AUDITÁVEL. Sem
-- elas, uma assinatura de R$ 39,99 num plano de R$ 49,99 é um valor
-- solto que ninguém consegue explicar seis meses depois.
--
-- Por que o desconto vale enquanto a assinatura durar: na Cakto o
-- preço é do PRODUTO, e a recorrência cobra esse preço todo mês. Não
-- existe "só o primeiro mês" sem criar dois produtos e trocar um pelo
-- outro na virada — o que ninguém garante que acontece. Então o
-- desconto é permanente, e a tela passa a dizer isso.
alter table public.empresas
  add column if not exists cupom_codigo text,
  add column if not exists cupom_desconto_centavos integer;

comment on column public.empresas.cupom_codigo is
  'Cupom usado na assinatura. O desconto vale enquanto a assinatura estiver ativa — ver 032.';

-- ════════════════════════════════════════════════════════════
-- 2. O CHATBOT NO WHATSAPP
-- ════════════════════════════════════════════════════════════
-- O motor de decisão (decidirRespostaChatbot) NÃO muda: ele já era uma
-- função pura, que recebe o bot, os itens e o texto e devolve a
-- resposta. O WhatsApp é só mais um canal entrando nela — por isso
-- estas colunas ficam em `chatbots`, e não numa tabela nova que
-- duplicaria nome, boas-vindas e fallback.
--
-- CANAL. 'interno' é o que existe hoje (chat da equipe). 'whatsapp'
-- atende só no número. 'ambos' atende nos dois. O padrão continua
-- 'interno' para nenhuma conta já configurada mudar de comportamento
-- sozinha ao subir esta migração.
alter table public.chatbots
  add column if not exists canal text not null default 'interno',
  -- Credenciais da WhatsApp Cloud API (Meta). São da EMPRESA, não da
  -- Workap: cada cliente conecta o próprio número, porque o número é
  -- que aparece para o cliente final dele.
  add column if not exists wa_phone_number_id text,
  add column if not exists wa_token text,
  add column if not exists wa_app_secret text,
  -- Segredo que o Workap gera e o dono cola no painel da Meta. É por
  -- ele que o handshake de verificação do webhook descobre de QUEM é a
  -- requisição — a Meta não manda nada além dele nessa etapa.
  add column if not exists wa_verify_token text,
  -- Só para mostrar na tela ("conectado ao (11) 99999-9999").
  add column if not exists wa_numero text,
  add column if not exists wa_conectado_em timestamptz,
  add column if not exists wa_ultimo_evento_em timestamptz;

do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'chatbots_canal_check'
  ) then
    alter table public.chatbots
      add constraint chatbots_canal_check
      check (canal in ('interno','whatsapp','ambos'));
  end if;
end $$;

-- O webhook chega SEM token de sessão: quem chama é a Meta. A empresa
-- é encontrada pelo phone_number_id que vem no corpo, e o verify_token
-- no handshake. Os dois precisam ser únicos, senão duas empresas
-- disputariam a mesma mensagem — e um índice único é o que impede isso
-- de acontecer por erro de digitação, não uma checagem no código.
create unique index if not exists idx_chatbots_wa_phone
  on public.chatbots (wa_phone_number_id) where wa_phone_number_id is not null;

create unique index if not exists idx_chatbots_wa_verify
  on public.chatbots (wa_verify_token) where wa_verify_token is not null;

comment on column public.chatbots.canal is
  'interno = chat da equipe; whatsapp = número da empresa; ambos = os dois.';
comment on column public.chatbots.wa_token is
  'Token permanente do usuário de sistema da Meta. NUNCA volta para o navegador — ver GET /chatbot.';

-- ════════════════════════════════════════════════════════════
-- 3. DE ONDE VEIO CADA ATENDIMENTO
-- ════════════════════════════════════════════════════════════
-- Sem o canal, a lista de conversas mistura equipe e cliente final
-- sem distinguir — e "Alguém da equipe" apareceria no lugar do nome de
-- um cliente que escreveu do WhatsApp.
alter table public.chatbot_atendimentos
  add column if not exists canal text not null default 'interno',
  -- Nome do perfil e número de quem escreveu, quando veio do WhatsApp.
  -- funcionario_id continua nulo nesse caso: quem falou não é da casa.
  add column if not exists contato text;

comment on column public.chatbot_atendimentos.contato is
  'Quem escreveu, quando veio do WhatsApp (nome do perfil e número). Nulo no chat interno.';

-- A Meta REENVIA o webhook quando não recebe 200 rápido o bastante, e
-- reenvia a mesma mensagem. Sem uma trava, o cliente recebe a mesma
-- resposta duas ou três vezes — o defeito que faz um bot parecer
-- quebrado.
--
-- A trava é o índice único, não uma checagem no código: entre "já
-- respondi essa?" e "respondi", cabe o reenvio. Aqui o segundo insert
-- simplesmente falha com 23505, e o envio não acontece.
alter table public.chatbot_atendimentos
  add column if not exists wa_message_id text;

create unique index if not exists idx_chatbot_atend_wa_msg
  on public.chatbot_atendimentos (wa_message_id) where wa_message_id is not null;
