-- Suporte a pagamento via Cakto. Inerte até CAKTO_CLIENT_ID/SECRET/
-- WEBHOOK_SECRET existirem no ambiente (ver src/config.js) — esta
-- migração só prepara o terreno, não liga nada sozinha.

alter table contas
  add column if not exists cakto_assinatura_id text;

-- Idempotência do webhook: a Cakto pode reenviar o mesmo evento mais de
-- uma vez (rede instável, timeout do lado deles), e o webhook precisa
-- responder rápido — não dá para consultar "já processei isto?" contra
-- a lógica de negócio inteira a cada aviso. Uma chave primária no id do
-- evento faz o BANCO recusar a repetição, como eventos_recebidos já faz
-- para o WhatsApp.
create table if not exists pagamentos_eventos (
  id         text primary key,
  criado_em  timestamptz not null default now()
);
