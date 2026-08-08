-- ════════════════════════════════════════════════════════════
-- WORKAP — Foto no produto de validade
-- ════════════════════════════════════════════════════════════
-- Rode este SQL uma única vez no projeto Supabase ATIVO
-- ("Worka1" — vtkmqykwyilcdnigaxsr), em: SQL Editor > New query.
-- ════════════════════════════════════════════════════════════

-- Duas colunas em vez de uma, de propósito.
--
-- `foto_thumb` é um quadrado de ~96px que acompanha a lista de
-- produtos; `foto` é a imagem de ~800px, buscada só quando alguém
-- abre um produto específico.
--
-- Guardar uma imagem só e devolvê-la na listagem parece mais simples,
-- mas quebra na primeira loja de verdade: um mercadinho com 200
-- produtos transformaria GET /validade num download de vários
-- megabytes, no 4G do celular do funcionário, toda vez que a tela
-- abrisse. Com a miniatura separada, a lista continua na casa dos
-- kilobytes e a foto grande só trafega quando é pedida.
--
-- As duas guardam data URL ("data:image/jpeg;base64,..."), não um
-- link para arquivo: o Supabase Storage exigiria bucket público (URL
-- adivinhável, foto de estoque de um cliente vazando para fora) ou
-- toda uma camada de URL assinada. Para imagem pequena, a coluna de
-- texto é mais simples e não abre porta nenhuma.
alter table public.produtos_validade
  add column if not exists foto       text,
  add column if not exists foto_thumb text;

comment on column public.produtos_validade.foto is
  'Data URL JPEG (~800px). Nunca incluída na listagem — só em GET /validade/:id/foto.';
comment on column public.produtos_validade.foto_thumb is
  'Data URL JPEG (~96px) exibida na lista e nos alertas.';
