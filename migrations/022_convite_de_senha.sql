-- 022 — Convite de senha de uso único para quem compra por link
--
-- Problema: o link de venda que o dono manda por WhatsApp costuma ir
-- para quem NUNCA usou o Workap. O pagamento entra, mas não existe
-- conta com aquele e-mail — logo, não existe senha, e o cliente não
-- tem como entrar. Ele precisava adivinhar que devia ir ao site se
-- cadastrar, usando o e-mail EXATO digitado na cobrança.
--
-- Solução: junto da cobrança nasce um convite — um endereço próprio
-- que abre o cadastro já sabendo de quem é, de qual plano e por
-- quantos dias. O dono copia e manda junto com o link de pagamento.
--
-- USO ÚNICO: assim que uma conta é criada por ele, o convite é
-- consumido (token_senha_usado_em). Reenviar o mesmo endereço para
-- outra pessoa deixa de funcionar, e um link vazado depois do uso não
-- serve para nada.
--
-- O token NÃO é credencial: criar a conta continua exigindo o código
-- de 6 dígitos enviado ao e-mail. Quem tiver o endereço sem ter a
-- caixa de entrada não passa do primeiro passo. Ele identifica e
-- limita — não autentica.

alter table links_pagamento
  add column if not exists token_senha            text,
  add column if not exists token_senha_usado_em   timestamptz,
  add column if not exists token_senha_expira_em  timestamptz;

-- Único: dois convites com o mesmo token fariam a busca devolver a
-- cobrança errada, e o cliente receberia o plano de outro.
-- Parcial (where not null) porque cobrança avulsa, que não libera
-- plano, não tem convite — e vários nulos violariam um unique comum.
create unique index if not exists idx_links_token_senha
  on links_pagamento (token_senha)
  where token_senha is not null;

comment on column links_pagamento.token_senha is
  'Convite de uso único para criar a senha. Nulo em cobrança que não libera plano.';
comment on column links_pagamento.token_senha_usado_em is
  'Quando a conta foi criada por este convite. Preenchido = convite gasto.';
comment on column links_pagamento.token_senha_expira_em is
  'Prazo do convite. Vencido não abre cadastro, mas o pagamento segue valendo.';
