-- 025 — Convite do funcionário: ele cria a própria senha
--
-- O PROBLEMA que isto resolve:
--
-- Para cadastrar um funcionário, o dono tinha que INVENTAR uma senha
-- para ele e comunicar de algum jeito. Numa padaria com oito pessoas,
-- são oito senhas que o dono cria na mão, escreve num papel e entrega
-- — e que o funcionário não conseguia trocar depois.
--
-- Isso não é atrito de cadastro, é o produto inteiro travado: se o
-- funcionário não entra, ninguém bate ponto; sem ponto, o espelho não
-- tem o que imprimir; e o argumento do Plano Pro ("o que você manda
-- para o contador, pronto") deixa de existir. O teste de 7 dias morre
-- em silêncio, e o dono acha que não gostou do sistema.
--
-- Agora: o dono cadastra só nome e telefone, recebe um link, manda no
-- WhatsApp, e cada um cria a própria senha.
--
-- senha_hash passa a aceitar NULO: é isso que distingue "convidado,
-- ainda não entrou" de "tem conta". A alternativa seria gravar uma
-- senha falsa, que é uma credencial de verdade esperando ser
-- descoberta.

alter table public.funcionarios
  alter column senha_hash drop not null;

alter table public.funcionarios
  add column if not exists token_convite           text,
  add column if not exists token_convite_usado_em  timestamptz,
  add column if not exists token_convite_expira_em timestamptz;

-- Único e parcial, como o convite de senha da cobrança (022): dois
-- funcionários com o mesmo token fariam o link abrir a conta errada.
create unique index if not exists idx_funcionarios_token_convite
  on public.funcionarios (token_convite)
  where token_convite is not null;

-- O e-mail continua obrigatório no banco, mas o cadastro por convite
-- nem sempre tem um: dono de padaria sabe o telefone do ajudante, não
-- o e-mail. Quando não vier, o backend gera um endereço interno
-- (convite-<uuid>@workap.local) que serve de chave e nunca recebe
-- mensagem. Trocar a coluna para nula quebraria o login, que busca
-- por e-mail.

comment on column public.funcionarios.token_convite is
  'Link de uso único para o funcionário criar a própria senha. Nulo depois de usado.';
comment on column public.funcionarios.senha_hash is
  'Nulo = convidado que ainda não criou senha. Não consegue entrar até criar.';
