-- ════════════════════════════════════════════════════════════
-- WORKAP — Telefone e CPF/CNPJ no cadastro
-- ════════════════════════════════════════════════════════════
-- Rode uma única vez no projeto Supabase ATIVO
-- ("Worka1" — vtkmqykwyilcdnigaxsr), em: SQL Editor > New query.
-- ════════════════════════════════════════════════════════════
--
-- POR QUE
--
-- O aviso de trial novo chegava com nome, e-mail e segmento — e nada
-- para ligar. Quem entra no trial tem 7 dias; sem telefone, a única
-- forma de falar com essa pessoa é e-mail, que é justamente o canal
-- que ela ignora.
--
-- O CPF/CNPJ serve para dois usos concretos: emitir nota e saber se
-- quem está do outro lado é pessoa física ou empresa — o que muda a
-- conversa de venda.

alter table public.empresas
  -- Só dígitos, com DDD: 10 para fixo, 11 para celular. A formatação
  -- ("(11) 98765-4321") é decisão de tela e por isso não é gravada —
  -- quem guarda máscara acaba com o mesmo número em três formatos.
  add column if not exists telefone  text,

  -- Só dígitos: 11 para CPF, 14 para CNPJ. Mesma razão.
  --
  -- Não é chave única de propósito: o mesmo CNPJ pode legitimamente
  -- abrir mais de uma conta (matriz e filial, dois pontos de venda), e
  -- uma restrição aqui só apareceria no dia em que o segundo cliente
  -- tentasse se cadastrar e não conseguisse, sem entender por quê.
  add column if not exists documento text;

-- Busca por telefone acontece no atendimento: chega uma mensagem no
-- WhatsApp e é preciso achar de quem é. Parcial porque as contas
-- antigas ficam sem telefone e não têm por que ocupar o índice.
create index if not exists idx_empresas_telefone
  on public.empresas (telefone) where telefone is not null;
