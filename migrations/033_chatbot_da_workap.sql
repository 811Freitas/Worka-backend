-- 033 — O chatbot da própria Workap
--
-- O painel Owner ganha a mesma coisa que o cliente tem: um número de
-- WhatsApp com um assistente atendendo. Quem manda mensagem para a
-- Workap perguntando preço, horário ou "quero assinar" é respondido na
-- hora, em vez de esperar alguém acordar.
--
-- POR QUE NA MESMA TABELA, e não numa `chatbot_plataforma` nova. O
-- motor de decisão, o menu numerado, os gatilhos, o webhook que acha o
-- bot pelo phone_number_id, o registro de atendimento — está tudo
-- pronto e nada disso muda por ser a Workap. Uma tabela paralela seria
-- a mesma estrutura duplicada, e a partir daí toda correção de bug
-- teria que ser feita duas vezes. A que fosse esquecida vira o bug que
-- só acontece "no meu" ou "no do cliente".
--
-- O que muda é uma coisa só: a Workap não é uma empresa da tabela
-- `empresas`. Daí `escopo`.

-- ════════════════════════════════════════════════════════════
-- 1. DE QUEM É O BOT
-- ════════════════════════════════════════════════════════════
alter table public.chatbots
  add column if not exists escopo text not null default 'empresa';

-- empresa_id deixa de ser obrigatório porque o bot da plataforma não
-- pertence a empresa nenhuma. O DEFAULT 'empresa' acima garante que
-- toda linha que já existe continua exatamente como estava.
alter table public.chatbots            alter column empresa_id drop not null;
alter table public.chatbot_itens       alter column empresa_id drop not null;
alter table public.chatbot_atendimentos alter column empresa_id drop not null;

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'chatbots_escopo_check') then
    alter table public.chatbots
      add constraint chatbots_escopo_check check (escopo in ('empresa','plataforma'));
  end if;

  -- Escopo e empresa_id andam juntos, e o banco é que garante isso.
  -- Deixado a cargo do código, o primeiro insert distraído cria um bot
  -- "de empresa" sem empresa — invisível para o dono, invisível para o
  -- owner, e respondendo no WhatsApp de alguém.
  if not exists (select 1 from pg_constraint where conname = 'chatbots_escopo_coerente') then
    alter table public.chatbots
      add constraint chatbots_escopo_coerente check (
        (escopo = 'empresa'    and empresa_id is not null) or
        (escopo = 'plataforma' and empresa_id is null)
      );
  end if;
end $$;

-- UM bot da plataforma, e só um. A restrição UNIQUE de empresa_id não
-- serve aqui: em Postgres, vários NULL não conflitam entre si, então
-- sem este índice dava para criar dez bots da Workap e o webhook
-- responderia com o que viesse primeiro.
create unique index if not exists idx_chatbots_um_da_plataforma
  on public.chatbots ((escopo)) where escopo = 'plataforma';

comment on column public.chatbots.escopo is
  'empresa = bot de um assinante; plataforma = o bot da própria Workap, no painel Owner.';
