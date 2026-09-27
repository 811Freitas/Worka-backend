-- Preferências usadas pelo painel e pelo motor de atendimento.
-- Pode ser executada novamente sem perder configurações existentes.
alter table public.chatbots
  add column if not exists personalidade text,
  add column if not exists memoria_trocas integer not null default 6,
  add column if not exists modo_economia boolean not null default false,
  add column if not exists modo_atendimento text;

-- Preserva o liga/desliga da IA dos bots anteriores à migração.
update public.chatbots
set modo_atendimento = case when usa_ia then 'misto' else 'comandos' end
where modo_atendimento is null;

alter table public.chatbots
  alter column modo_atendimento set default 'misto',
  alter column modo_atendimento set not null;

do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'chatbots_memoria_trocas_check') then
    alter table public.chatbots add constraint chatbots_memoria_trocas_check
      check (memoria_trocas between 0 and 12);
  end if;
  if not exists (select 1 from pg_constraint where conname = 'chatbots_modo_atendimento_check') then
    alter table public.chatbots add constraint chatbots_modo_atendimento_check
      check (modo_atendimento in ('comandos', 'misto', 'ia'));
  end if;
end $$;
