-- ════════════════════════════════════════════════════════════
-- WORKAP — Ramos de negócio
-- ════════════════════════════════════════════════════════════
-- Rode este SQL uma única vez no projeto Supabase ATIVO
-- ("Worka1" — vtkmqykwyilcdnigaxsr), em: SQL Editor > New query.
-- ════════════════════════════════════════════════════════════

-- ── 1. DATA DE VENCIMENTO DEIXA DE SER OBRIGATÓRIA ──────────
--
-- A coluna nasceu NOT NULL porque o sistema começou pensando em
-- mercearia e padaria. Isso torna impossível cadastrar um carro numa
-- concessionária, uma calça numa loja de roupa ou uma chave de fenda
-- numa oficina — nada disso vence, e a tela exigia uma data.
--
-- Quem usa validade (farmácia, restaurante, mercado) continua igual:
-- a data segue obrigatória, agora pela regra do ramo, checada na API.
-- O que muda é o banco parar de impor a regra de um ramo a todos.
alter table public.produtos_validade
  alter column data_vencimento drop not null;

-- O gatilho que calcula `status` precisa aguentar linha sem data —
-- sem isto, cadastrar um veículo quebraria já no INSERT, porque
-- `null < current_date` devolve null e nenhum ramo do IF pega.
--
-- A regra de negócio abaixo é a MESMA de antes (inclusive o
-- least(dias_aviso, 7) do "urgente"); a única mudança é o retorno
-- antecipado para item sem validade.
create or replace function public.atualizar_status_validade()
returns trigger
language plpgsql
as $function$
begin
  -- Item que não vence (veículo, roupa, peça, serviço): fica sempre
  -- "normal". Não é dado faltando — é um item sem prazo.
  if new.data_vencimento is null then
    new.status := 'normal';
    return new;
  end if;

  if new.data_vencimento < current_date then
    new.status := 'vencido';
  elsif new.data_vencimento <= current_date + interval '1 day' * least(new.dias_aviso, 7) then
    new.status := 'urgente';
  elsif new.data_vencimento <= current_date + interval '1 day' * new.dias_aviso then
    new.status := 'atencao';
  else
    new.status := 'normal';
  end if;
  return new;
end;
$function$;

-- ── 2. CAMPOS ESPECÍFICOS DE CADA RAMO ──────────────────────
--
-- Concessionária precisa de placa, ano e quilometragem; loja de roupa
-- precisa de tamanho e cor; farmácia, de princípio ativo e tarja.
-- Uma coluna por campo daria dezenas de colunas nulas para todo mundo,
-- e uma tabela por ramo multiplicaria o código por doze.
--
-- jsonb com chaves fechadas: a API só aceita as chaves declaradas no
-- catálogo do ramo (ver RAMOS no index.js) — o cliente não escolhe o
-- que grava aqui.
alter table public.produtos_validade
  add column if not exists atributos jsonb not null default '{}'::jsonb;

comment on column public.produtos_validade.atributos is
  'Campos do ramo (placa, tamanho, cor...). Chaves validadas contra RAMOS no backend.';

-- ── 3. RAMO DA EMPRESA ──────────────────────────────────────
--
-- A coluna já existia como texto livre preenchido no cadastro, mas
-- nada no sistema lia — a landing prometia "escolha o segmento do seu
-- negócio" e o app ignorava. Agora ela decide vocabulário, campos e
-- menu, então passa a ter valor padrão em vez de ficar nula: empresa
-- sem ramo definido cai em "outro", que mostra o app genérico.
alter table public.empresas
  alter column ramo set default 'outro';

update public.empresas
   set ramo = 'outro'
 where ramo is null or btrim(ramo) = '';

comment on column public.empresas.ramo is
  'Slug do ramo (restaurante, farmacia, loja_roupa, concessionaria...). Define vocabulário e campos no app.';

-- Índice para o painel owner agrupar por ramo sem varrer a tabela
-- quando houver muitos assinantes.
create index if not exists idx_empresas_ramo on public.empresas (ramo);
