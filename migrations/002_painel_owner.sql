-- ════════════════════════════════════════════════════════════
-- ZAPFY — Painel do dono da plataforma
-- ════════════════════════════════════════════════════════════
--
-- Quem administra o Zapfy precisa enxergar a plataforma inteira: quantas
-- contas existem, quais estão com o WhatsApp caído, quem parou de usar.
-- Sem isso, a única forma de saber que um cliente está com problema é
-- ele reclamar — e a maioria não reclama, cancela.
--
-- LIMITE DELIBERADO: o painel de owner mostra NÚMEROS e METADADOS, nunca
-- o conteúdo das conversas dos clientes nem as credenciais deles. Saber
-- que a conta X trocou 400 mensagens ontem é operação; ler o que o
-- consumidor final escreveu para aquela empresa é outra coisa, e não é
-- necessária para administrar a plataforma. As consultas deste módulo
-- foram escritas com essa linha em mente.
-- ════════════════════════════════════════════════════════════

alter table contas
  -- Quando a conta foi suspensa, e por quê. Suspensa continua logando
  -- (a pessoa precisa ver a própria conta para regularizar), mas o bot
  -- para de responder — a suspensão tem que ser visível para o dono da
  -- conta, nunca silenciosa.
  add column if not exists suspensa_em  timestamptz,
  add column if not exists motivo_suspensao text,

  -- Anotação interna do dono da plataforma sobre a conta ("cliente do
  -- plano anual", "pediu reembolso"). Nunca aparece para o cliente.
  add column if not exists observacao   text;


-- ════════════════════════════════════════
-- AÇÕES DO OWNER — trilha de auditoria
-- ════════════════════════════════════════
-- Toda ação administrativa fica registrada. Não é burocracia: suspender
-- a conta de um cliente pagante é uma operação com consequência
-- comercial, e "quem fez isso, e quando?" precisa ter resposta. Também
-- protege o próprio dono — se um dia o acesso de owner vazar, é por aqui
-- que se descobre o que foi feito com ele.
create table if not exists owner_acoes (
  id         uuid primary key default gen_random_uuid(),

  -- E-mail de quem executou, copiado no momento da ação. Não é chave
  -- estrangeira porque o owner não é um usuario: ele vive nas variáveis
  -- de ambiente, fora do banco.
  autor      text not null,

  -- suspender | reativar | mudar_plano | anotar
  acao       text not null,

  -- A conta afetada. ON DELETE SET NULL para o registro sobreviver ao
  -- apagamento da conta — é justamente o caso em que ele mais importa.
  conta_id   uuid references contas(id) on delete set null,

  -- Nome da conta copiado, pelo mesmo motivo.
  conta_nome text,

  detalhe    jsonb,
  criado_em  timestamptz not null default now()
);

create index if not exists idx_owner_acoes on owner_acoes (criado_em desc);


-- ════════════════════════════════════════
-- ÍNDICES PARA AS CONSULTAS DO PAINEL
-- ════════════════════════════════════════
-- O painel do owner varre TODAS as contas, sem filtro por conta_id — é o
-- único lugar do sistema que faz isso. Com dez clientes qualquer consulta
-- serve; com mil, a tela inicial começa a demorar segundos, e o
-- diagnóstico disso é sempre tardio.

-- "Quantas mensagens cada conta trocou nos últimos 7 dias" — o número
-- mais consultado do painel.
create index if not exists idx_mensagens_conta_data on mensagens (conta_id, criado_em desc);

-- "Quais conexões estão com problema agora" — a primeira coisa que o
-- dono olha de manhã.
create index if not exists idx_conexoes_status on conexoes (status);

-- "Quem se cadastrou esta semana".
create index if not exists idx_contas_criado on contas (criado_em desc);
