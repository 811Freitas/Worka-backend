-- ════════════════════════════════════════════════════════════
-- WORKAP — De qual anúncio veio cada cadastro
-- ════════════════════════════════════════════════════════════
-- Rode uma única vez no projeto Supabase ATIVO
-- ("Worka1" — vtkmqykwyilcdnigaxsr), em: SQL Editor > New query.
-- ════════════════════════════════════════════════════════════
--
-- O site já capturava os parâmetros UTM na primeira visita e guardava
-- no navegador. Só que a função que os lê de volta nunca era chamada:
-- o dado era coletado e descartado no cadastro.
--
-- Sem estas colunas, tráfego pago é aposta. Com elas, dá para responder
-- a única pergunta que importa quando se gasta com anúncio: QUAL
-- anúncio trouxe cliente que paga — e não apenas cliente que clica.
--
-- Colunas separadas em vez de um jsonb porque a consulta que vale é
-- "agrupe por campanha e me diga quantos viraram pagantes". Isso em
-- jsonb exige extrair campo a campo em toda query.

alter table public.empresas
  -- De onde veio (FB, google, instagram...).
  add column if not exists utm_source   text,
  -- No padrão do Meta que estamos usando, carrega o CONJUNTO de
  -- anúncios: "nome|id". Fora da convenção clássica (onde medium seria
  -- "cpc"), mas é o que o Gerenciador preenche sozinho — e o que
  -- importa é conseguir voltar do cliente até o anúncio.
  add column if not exists utm_medium   text,
  -- Campanha: "nome|id".
  add column if not exists utm_campaign text,
  -- Anúncio específico: "nome|id". É a coluna que responde qual
  -- CRIATIVO vende, que é a decisão de maior impacto no custo.
  add column if not exists utm_content  text,
  -- Posicionamento (feed, stories, reels...).
  add column if not exists utm_term     text,
  -- Quando a origem foi capturada. Separado do created_at porque a
  -- pessoa pode clicar no anúncio hoje e só se cadastrar semana que
  -- vem — e a distância entre os dois é informação de venda.
  add column if not exists origem_em    timestamptz;

-- A pergunta frequente é "quanto cada campanha trouxe". Índice parcial:
-- cadastro orgânico não tem campanha e não precisa ocupar espaço.
create index if not exists idx_empresas_utm_campaign
  on public.empresas (utm_campaign) where utm_campaign is not null;

create index if not exists idx_empresas_utm_content
  on public.empresas (utm_content) where utm_content is not null;
