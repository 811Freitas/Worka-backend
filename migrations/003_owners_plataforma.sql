-- ════════════════════════════════════════════════════════════
-- WORKAP — Conta de owner da plataforma no banco de dados
-- ════════════════════════════════════════════════════════════
-- Rode este SQL uma única vez no projeto Supabase ATIVO
-- ("Worka1" — vtkmqykwyilcdnigaxsr), em: SQL Editor > New query.
--
-- Antes disso, a conta de owner vivia só em variáveis de ambiente do
-- Render (OWNER_EMAIL e OWNER_PASSWORD_HASH). Funcionava, mas trocar a
-- senha ou adicionar um segundo administrador exigia mexer no painel
-- do Render e esperar o serviço reiniciar. Aqui é um UPDATE.
--
-- Por que uma tabela separada e não uma linha em `empresas`:
-- o painel de owner lista todas as empresas e conta assinantes por
-- status (ativa / trial / inadimplente). Uma linha de administrador
-- ali dentro apareceria como um assinante fantasma em todos esses
-- números — e um dia alguém tentaria cobrar dela.
-- ════════════════════════════════════════════════════════════

create table if not exists public.owners_plataforma (
  id           uuid primary key default gen_random_uuid(),

  email        text not null unique,

  -- Hash bcrypt (12 rounds). NUNCA a senha em texto. O backend só sabe
  -- comparar hash — uma senha em texto plano aqui simplesmente nunca
  -- confere, e o login fica quebrado sem dizer por quê.
  senha_hash   text not null,

  nome         text not null default 'Owner Workap',

  -- Desligar o acesso sem apagar o histórico de quem era admin.
  ativo        boolean not null default true,

  ultimo_login timestamptz,
  created_at   timestamptz not null default now()
);

-- Todo login consulta por e-mail.
create index if not exists idx_owners_email
  on public.owners_plataforma (email);

-- ── Segurança ───────────────────────────────────────────────
-- O backend usa a service_role key, que ignora RLS. RLS fica ligado
-- SEM policy permissiva para que, se um dia a chave pública (anon) for
-- usada no navegador por engano, ninguém consiga ler esta tabela do
-- frontend — é onde mora o hash da senha que abre o painel da
-- plataforma inteira.
alter table public.owners_plataforma enable row level security;

-- ── Conta inicial ───────────────────────────────────────────
-- Senha: definida pelo dono da plataforma. O hash abaixo é bcrypt de
-- 12 rounds. Para trocar a senha depois, gere um hash novo com:
--   node -e "console.log(require('bcryptjs').hashSync('NOVA_SENHA',12))"
-- e rode: update public.owners_plataforma set senha_hash = 'NOVO_HASH'
--         where email = 'workappoficial@gmail.com';
insert into public.owners_plataforma (email, senha_hash, nome)
values (
  'workappoficial@gmail.com',
  '$2b$12$A53Nb3XGt3bRvWYVwbI7pugvKeTKrDsvcRWemO02yatvLObG0pOay',
  'Owner Workap'
)
on conflict (email) do nothing;
