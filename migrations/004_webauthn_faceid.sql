-- ════════════════════════════════════════════════════════════
-- WORKAP — Face ID / Touch ID como verificação de aparelho
-- ════════════════════════════════════════════════════════════
-- Rode este SQL uma única vez no projeto Supabase ATIVO
-- ("Worka1" — vtkmqykwyilcdnigaxsr), em: SQL Editor > New query.
--
-- As tabelas webauthn_credentials e webauthn_challenges já existiam,
-- criadas junto do resto do banco, mas nunca foram usadas: não havia
-- uma linha de código de WebAuthn no projeto. Duas coisas impediam de
-- usá-las como estavam:
--
-- 1) empresa_id era obrigatório. A conta de owner da plataforma não
--    tem empresa, então nunca conseguiria cadastrar uma credencial.
-- 2) Não havia como achar a credencial pelo e-mail digitado na tela de
--    login. O login acontece ANTES de existir sessão — o servidor só
--    tem o e-mail, não tem empresa_id nem funcionario_id.
--
-- Este SQL corrige as duas coisas sem apagar nada (as tabelas estão
-- vazias, mas a migration é escrita para ser segura de qualquer jeito).
-- ════════════════════════════════════════════════════════════

-- ── Credenciais ─────────────────────────────────────────────
alter table public.webauthn_credentials
  alter column empresa_id drop not null;

-- Identifica a CONTA pelo e-mail, igual dispositivos_confiaveis faz.
-- É o único dado que o servidor tem em mãos na hora do login.
alter table public.webauthn_credentials
  add column if not exists email text;

-- Contador de assinaturas: o autenticador incrementa a cada uso. Se um
-- dia chegar um valor menor que o guardado, é sinal de credencial
-- clonada. Já existia como bigint — aqui só garantimos o default.
alter table public.webauthn_credentials
  alter column counter set default 0;

create index if not exists idx_webauthn_cred_email
  on public.webauthn_credentials (email);

-- ── Desafios ────────────────────────────────────────────────
-- Cada tentativa de cadastro/uso gera um desafio aleatório que só vale
-- uma vez. Sem isso, uma assinatura capturada poderia ser reenviada.
alter table public.webauthn_challenges
  alter column empresa_id drop not null;

alter table public.webauthn_challenges
  add column if not exists email text;

alter table public.webauthn_challenges
  add column if not exists finalidade text not null default 'login';

create index if not exists idx_webauthn_chal_email
  on public.webauthn_challenges (email, usado);

-- ── Segurança ───────────────────────────────────────────────
-- O backend usa a service_role key, que ignora RLS. RLS fica ligado sem
-- policy permissiva: se um dia a chave pública (anon) for usada no
-- navegador por engano, ninguém lê nem grava credenciais pelo frontend.
alter table public.webauthn_credentials enable row level security;
alter table public.webauthn_challenges  enable row level security;
