-- ════════════════════════════════════════════════════════════
-- WORKA — Dispositivos confiáveis (verificação de login por código)
-- ════════════════════════════════════════════════════════════
-- Rode este SQL uma única vez no projeto Supabase ATIVO
-- ("Worka1" — vtkmqykwyilcdnigaxsr), em: SQL Editor > New query.
--
-- O que isso faz: quando alguém entra de um aparelho que o sistema
-- não reconhece (ou que não é usado há mais de 30 dias), a senha
-- sozinha deixa de bastar — é enviado um código por e-mail antes de
-- liberar o acesso. Aparelhos já conhecidos entram direto.
--
-- Sem esta tabela, o login continua funcionando normalmente, só que
-- sem a verificação extra (o backend trata a ausência da tabela como
-- "não há nada registrado" e não bloqueia ninguém).
-- ════════════════════════════════════════════════════════════

create table if not exists public.dispositivos_confiaveis (
  id            uuid primary key default gen_random_uuid(),

  -- Identifica a CONTA. Guardamos o e-mail porque a conta de owner da
  -- Worka não existe na tabela empresas (vive em variável de ambiente),
  -- então não há empresa_id para usar como chave nesse caso.
  email         text not null,
  empresa_id    uuid,                       -- null quando é a conta owner

  -- Identificador aleatório gerado pelo navegador e guardado no
  -- localStorage do aparelho. Não é dado pessoal: é um número
  -- aleatório sem relação com o aparelho em si.
  device_id     text not null,

  -- Rótulo legível ("iPhone · Safari") só para a pessoa reconhecer o
  -- aparelho numa futura tela de "sessões ativas".
  descricao     text,

  ultimo_acesso timestamptz not null default now(),
  created_at    timestamptz not null default now(),

  -- Um registro por aparelho por conta.
  unique (email, device_id)
);

-- Busca por (email, device_id) acontece em todo login.
create index if not exists idx_dispositivos_email_device
  on public.dispositivos_confiaveis (email, device_id);

-- ── Segurança ───────────────────────────────────────────────
-- O backend usa a service_role key, que ignora RLS. Habilitamos RLS
-- sem policy permissiva para que, se algum dia a chave pública (anon)
-- for usada no navegador por engano, ninguém consiga ler nem gravar
-- dispositivos direto do frontend.
alter table public.dispositivos_confiaveis enable row level security;
