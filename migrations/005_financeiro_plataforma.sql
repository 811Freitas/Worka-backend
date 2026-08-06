-- ════════════════════════════════════════════════════════════
-- WORKAP — Despesas da plataforma no painel de owner
-- ════════════════════════════════════════════════════════════
-- Rode este SQL uma única vez no projeto Supabase ATIVO
-- ("Worka1" — vtkmqykwyilcdnigaxsr), em: SQL Editor > New query.
--
-- lancamentos_financeiros.empresa_id era obrigatório, então só empresa
-- cliente conseguia registrar despesa. O owner da plataforma não tem
-- empresa — as contas dele são de outra natureza (servidor, domínio,
-- gateway de pagamento, anúncios).
--
-- Em vez de criar uma segunda tabela com as mesmas colunas, empresa_id
-- passa a aceitar NULL, e NULL significa "da plataforma". As consultas
-- de empresa já filtram por empresa_id=eq.<id>, então nunca enxergam
-- linha nenhuma da plataforma; e a consulta da plataforma filtra por
-- empresa_id=is.null, que nunca enxerga linha de cliente. A separação
-- é a mesma de antes, sem duplicar tabela nem lógica de categoria.
-- ════════════════════════════════════════════════════════════

alter table public.lancamentos_financeiros
  alter column empresa_id drop not null;

-- Consulta da plataforma varre por empresa_id nulo + data; sem índice
-- isso vira varredura da tabela inteira conforme os clientes crescem.
create index if not exists idx_lanc_plataforma
  on public.lancamentos_financeiros (data desc)
  where empresa_id is null;

comment on column public.lancamentos_financeiros.empresa_id is
  'NULL = lançamento da própria Workap (plataforma), não de empresa cliente.';
