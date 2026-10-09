# Worka Bots — Etapa 1

Status: modelo de dados e arquitetura entregues. Banco PostgreSQL ainda não provisionado. Serviços Node, autenticação, pagamento, workers e IA serão implementados nas próximas etapas. A landing page é uma entrega adicional independente.

## Serviços e fronteiras
- Frontend React/Next compatível (Vinext no Sites), Tailwind, lucide-react. O Sites hospeda a landing e captura de interesse via D1, não os workers WhatsApp. D1 de leads não substitui o PostgreSQL do SaaS.
- API Node.js/NestJS externa: autenticação, memberships/RBAC, limites, bots, billing, webhooks, REST e Socket.io. PostgreSQL + Prisma 7 como fonte de verdade.
- Redis/BullMQ: filas, rate limit, locks com fencing e heartbeat, cache efêmero e adapter Socket.io. Nunca única cópia da sessão.
- Worker whatsapp-web.js/Puppeteer em container com volume persistente criptografado; propriedade exclusiva por sessão, reconnect com backoff/jitter e término gracioso. Cloud API Meta como adaptador alternativo (sem QR).
- Worker IA: fila por conversa, contexto limitado, personality/systemPrompt versionado, timeout/retry, contabilização de tokens; credenciais em secret manager. OpenAI/Anthropic intercambiáveis.
- Webhooks: verificar assinatura, resolver workspace a partir do vínculo confiável do provedor, deduplicar, persistir e enfileirar; liberar acesso somente após evento de cobrança validado.

Fluxo: WhatsApp → adapter → inbox persistido/idempotente → fila → IA → outbox → adapter. Socket.io transmite somente eventos autorizados ao workspace. Transação de inbox/outbox + reconciliador de mensagens QUEUED evita perder trabalho entre commit e enqueue. Entrega externa não é exactly-once: reconciliação de IDs e estado SENT é necessária antes de repetir envio com resultado incerto.

## Multi-tenant
Banco compartilhado, workspaceId obrigatório nas entidades do tenant. User/Plan são globais; WorkspaceMember permite N:N. FKs compostas (workspaceId, id) impedem vincular bot/conversa/mensagem a outro tenant. Não tornam SELECT seguro por si só.

Toda operação usa workspace autorizado pelo usuário autenticado, nunca confia somente em body/header. Roles: OWNER controla billing e membros; ADMIN gerencia bots/sessões; EDITOR edita bots; VIEWER consulta. Criar workspace e seu OWNER na mesma transação. Impedir remover ou rebaixar último OWNER com lock transacional. Não existe senha no schema; authSubject vem de provedor de identidade.

RLS é defesa adicional: aplicar políticas no PostgreSQL em migration; role de aplicação sem superuser/BYPASSRLS, FORCE ROW LEVEL SECURITY. Dentro de cada transação autorizada, set_config('app.workspace_id', workspaceId, true); USING e WITH CHECK com workspaceId. Pool deve usar contexto local à transação, nunca SET persistente. Rotas de descoberta de memberships usam caminho privilegiado mínimo e filtrado por authSubject. RLS ainda não aplicada: não apresentar schema isoladamente como autorização pronta.

## Modelo e decisões
Users, Workspaces, WorkspaceMembers, WhatsAppSessions, Bots, BotTriggers, Conversations, Messages, Logs, Plans, Subscriptions, UsageBuckets, WebhookEvents.

Uma conexão tem no máximo um bot atribuído na versão inicial; workspace aceita múltiplas conexões/bots e drafts sem conexão. Fluxos são JSON versionado, validados no backend contra contrato de nodes/edges. Gatilhos têm prioridade determinística. humanTakeover suspende IA por conversa.

Preço em centavos; custo IA em Decimal USD; timestamps UTC com timezone do workspace na exibição. Uma assinatura corrente por workspace; histórico de transições em auditoria e eventos de billing. Planos devem ser versionados (não mudar limites/preço de plano contratado). Períodos de UsageBucket seguem ciclo de billing. Mensagens de saída aceitas pelo provedor contam para a franquia; entrada é métrica separada. Reservar quota atomicamente antes de enviar e liberar reserva em falhas definitivas; contadores só uma vez por idempotencyKey. Isso é contrato de implementação, não comportamento automático do schema.

Logs append-only para aplicação; retenção por plano com job administrativo. durationMs + kind separam latência IA, conexão e envio; calcular p50/p95 por janela. Nunca publicar latências fictícias como produção.

## Segurança e operação
Não persistir QR, tokens, segredos ou texto integral em logs. QR efêmero por Socket.io em room autorizada workspace+session, expira na autenticação. authStorageRef/credentialRef guardam referências, não segredos. Conteúdo de mensagens cifrado pela aplicação, com retenção e remoção conforme política. Exclusão de workspace exige fluxo explícito de encerramento/retenção; relações Restrict evitam cascata acidental.

CHECK constraints adicionais (prisma/constraints.sql): delays, tokens, preço e períodos. FKs já cobrem integridade entre tenants. Revogar UPDATE/DELETE de Log da role de aplicação e implantar políticas RLS antes de produção.

## Preparar o backend (etapa posterior)
Node >=22.13.0. Fixar Prisma CLI e client na mesma versão 7.x validada; instalar prisma, @prisma/client, @prisma/adapter-pg, pg e dotenv no pacote backend. Copiar schema e prisma.config.ts. DATABASE_URL apenas no ambiente. Executar prisma validate, prisma migrate dev --name init, incorporar constraints.sql na migration inicial antes de aplicar em produção e prisma generate. Runtime com PrismaPg adapter. Nunca apontar migração dev para produção; CI/CD usa migrate deploy.

A validação do schema não prova conectividade nem autorização. Próximas etapas precisam testes de acesso cruzado, retomada de sessão, idempotência, quotas concorrentes e webhook assinado.

## Landing page
Nome Worka Bots é editável. Preços propostos: Starter R$79, Pro R$199, Enterprise a partir de R$599. Nenhuma cobrança ocorre. CTA abre lista de interesse persistida; login explica disponibilidade futura. Demonstração local usa respostas simuladas identificadas. Antes de campanha pública, definir operador/controlador, contato de privacidade e termos comerciais finais.

Referências: https://www.prisma.io/docs/orm/v7/reference/prisma-config-reference e https://www.prisma.io/docs/orm/v7/prisma-schema/data-model/relations
