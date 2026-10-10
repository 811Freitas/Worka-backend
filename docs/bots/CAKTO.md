# Cakto — estado da integração

A Cakto permanece no backend do Render. O navegador nunca recebe client_secret ou segredo de webhook.

## Verificado
- GET /planos retornou apenas completo (R$49,99) e pro (R$89,99), referentes ao sistema de gestão.
- O plano chatbot existe no código mas depende de habilitação no painel e de preço configurado.
- POST /assinatura/checkout exige cadastro prévio em empresas. O formulário da landing grava interessados, não cria contas.
- POST /webhook/cakto valida o segredo e identifica a empresa antes de aplicar a assinatura. Cenários simulados de segredo e pagamento aprovado passam; não houve compra real de validação.
- A validação de checkout agora exige um plano explícito e conhecido. Master/chatbot desativados são recusados. Metadados com plano inválido não alteram o plano da empresa.

## Pendências antes de cobrar os planos novos
1. Implementar cadastro/login e os direitos de Starter, Pro e Enterprise. O sistema atual não oferece as cotas multi-bot/multi-número anunciadas na proposta.
2. Vincular cada plano a uma oferta recorrente correta da Cakto, com preço e periodicidade conferidos. Não mapear o Pro de R$199 ao pro de gestão de R$89,99.
3. Adequar o adaptador à API atual: a documentação de criação de produto usa type unique/subscription e paymentMethods; o código legado ainda usa hipóteses antigas e precisa de validação de contrato antes de gerar novos produtos.
4. Validar aprovação, renovação, atraso, cancelamento, reembolso e chargeback, incluindo entrega duplicada e eventos fora de ordem. A lógica legada agrupa cancelamento e reembolso; isso ainda precisa de revisão antes de lançar a oferta nova.
5. Só após validação de ponta a ponta substituir a lista de interesse pelo checkout. O redirecionamento de sucesso nunca pode liberar acesso por si só.

Webhook existente (sem segredo na URL): https://worka-backend-awng.onrender.com/webhook/cakto

Referências:
- https://docs.cakto.com.br/comece-aqui/receber-primeira-venda
- https://docs.cakto.com.br/api-reference/products/create
- https://docs.cakto.com.br/api-reference/webhooks/update
