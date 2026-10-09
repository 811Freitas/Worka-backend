# Workap Bots — landing do workap.com.br

React + TypeScript + Tailwind + Vite. O GitHub Pages hospeda o index.html e assets/bots compilados na raiz. O domínio continua em CNAME. O backend Node e as páginas antigas permanecem disponíveis.

## Desenvolvimento
Node >=22.13.0. Nesta pasta: npm ci; npm run typecheck; npm test; npm run build.

A UI fica em src/LandingPage.tsx. Copiar dist/index.html para ../index.html e dist/assets/bots/* para ../assets/bots/ após um build aprovado. Não apagar assets de releases anteriores imediatamente: usuários podem manter o HTML antigo em cache.

## Integração
POST https://worka-backend-awng.onrender.com/public/bots-leads
Valida origem, consentimento, campos, tamanho, honeypot e rate limit. Grava no Supabase existente (worka_bots_leads), acessível apenas ao backend. Sem sessão ou assinatura criada. Abertura do produto, WhatsApp e cobrança Hotmart continuam pendentes; não apontar os novos planos ao checkout Cakto anterior.

## Ordem de publicação
1. Backend e migration já testados.
2. Teste HTTP real + verificar linha no banco.
3. Build da página e testes de interação no DOM.
4. Commit dos arquivos estáticos na branch main e verificar resposta de workap.com.br e assets.

Restauração da landing: usar backup/workap-before-bots-2026-10-09 e restaurar index.html; o serviço novo é aditivo. Não remover o banco ou dados dos interessados para desfazer uma mudança visual.

## Verificação
13 testes Node do backend e 5 testes React em jsdom. TypeScript e build. jsdom não valida layout visual, CSS ou comportamento de um navegador real. Testar produção separadamente antes de campanhas.
