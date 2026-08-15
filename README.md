# Zapfy

Plataforma onde cada cliente cria, configura, conecta e mantém o próprio
chatbot de WhatsApp pelo navegador — sem tocar em código.

Multi-inquilino de verdade: vários clientes na mesma instalação, cada um
com seu número, seu fluxo, suas conversas e seus dados completamente
separados.

---

## Por que API oficial e não QR Code

A plataforma usa a **WhatsApp Cloud API da Meta**. Não é preferência de
gosto — é o que faz o "24/7" ser verdade:

| | QR Code (Baileys, whatsapp-web.js) | Cloud API (aqui) |
|---|---|---|
| Sessão | um socket vivo por cliente, dentro do servidor | a Meta guarda |
| Deploy / reinício | derruba todos os clientes ao mesmo tempo | não afeta ninguém |
| Reconexão | cada cliente lê um QR Code novo, na mão | não existe o problema |
| Banimento | risco real, é uso não autorizado | zero, é o caminho oficial |
| Escala | limitada pela memória de sockets | limitada só pelo banco |

Com 200 clientes no modelo QR Code, um deploy de sexta à noite significa
200 pessoas lendo QR Code no sábado. Aqui, o servidor pode reiniciar no
meio de uma conversa e a próxima mensagem chega normalmente — o estado da
conversa vive no Postgres, não na memória do processo.

O custo: o cliente precisa criar um app na Meta (gratuito, ~5 minutos). O
painel tem um assistente passo a passo para isso, com os valores prontos
para copiar.

---

## O que já funciona

**Contas** — cadastro, login, sessão que sobrevive ao F5, troca de senha,
papéis (dono e operador), rate limiting.

**Construtor de chatbot** — blocos de menu, mensagem, pergunta,
transbordo e encerramento; opções que viram botões no WhatsApp;
palavras-chave que funcionam de qualquer ponto da conversa; variáveis
(`{{nome}}`); horário de atendimento com fuso; personalização de todas as
mensagens.

**Simulador** — conversa com o fluxo salvo dentro do painel, sem tocar na
Meta e sem gravar nada. Mesmo motor que atende de verdade.

**Diagnóstico do fluxo** — encontra opção apontando para bloco que não
existe, bloco que ninguém alcança, menu sem saída.

**Conexão** — assistente de 3 passos, estado em tempo real, pausar,
retomar, reiniciar, desconectar e reconectar.

**Atendimento** — histórico completo de conversas, transferência para
atendente humano (o bot se cala), resposta manual pelo painel, devolução
ao bot preservando o ponto do fluxo.

**Operação** — monitor que pergunta à Meta se cada conexão ainda vale,
notifica o dono quando cai e quando volta, registro operacional por
cliente e faxina automática das tabelas que crescem para sempre.

**Painel de administração** (`/owner`) — a visão de quem administra a
plataforma: quantas contas existem, quais estão com o WhatsApp caído,
quem parou de usar, quem cresceu. Suspender e reativar contas, mudar
plano, anotar, e uma trilha de auditoria de toda ação administrativa.

> O painel administrativo mostra **números e metadados, nunca o conteúdo
> das conversas dos clientes nem as credenciais deles**. Saber que a
> conta X trocou 400 mensagens ontem é operar a plataforma; ler o que o
> consumidor final escreveu para aquela empresa é outra coisa, não é
> necessária para o negócio, e é o tipo de acesso que destrói a confiança
> do cliente no dia em que ele descobre que existe. Há um teste
> automatizado que falha se esses dados escaparem por ali.

---

## Como rodar

Precisa de Node 20+ e um Postgres.

```bash
git clone https://github.com/811Freitas/zapfy.git
cd zapfy
npm install

cp .env.example .env
# preencha DATABASE_URL, JWT_SECRET e CRYPTO_KEY
# para gerar segredos:
#   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

npm run migrar
npm start
```

Abra `http://localhost:3000`, crie uma conta e o chatbot de exemplo já
vem montado — dá para testar no simulador antes de conectar qualquer
número.

### Testes

```bash
npm run teste
```

106 casos. Sobem um servidor de verdade, contra um Postgres de verdade,
com uma Meta falsa em `127.0.0.1` que responde como a Graph API responde
(inclusive os erros: token expirado, limite de botões, instabilidade).

> A suíte **apaga o schema `public`** do banco que usar. Aponte
> `DATABASE_URL_TESTE` para um banco descartável — o padrão é
> `postgres://zapfy:zapfy@127.0.0.1:5432/zapfy_teste`.

O que a suíte cobre: cadastro e login, isolamento entre clientes,
navegação do fluxo, palavras-chave, variáveis, horário de atendimento,
fusos, expiração de conversa, fluxo circular, conexão, verificação do
webhook, mensagem entrando e resposta saindo, idempotência de reenvio,
assinatura do webhook, pausar/reiniciar/desconectar/reconectar,
transbordo humano, queda e recuperação de conexão, dois clientes
atendendo ao mesmo tempo sem se misturar, e a fronteira do painel
administrativo nas duas direções (cliente não entra; administrador não
alcança conversa nem credencial de cliente).

---

## Deploy

Qualquer hospedagem que rode Node e tenha um Postgres. As migrations
rodam sozinhas no boot, então o deploy é `git push`.

Variáveis obrigatórias: `DATABASE_URL`, `JWT_SECRET`, `CRYPTO_KEY`.
Praticamente obrigatória: `PUBLIC_URL` — é dela que sai a URL de webhook
que o cliente copia para o painel da Meta.

Para o painel de administração: `OWNER_EMAIL` e `OWNER_SENHA_HASH`. Sem
elas, `/owner` responde 503 — o painel não existe, em vez de existir com
uma senha padrão.

> **`CRYPTO_KEY` é a única variável cuja perda é irreversível.** Ela cifra
> os tokens da Meta guardados no banco. Trocá-la torna ilegíveis as
> credenciais de **todos** os clientes, e cada um terá que reconectar o
> WhatsApp na mão. Guarde uma cópia em lugar seguro.

O arquivo `render.yaml` deixa o deploy na Render em um clique.

---

## Arquitetura

```
src/
├── servidor.js              sobe, migra, liga o monitor, encerra limpo
├── app.js                   middlewares, CSP, rotas, arquivos estáticos
├── config.js                ambiente (falha cedo se faltar segredo)
├── db/
│   ├── index.js             pool do Postgres, consultas, transações
│   └── migrar.js            migrador idempotente
├── lib/
│   ├── cripto.js            AES-256-GCM para os tokens da Meta
│   ├── sessao.js            JWT HS256 escrito à mão
│   ├── validar.js           validação de tudo que entra
│   └── registro.js          log do cliente e notificações
├── middlewares/             autenticação, rate limit, erro
├── motor/motor.js           ⭐ o motor de conversa
└── modulos/
    ├── contas/              cadastro, login, painel
    ├── bots/                construtor, blocos, simulador, diagnóstico
    ├── whatsapp/            conexão, webhook, Cloud API, envio
    ├── conversas/           histórico e atendimento humano
    ├── owner/               painel do dono da plataforma
    └── monitor/             saúde das conexões e faxina
```

Duas decisões que explicam o resto:

**O motor de conversa não faz I/O.** `src/motor/motor.js` é uma função de
(estado, mensagem) para (respostas, novo estado). Não lê banco, não chama
a Meta, não olha o relógio sozinho. Isso permite testar o comportamento
inteiro do produto em milissegundos, faz o simulador do painel ser o
mesmo código que atende de verdade (não uma imitação que um dia diverge),
e deixa a porta aberta para outro canal sem tocar no motor.

**`conta_id` em toda tabela.** Inclusive onde daria para chegar por JOIN.
Uma consulta que esqueça o filtro devolve vazio, não o dado do vizinho —
e o `conta_id` sempre vem do token assinado, nunca da URL ou do corpo.

### O caminho de uma mensagem

```
cliente escreve no WhatsApp
   → Meta chama POST /webhook
   → confere assinatura (HMAC do corpo cru)
   → acha a conta pelo phone_number_id
   → responde 200 na hora  (demorar = a Meta reenvia = resposta duplicada)
   → em segundo plano:
        grava o evento (chave primária no wamid impede repetição)
        grava a mensagem recebida
        motor decide o que responder
        salva o novo estado da conversa
        envia pela Cloud API e grava o que saiu
```

### Segurança

- Senhas em bcrypt (custo 12); comparação roda mesmo sem usuário, para
  não vazar quais e-mails existem pelo tempo de resposta.
- Tokens da Meta cifrados em AES-256-GCM. Não voltam para o navegador
  nem para o dono que os cadastrou — só os quatro últimos caracteres.
- Webhook verificado por `X-Hub-Signature-256` sobre o corpo cru.
- JWT HS256 com comparação em tempo constante, algoritmo fixo no código
  (nunca lido do próprio token) e conferência no banco a cada requisição.
- CSP sem `unsafe-inline` em script — o painel não tem um único
  `<script>` inline nem atributo `onclick`.
- Toda consulta é parametrizada; nenhum valor entra concatenado no SQL.
- Todo texto de terceiro chega à tela por `textContent`, nunca `innerHTML`.

---

## Limites conhecidos

- **Rate limit em memória.** Com mais de uma instância, cada uma conta
  por si. Está isolado em `src/middlewares/limitar.js` — trocar por Redis
  é mudar aquela função.
- **Um número por conta.** O esquema já separa conta de conexão, então
  suportar vários é acrescentar a coluna e a tela, não refazer nada.
- **O bot é de texto.** Áudio, imagem e documento entram no histórico
  (o atendente humano vê), mas o motor não os interpreta.
- **Sem cobrança.** A coluna `plano` existe e não faz nada ainda.
- **Sem recuperação de senha por e-mail.** Trocar senha exige estar logado.
