"use strict";

/**
 * O caminho completo: conectar, receber, responder, pausar, reiniciar,
 * desconectar e voltar sozinho.
 *
 * A Meta é falsa; todo o resto é real — banco, rotas, motor, cliente da
 * Cloud API, formato dos payloads.
 */

var { teste, igual, verdade, contem, criarConta, conectarWhatsapp,
      webhookMensagem, webhookBotao, assinar } = require("./ajuda");
var webhook = require("../src/modulos/whatsapp/webhook");
var monitor = require("../src/modulos/monitor");

var G = "WhatsApp de ponta a ponta";
/**
 * Um phone_number_id novo, registrado na Meta falsa na hora.
 *
 * Cada caso precisa do seu porque a plataforma só aceita um dono por
 * número — reaproveitar um id fixo faria os casos brigarem entre si por
 * um motivo que nada tem a ver com o que eles testam.
 */
var contadorPhone = 0;
function numeroNovo(ctx) {
  contadorPhone++;
  var id = String(800000000000000 + contadorPhone);
  ctx.meta.numeros[id] = { display_phone_number: "+55 11 90000-0000", verified_name: "Loja Teste" };
  return id;
}

/**
 * Entrega um webhook e ESPERA o trabalho terminar.
 *
 * A rota responde 200 antes de processar — é o que a Meta exige, e quem
 * demora vira reenvio. Sem esta espera, o teste conferiria o banco antes
 * de a mensagem ter sido gravada e falharia por corrida, não por defeito.
 */
async function entregar(ctx, corpo, segredo) {
  var cabecalhos = {};
  if (segredo !== null) {
    cabecalhos["X-Hub-Signature-256"] = assinar(corpo, segredo || "segredo-do-app");
  }
  var r = await ctx.cliente.post("/webhook", corpo, null, cabecalhos);
  await webhook.aguardarPendentes();
  return r;
}

// ════════════════════════════════════════
// CONEXÃO
// ════════════════════════════════════════
teste(G, "conecta com credenciais válidas e fica aguardando o webhook", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "conectar");

  var r = await ctx.cliente.post("/api/whatsapp/conexao", {
    phone_number_id: numeroNovo(ctx), token: "token-bom", app_secret: "segredo-do-app"
  }, conta.token);

  igual(r.status, 200);
  // Credencial boa prova que dá para ENVIAR. Receber depende do webhook,
  // que ainda não foi validado — mostrar "conectado" aqui seria meia
  // verdade, e o cliente descobriria a outra metade pelo consumidor dele.
  igual(r.corpo.status, "aguardando_webhook");
  igual(r.corpo.numero_exibicao, "+55 11 90000-0000");
  verdade(r.corpo.proximo_passo, "deveria dizer o que falta fazer");
});

teste(G, "o token nunca volta ao navegador", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "segredo");
  var wa = await conectarWhatsapp(ctx, conta.token);

  var r = await ctx.cliente.get("/api/whatsapp/conexao", conta.token);
  var texto = JSON.stringify(r.corpo);

  verdade(texto.indexOf("token-bom") === -1, "o token da Meta vazou para o painel");
  verdade(texto.indexOf("segredo-do-app") === -1, "o app secret vazou para o painel");
  // Mas o painel sabe que está configurado, e mostra o final para a
  // pessoa reconhecer qual token colou.
  igual(r.corpo.token_configurado, true);
  contem(r.corpo.token_final, "••••");
});

teste(G, "o token é guardado cifrado, não em texto puro", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "cifra");
  var wa = await conectarWhatsapp(ctx, conta.token);

  // Olhando direto no banco, como olharia quem tivesse um dump vazado.
  var linha = await ctx.db.uma("select token_cifrado from conexoes where conta_id=$1", [conta.conta.id]);
  verdade(linha.token_cifrado.indexOf("token-bom") === -1, "o token está legível no banco");
  igual(linha.token_cifrado.split(":").length, 3, "formato iv:tag:conteudo do AES-GCM");
});

teste(G, "recusa credencial inválida com uma explicação útil", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "token-ruim");

  var r = await ctx.cliente.post("/api/whatsapp/conexao", {
    phone_number_id: numeroNovo(ctx), token: "token-expirado"
  }, conta.token);

  igual(r.status, 400);
  // O erro 190 da Meta é o nº 1 na prática — quem gera um token
  // TEMPORÁRIO descobre 24h depois. A mensagem tem que dizer o que fazer.
  contem(r.corpo.erro, "PERMANENTE");
});

teste(G, "recusa telefone colado no lugar do Phone Number ID", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "id-errado");

  var r = await ctx.cliente.post("/api/whatsapp/conexao", {
    phone_number_id: "+55 11 98765-4321", token: "token-bom"
  }, conta.token);

  igual(r.status, 400);
  contem(r.corpo.erro, "Phone Number ID");
});

teste(G, "recusa um número que já pertence a outra conta", async function (ctx) {
  // O webhook descobre o dono da mensagem pelo phone_number_id. Dois
  // donos para o mesmo número tornariam essa pergunta sem resposta — e
  // um cliente acabaria respondendo as conversas do outro.
  var primeira = await criarConta(ctx.cliente, "dono-do-numero");
  var wa = await conectarWhatsapp(ctx, primeira.token);

  var segunda = await criarConta(ctx.cliente, "segundo-dono");
  var r = await ctx.cliente.post("/api/whatsapp/conexao", {
    phone_number_id: wa.phone_number_id, token: "token-bom"
  }, segunda.token);

  igual(r.status, 409, "deveria explicar, não estourar 500 de chave duplicada");
  contem(r.corpo.erro, "outra conta");
});

teste(G, "a Meta valida o webhook e a conexão fica pronta", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "webhook-ok");

  var conexao = await ctx.cliente.post("/api/whatsapp/conexao", {
    phone_number_id: numeroNovo(ctx), token: "token-bom", app_secret: "segredo-do-app"
  }, conta.token);

  var v = await ctx.cliente.get("/webhook?hub.mode=subscribe&hub.verify_token=" +
    encodeURIComponent(conexao.corpo.verify_token) + "&hub.challenge=12345");

  igual(v.status, 200);
  // Texto puro, não JSON: devolver JSON aqui faz a verificação falhar do
  // lado da Meta, com uma mensagem que não explica nada.
  igual(v.texto, "12345");

  var depois = await ctx.cliente.get("/api/whatsapp/conexao", conta.token);
  igual(depois.corpo.status, "conectado");
});

teste(G, "verificação com token errado é recusada", async function (ctx) {
  var r = await ctx.cliente.get("/webhook?hub.mode=subscribe&hub.verify_token=chute&hub.challenge=123");
  igual(r.status, 403);
});

// ════════════════════════════════════════
// RECEBER E RESPONDER
// ════════════════════════════════════════
teste(G, "mensagem recebida vira resposta do bot no WhatsApp", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "conversa");
  var wa = await conectarWhatsapp(ctx, conta.token);

  var r = await entregar(ctx, webhookMensagem(wa.phone_number_id, "5511999990001", "oi", "Joana"));
  igual(r.status, 200);

  // Boas-vindas + menu, saindo pela Cloud API de verdade.
  igual(ctx.meta.enviadas.length, 2);
  contem(ctx.meta.textos()[0], "assistente");

  // O menu de 3 opções virou botões — o formato certo da Cloud API.
  var menu = ctx.meta.enviadas[1].payload;
  igual(menu.type, "interactive");
  igual(menu.interactive.type, "button");
  igual(menu.interactive.action.buttons.length, 3);
  igual(menu.to, "5511999990001");

  // E tudo isso está no histórico do painel.
  var conversas = await ctx.cliente.get("/api/conversas", conta.token);
  igual(conversas.corpo.length, 1);
  igual(conversas.corpo[0].telefone, "5511999990001");
  igual(conversas.corpo[0].contato_nome, "Joana");
  igual(conversas.corpo[0].total_mensagens, 3, "1 recebida + 2 enviadas");
});

teste(G, "a conversa avança de verdade entre mensagens", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "navegar");
  var wa = await conectarWhatsapp(ctx, conta.token);
  var de = "5511999990002";

  await entregar(ctx, webhookMensagem(wa.phone_number_id, de, "oi"));
  ctx.meta.limpar();

  await entregar(ctx, webhookMensagem(wa.phone_number_id, de, "1"));   // Ver produtos
  contem(ctx.meta.textos().join(" "), "Plano Básico");

  ctx.meta.limpar();
  await entregar(ctx, webhookMensagem(wa.phone_number_id, de, "1"));   // Quero contratar
  contem(ctx.meta.textos().join(" "), "Qual é o seu nome?");

  ctx.meta.limpar();
  await entregar(ctx, webhookMensagem(wa.phone_number_id, de, "Carlos Andrade"));
  // A variável guardada apareceu na mensagem seguinte.
  contem(ctx.meta.textos().join(" "), "Prazer, Carlos Andrade");

  // O estado sobreviveu no banco entre uma mensagem e outra — que é o
  // que faz um deploy no meio do atendimento não zerar a conversa.
  var conversas = await ctx.cliente.get("/api/conversas", conta.token);
  var detalhe = await ctx.cliente.get("/api/conversas/" + conversas.corpo[0].id, conta.token);
  igual(detalhe.corpo.conversa.variaveis.nome, "Carlos Andrade");
});

teste(G, "toque em botão é entendido como escolha de menu", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "botao");
  var wa = await conectarWhatsapp(ctx, conta.token);
  var de = "5511999990003";

  await entregar(ctx, webhookMensagem(wa.phone_number_id, de, "oi"));
  ctx.meta.limpar();

  // A Meta manda o TÍTULO do botão, num lugar diferente do texto comum.
  await entregar(ctx, webhookBotao(wa.phone_number_id, de, "Horário e endereço"));
  contem(ctx.meta.textos().join(" "), "segunda a sexta");
});

teste(G, "palavra-chave leva direto ao ponto", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "atalho");
  var wa = await conectarWhatsapp(ctx, conta.token);

  await entregar(ctx, webhookMensagem(wa.phone_number_id, "5511999990004", "quanto custa o plano?"));
  contem(ctx.meta.textos().join(" "), "Plano Básico");
});

teste(G, "evento repetido não gera resposta em duplicata", async function (ctx) {
  // A Meta reenvia quando não recebe 200 rápido. Sem idempotência, o
  // cliente final recebe a mesma resposta duas ou três vezes — o defeito
  // mais visível que um bot pode ter.
  var conta = await criarConta(ctx.cliente, "duplicata");
  var wa = await conectarWhatsapp(ctx, conta.token);

  var evento = webhookMensagem(wa.phone_number_id, "5511999990005", "oi");

  await entregar(ctx, evento);
  var depoisDaPrimeira = ctx.meta.enviadas.length;

  await entregar(ctx, evento);   // o MESMO wamid
  await entregar(ctx, evento);

  igual(ctx.meta.enviadas.length, depoisDaPrimeira, "o reenvio gerou resposta repetida");
});

teste(G, "webhook com assinatura inválida é descartado", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "assinatura");
  var wa = await conectarWhatsapp(ctx, conta.token);

  var evento = webhookMensagem(wa.phone_number_id, "5511999990006", "oi");
  var r = await ctx.cliente.post("/webhook", evento, null,
    { "X-Hub-Signature-256": "sha256=" + "0".repeat(64) });

  igual(r.status, 401);
  await webhook.aguardarPendentes();
  igual(ctx.meta.enviadas.length, 0, "respondeu a um evento forjado");
});

teste(G, "mensagem para número desconhecido não derruba o webhook", async function (ctx) {
  var r = await entregar(ctx, webhookMensagem("999999999999999", "5511999990007", "oi"), null);
  // 200 de propósito: 4xx faria a Meta reenviar para sempre um evento
  // que nunca vai ter dono.
  igual(r.status, 200);
});

teste(G, "anexo sem texto entra no histórico e recebe o fallback", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "anexo");
  var wa = await conectarWhatsapp(ctx, conta.token);

  var evento = webhookMensagem(wa.phone_number_id, "5511999990008", "oi");
  await entregar(ctx, evento);
  ctx.meta.limpar();

  var audio = webhookMensagem(wa.phone_number_id, "5511999990008", "");
  audio.entry[0].changes[0].value.messages[0].type = "audio";
  delete audio.entry[0].changes[0].value.messages[0].text;
  audio.entry[0].changes[0].value.messages[0].audio = { id: "midia-1", mime_type: "audio/ogg" };

  await entregar(ctx, audio);

  // O bot não entende áudio — e responder "não entendi" é o certo. O que
  // não pode é a mensagem sumir do painel.
  contem(ctx.meta.textos().join(" "), "Não entendi");

  var conversas = await ctx.cliente.get("/api/conversas", conta.token);
  var detalhe = await ctx.cliente.get("/api/conversas/" + conversas.corpo[0].id, conta.token);
  verdade(detalhe.corpo.mensagens.some(function (m) { return m.tipo === "audio"; }),
    "o áudio não foi gravado no histórico");
});

teste(G, "recibo de entrega atualiza o status da mensagem", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "recibo");
  var wa = await conectarWhatsapp(ctx, conta.token);

  await entregar(ctx, webhookMensagem(wa.phone_number_id, "5511999990009", "oi"));
  var waId = ctx.meta.enviadas[0].wa_id;

  await entregar(ctx, {
    object: "whatsapp_business_account",
    entry: [{ id: "waba", changes: [{ field: "messages", value: {
      metadata: { phone_number_id: wa.phone_number_id },
      statuses: [{ id: waId, status: "read", recipient_id: "5511999990009" }]
    } }] }]
  });

  var conversas = await ctx.cliente.get("/api/conversas", conta.token);
  var detalhe = await ctx.cliente.get("/api/conversas/" + conversas.corpo[0].id, conta.token);
  var enviada = detalhe.corpo.mensagens.find(function (m) { return m.wa_id === waId; });

  igual(enviada.status, "lida");
});

// ════════════════════════════════════════
// PAUSAR, REINICIAR, DESCONECTAR
// ════════════════════════════════════════
teste(G, "pausado: grava a mensagem e não responde", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "pausar");
  var wa = await conectarWhatsapp(ctx, conta.token);

  var p = await ctx.cliente.post("/api/whatsapp/conexao/pausar", {}, conta.token);
  igual(p.corpo.status, "pausado");

  await entregar(ctx, webhookMensagem(wa.phone_number_id, "5511999990010", "oi"));

  igual(ctx.meta.enviadas.length, 0, "o bot respondeu estando pausado");

  // Mas a mensagem do cliente final está lá. Um bot mudo é um problema;
  // uma mensagem perdida é outro, muito pior.
  var conversas = await ctx.cliente.get("/api/conversas", conta.token);
  igual(conversas.corpo.length, 1);
  igual(conversas.corpo[0].total_mensagens, 1);
});

teste(G, "retomar volta a responder", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "retomar");
  var wa = await conectarWhatsapp(ctx, conta.token);

  await ctx.cliente.post("/api/whatsapp/conexao/pausar", {}, conta.token);
  var r = await ctx.cliente.post("/api/whatsapp/conexao/retomar", {}, conta.token);
  igual(r.corpo.status, "conectado");

  await entregar(ctx, webhookMensagem(wa.phone_number_id, "5511999990011", "oi"));
  verdade(ctx.meta.enviadas.length > 0, "não voltou a responder depois de retomar");
});

teste(G, "reiniciar revalida e destrava conversas presas em atendimento", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "reiniciar");
  var wa = await conectarWhatsapp(ctx, conta.token);

  // Alguém pediu atendente e ninguém atendeu. Sem destravar, o bot fica
  // mudo para essa pessoa para sempre.
  await entregar(ctx, webhookMensagem(wa.phone_number_id, "5511999990012", "quero falar com atendente"));

  var conversas = await ctx.cliente.get("/api/conversas", conta.token);
  igual(conversas.corpo[0].status, "humano");

  // Envelhece a conversa para além da hora que o reinício considera.
  await ctx.db.consultar(
    "update conversas set ultima_interacao_em = now() - interval '3 hours' where conta_id=$1",
    [conta.conta.id]
  );

  var r = await ctx.cliente.post("/api/whatsapp/conexao/reiniciar", {}, conta.token);
  igual(r.status, 200);
  igual(r.corpo.status, "conectado");
  igual(r.corpo.conversas_destravadas, 1);

  ctx.meta.limpar();
  await entregar(ctx, webhookMensagem(wa.phone_number_id, "5511999990012", "oi de novo"));
  verdade(ctx.meta.enviadas.length > 0, "a conversa continuou travada depois do reinício");
});

teste(G, "desconectar apaga as credenciais e troca o verify token", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "desconectar");
  var wa = await conectarWhatsapp(ctx, conta.token);
  var antes = wa;

  var r = await ctx.cliente.delete("/api/whatsapp/conexao", conta.token);
  igual(r.corpo.status, "desconectado");
  igual(r.corpo.token_configurado, false);

  // Verify token novo: o webhook antigo, que ainda pode estar cadastrado
  // no painel da Meta do cliente, deixa de casar com esta conta.
  verdade(r.corpo.verify_token !== antes.verify_token, "o verify token não foi trocado");

  var velho = await ctx.cliente.get("/webhook?hub.mode=subscribe&hub.verify_token=" +
    encodeURIComponent(antes.verify_token) + "&hub.challenge=x");
  igual(velho.status, 403);

  var linha = await ctx.db.uma("select token_cifrado from conexoes where conta_id=$1", [conta.conta.id]);
  igual(linha.token_cifrado, null, "a credencial continuou no banco depois de desconectar");
});

teste(G, "reconectar depois de desconectar volta a funcionar", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "reconectar");
  var wa = await conectarWhatsapp(ctx, conta.token);
  await ctx.cliente.delete("/api/whatsapp/conexao", conta.token);

  var wa = await conectarWhatsapp(ctx, conta.token);
  ctx.meta.limpar();

  await entregar(ctx, webhookMensagem(wa.phone_number_id, "5511999990013", "oi"));
  verdade(ctx.meta.enviadas.length > 0, "não voltou a atender depois de reconectar");
});

// ════════════════════════════════════════
// ATENDIMENTO HUMANO
// ════════════════════════════════════════
teste(G, "atendente assume, responde e o bot se cala", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "humano");
  var wa = await conectarWhatsapp(ctx, conta.token);
  var de = "5511999990014";

  await entregar(ctx, webhookMensagem(wa.phone_number_id, de, "oi"));
  var conversas = await ctx.cliente.get("/api/conversas", conta.token);
  var id = conversas.corpo[0].id;

  await ctx.cliente.post("/api/conversas/" + id + "/assumir", {}, conta.token);
  ctx.meta.limpar();

  var envio = await ctx.cliente.post("/api/whatsapp/enviar",
    { telefone: de, texto: "Oi! Aqui é a Paula, em que posso ajudar?" }, conta.token);
  igual(envio.status, 200);
  contem(ctx.meta.textos()[0], "Aqui é a Paula");

  // O bot não pode emendar "não entendi" embaixo da fala da atendente.
  ctx.meta.limpar();
  await entregar(ctx, webhookMensagem(wa.phone_number_id, de, "queria trocar meu pedido"));
  igual(ctx.meta.enviadas.length, 0, "o bot falou por cima da atendente");

  // Devolver ao bot volta a automação, preservando o ponto do fluxo.
  await ctx.cliente.post("/api/conversas/" + id + "/devolver", {}, conta.token);
  await entregar(ctx, webhookMensagem(wa.phone_number_id, de, "menu"));
  verdade(ctx.meta.enviadas.length > 0, "o bot não voltou depois de devolvida");
});

teste(G, "envio manual recusa telefone inválido", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "envio-invalido");
  var wa = await conectarWhatsapp(ctx, conta.token);

  var r = await ctx.cliente.post("/api/whatsapp/enviar",
    { telefone: "123", texto: "oi" }, conta.token);
  igual(r.status, 400);
});

// ════════════════════════════════════════
// MONITOR E RECUPERAÇÃO
// ════════════════════════════════════════
teste(G, "token revogado derruba a conexão e avisa o dono", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "monitor-queda");
  var wa = await conectarWhatsapp(ctx, conta.token);

  // A Meta passa a recusar o token — exatamente o que acontece quando
  // ele expira ou é revogado, sem aviso nenhum.
  ctx.meta.tokensValidos.delete("token-bom");
  try {
    await monitor.verificarTodas();

    var conexao = await ctx.cliente.get("/api/whatsapp/conexao", conta.token);
    igual(conexao.corpo.status, "erro");
    contem(conexao.corpo.ultimo_erro, "recusado");

    // E o cliente é avisado: um bot mudo é indistinguível de um bot sem
    // clientes, e ninguém abre a tela de logs por acaso.
    var avisos = await ctx.cliente.get("/api/notificacoes", conta.token);
    verdade(avisos.corpo.some(function (n) { return n.tipo === "conexao_caiu"; }),
      "o dono não foi notificado da queda");
  } finally {
    ctx.meta.tokensValidos.add("token-bom");
  }
});

teste(G, "conexão que volta sozinha é recuperada e o aviso antigo é baixado", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "monitor-volta");
  var wa = await conectarWhatsapp(ctx, conta.token);

  ctx.meta.tokensValidos.delete("token-bom");
  await monitor.verificarTodas();
  ctx.meta.tokensValidos.add("token-bom");

  var resumo = await monitor.verificarTodas();
  verdade(resumo.recuperadas >= 1, "a recuperação não foi contabilizada");

  var conexao = await ctx.cliente.get("/api/whatsapp/conexao", conta.token);
  igual(conexao.corpo.status, "conectado");
  igual(conexao.corpo.ultimo_erro, null);

  var avisos = await ctx.cliente.get("/api/notificacoes", conta.token);
  var queda = avisos.corpo.find(function (n) { return n.tipo === "conexao_caiu"; });
  // "Seu WhatsApp parou" ao lado de "voltou ao normal" deixa o cliente
  // sem saber em qual acreditar.
  verdade(!queda || queda.lida, "o aviso de queda continuou aberto depois da recuperação");
  verdade(avisos.corpo.some(function (n) { return n.tipo === "conexao_voltou"; }));
});

teste(G, "instabilidade passageira da Meta não derruba a conexão", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "instabilidade");
  var wa = await conectarWhatsapp(ctx, conta.token);

  ctx.meta.forcarInstabilidade = true;
  try {
    await monitor.verificarTodas();

    var conexao = await ctx.cliente.get("/api/whatsapp/conexao", conta.token);
    // Marcar "erro" a cada oscilação faria o cliente correr para
    // reconectar um número que nunca saiu do ar.
    igual(conexao.corpo.status, "conectado");
  } finally {
    ctx.meta.forcarInstabilidade = false;
  }
});

teste(G, "falha de envio é registrada na mensagem, não escondida", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "falha-envio");
  var wa = await conectarWhatsapp(ctx, conta.token);

  ctx.meta.forcarInstabilidade = true;
  try {
    await entregar(ctx, webhookMensagem(wa.phone_number_id, "5511999990015", "oi"));
  } finally {
    ctx.meta.forcarInstabilidade = false;
  }

  var conversas = await ctx.cliente.get("/api/conversas", conta.token);
  var detalhe = await ctx.cliente.get("/api/conversas/" + conversas.corpo[0].id, conta.token);
  var falhou = detalhe.corpo.mensagens.find(function (m) { return m.status === "falha"; });

  verdade(falhou, "a mensagem que não saiu deveria estar marcada como falha");
  verdade(falhou.erro, "e com o motivo junto");
});

// ════════════════════════════════════════
// PAINEL
// ════════════════════════════════════════
teste(G, "o resumo do painel conta o que aconteceu de verdade", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "resumo");
  var wa = await conectarWhatsapp(ctx, conta.token);

  await entregar(ctx, webhookMensagem(wa.phone_number_id, "5511999990016", "oi"));
  await entregar(ctx, webhookMensagem(wa.phone_number_id, "5511999990017", "oi"));

  var r = await ctx.cliente.get("/api/painel/resumo", conta.token);
  igual(r.status, 200);
  igual(r.corpo.numeros.contatos, 2);
  igual(r.corpo.numeros.conversas_total, 2);
  igual(r.corpo.numeros.recebidas_24h, 2);
  verdade(r.corpo.numeros.enviadas_24h >= 4);
  igual(r.corpo.conexao.status, "conectado");
  igual(r.corpo.serie.length, 7, "sete dias, inclusive os vazios");
});

teste(G, "editar o fluxo vale na mensagem seguinte, sem reconectar", async function (ctx) {
  // É a promessa central do produto: mexer no bot não derruba o WhatsApp.
  var conta = await criarConta(ctx.cliente, "editar-ao-vivo");
  var wa = await conectarWhatsapp(ctx, conta.token);

  await entregar(ctx, webhookMensagem(wa.phone_number_id, "5511999990018", "oi"));

  await ctx.cliente.put("/api/bot",
    { mensagem_boas_vindas: "MENSAGEM NOVA EM PRODUÇÃO" }, conta.token);

  ctx.meta.limpar();
  await entregar(ctx, webhookMensagem(wa.phone_number_id, "5511999990019", "oi"));
  contem(ctx.meta.textos()[0], "MENSAGEM NOVA EM PRODUÇÃO");

  // E a conexão continua a mesma, sem nenhum passo de reconexão.
  var conexao = await ctx.cliente.get("/api/whatsapp/conexao", conta.token);
  igual(conexao.corpo.status, "conectado");
});

teste(G, "dois clientes atendem ao mesmo tempo sem se misturar", async function (ctx) {
  // O teste que justifica a arquitetura multi-inquilino inteira.
  var loja = await criarConta(ctx.cliente, "loja");
  var clinica = await criarConta(ctx.cliente, "clinica");

  var waLoja = await conectarWhatsapp(ctx, loja.token);

  // Um segundo número, de outro cliente, na mesma plataforma.
  ctx.meta.numeros["555444333222111"] = {
    display_phone_number: "+55 21 90000-0000", verified_name: "Clínica Teste"
  };
  var waClinica = await conectarWhatsapp(ctx, clinica.token);

  await ctx.cliente.put("/api/bot", { mensagem_boas_vindas: "Bem-vindo à LOJA" }, loja.token);
  await ctx.cliente.put("/api/bot", { mensagem_boas_vindas: "Bem-vindo à CLÍNICA" }, clinica.token);

  ctx.meta.limpar();
  await entregar(ctx, webhookMensagem(waLoja.phone_number_id, "5511888880001", "oi"));
  await entregar(ctx, webhookMensagem(waClinica.phone_number_id, "5521888880002", "oi"));

  var textos = ctx.meta.textos().join(" | ");
  contem(textos, "Bem-vindo à LOJA");
  contem(textos, "Bem-vindo à CLÍNICA");

  // Cada painel só enxerga a própria conversa.
  var daLoja = await ctx.cliente.get("/api/conversas", loja.token);
  var daClinica = await ctx.cliente.get("/api/conversas", clinica.token);

  igual(daLoja.corpo.length, 1);
  igual(daClinica.corpo.length, 1);
  igual(daLoja.corpo[0].telefone, "5511888880001");
  igual(daClinica.corpo[0].telefone, "5521888880002");
});
