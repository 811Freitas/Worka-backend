"use strict";

/**
 * O construtor de chatbot: configuração, blocos, simulador e
 * diagnóstico do fluxo.
 */

var { teste, igual, verdade, contem, criarConta } = require("./ajuda");

var G = "Construtor de chatbot";

teste(G, "salva a personalização das mensagens do bot", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "config");

  var r = await ctx.cliente.put("/api/bot", {
    nome: "Atendimento da Padaria",
    mensagem_boas_vindas: "Bom dia! Aqui é a Padaria do Zé 🥖",
    mensagem_fallback: "Desculpa, não peguei. Escolhe uma opção:",
    expirar_apos_minutos: 120
  }, conta.token);

  igual(r.status, 200);
  igual(r.corpo.nome, "Atendimento da Padaria");
  contem(r.corpo.mensagem_boas_vindas, "Padaria do Zé");
  igual(r.corpo.expirar_apos_minutos, 120);

  // E a mudança está no banco de verdade, não só na resposta.
  var relido = await ctx.cliente.get("/api/bot", conta.token);
  contem(relido.corpo.mensagem_boas_vindas, "Padaria do Zé");
});

teste(G, "salva o horário de atendimento", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "horario");

  var r = await ctx.cliente.put("/api/bot", {
    atendimento_ativo: true,
    atendimento_inicio: "09:00",
    atendimento_fim: "17:30",
    atendimento_dias: [1, 2, 3, 4, 5, 6]
  }, conta.token);

  igual(r.status, 200);
  igual(r.corpo.atendimento_ativo, true);
  contem(r.corpo.atendimento_inicio, "09:00");
  igual(r.corpo.atendimento_dias.length, 6);

  var invalido = await ctx.cliente.put("/api/bot", { atendimento_dias: [9] }, conta.token);
  igual(invalido.status, 400, "dia 9 da semana não existe");
});

teste(G, "cria, edita e apaga um bloco", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "bloco");

  var criado = await ctx.cliente.post("/api/bot/blocos", {
    chave: "entrega",
    titulo: "Entrega",
    tipo: "menu",
    mensagem: "Entregamos em toda a cidade!",
    gatilhos: ["entrega", "delivery", "frete"],
    opcoes: [{ rotulo: "Voltar", proxima: "menu" }]
  }, conta.token);

  igual(criado.status, 201);
  igual(criado.corpo.chave, "entrega");
  igual(criado.corpo.gatilhos.length, 3);

  var editado = await ctx.cliente.put("/api/bot/blocos/" + criado.corpo.id, {
    mensagem: "Entregamos em toda a região metropolitana!"
  }, conta.token);
  igual(editado.status, 200);
  contem(editado.corpo.mensagem, "região metropolitana");
  // O que não foi enviado tem que sobreviver: o painel salva campo a
  // campo, e um PUT parcial que zera o resto apaga o trabalho do cliente.
  igual(editado.corpo.gatilhos.length, 3, "os gatilhos não podiam sumir");

  var apagado = await ctx.cliente.delete("/api/bot/blocos/" + criado.corpo.id, conta.token);
  igual(apagado.status, 200);
});

teste(G, "recusa dois blocos com o mesmo identificador", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "chave-dupla");

  var r = await ctx.cliente.post("/api/bot/blocos", {
    chave: "menu", titulo: "Outro menu", tipo: "menu", mensagem: "Oi"
  }, conta.token);

  igual(r.status, 409);
  contem(r.corpo.erro, "Já existe");
});

teste(G, "normaliza o identificador digitado com acento e espaço", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "chave-suja");

  var r = await ctx.cliente.post("/api/bot/blocos", {
    chave: "Preços Especiais!", titulo: "Preços", tipo: "menu", mensagem: "Confira"
  }, conta.token);

  igual(r.status, 201);
  igual(r.corpo.chave, "precos-especiais");
});

teste(G, "renomear a chave reescreve quem apontava para ela", async function (ctx) {
  // Sem isto, renomear quebraria o fluxo em silêncio: o menu continuaria
  // salvo, mas a opção levaria a lugar nenhum.
  var conta = await criarConta(ctx.cliente, "renomear");

  var blocos = await ctx.cliente.get("/api/bot/blocos", conta.token);
  var horario = blocos.corpo.find(function (b) { return b.chave === "horario"; });

  var r = await ctx.cliente.put("/api/bot/blocos/" + horario.id,
    { chave: "onde-estamos" }, conta.token);
  igual(r.status, 200);
  igual(r.corpo.chave, "onde-estamos");

  var depois = await ctx.cliente.get("/api/bot/blocos", conta.token);
  var menu = depois.corpo.find(function (b) { return b.chave === "menu"; });
  var apontamentos = menu.opcoes.map(function (o) { return o.proxima; });

  verdade(apontamentos.indexOf("onde-estamos") !== -1, "o menu deveria apontar para a chave nova");
  verdade(apontamentos.indexOf("horario") === -1, "sobrou apontamento para a chave antiga");
});

teste(G, "apagar um bloco limpa as opções que apontavam para ele", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "apagar-vinculo");

  var blocos = await ctx.cliente.get("/api/bot/blocos", conta.token);
  var horario = blocos.corpo.find(function (b) { return b.chave === "horario"; });

  await ctx.cliente.delete("/api/bot/blocos/" + horario.id, conta.token);

  var depois = await ctx.cliente.get("/api/bot/blocos", conta.token);
  var menu = depois.corpo.find(function (b) { return b.chave === "menu"; });

  verdade(menu.opcoes.every(function (o) { return o.proxima !== "horario"; }),
    "a opção órfã continuou no menu");
});

teste(G, "não deixa apagar o bloco inicial enquanto houver outros", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "inicial");

  var blocos = await ctx.cliente.get("/api/bot/blocos", conta.token);
  var inicial = blocos.corpo.find(function (b) { return b.inicial; });

  var r = await ctx.cliente.delete("/api/bot/blocos/" + inicial.id, conta.token);
  igual(r.status, 400);
  contem(r.corpo.erro, "inicial");
});

teste(G, "só existe um bloco inicial por vez", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "um-inicial");

  var novo = await ctx.cliente.post("/api/bot/blocos", {
    chave: "recepcao", titulo: "Recepção", tipo: "menu",
    mensagem: "Bem-vindo!", inicial: true,
    opcoes: [{ rotulo: "Menu", proxima: "menu" }]
  }, conta.token);
  igual(novo.status, 201);

  var blocos = await ctx.cliente.get("/api/bot/blocos", conta.token);
  var iniciais = blocos.corpo.filter(function (b) { return b.inicial; });
  igual(iniciais.length, 1, "dois blocos iniciais deixariam a conversa sem começo definido");
  igual(iniciais[0].chave, "recepcao");
});

teste(G, "recusa menu sem mensagem e mais de 10 opções", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "validacao");

  var semMensagem = await ctx.cliente.post("/api/bot/blocos", {
    chave: "mudo", titulo: "Mudo", tipo: "menu", mensagem: ""
  }, conta.token);
  igual(semMensagem.status, 400);

  var demais = [];
  for (var i = 0; i < 11; i++) demais.push({ rotulo: "Opção " + i, proxima: "menu" });

  var muitas = await ctx.cliente.post("/api/bot/blocos", {
    chave: "gigante", titulo: "Gigante", tipo: "menu", mensagem: "Escolha", opcoes: demais
  }, conta.token);
  // 10 é o teto da Cloud API. Aceitar 11 aqui produziria um bloco que o
  // cliente salva e que a Meta recusa só na hora de enviar.
  igual(muitas.status, 400);
});

// ════════════════════════════════════════
// SIMULADOR
// ════════════════════════════════════════
teste(G, "simulador conversa com o fluxo sem tocar no WhatsApp", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "simular");

  var passo1 = await ctx.cliente.post("/api/bot/simular", { mensagem: "oi" }, conta.token);
  igual(passo1.status, 200);
  verdade(passo1.corpo.respostas.length >= 2);
  igual(passo1.corpo.conversa.bloco_chave, "menu");

  var passo2 = await ctx.cliente.post("/api/bot/simular", {
    mensagem: "1", conversa: passo1.corpo.conversa
  }, conta.token);
  igual(passo2.corpo.conversa.bloco_chave, "produtos");

  // Nada foi gravado: simular não pode criar conversa nem contato.
  var conversas = await ctx.cliente.get("/api/conversas", conta.token);
  igual(conversas.corpo.length, 0, "o simulador criou linhas no banco");

  // E a Meta não foi chamada nenhuma vez.
  igual(ctx.meta.enviadas.length, 0);
});

teste(G, "simulador respeita a personalização salva", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "simular-config");

  await ctx.cliente.put("/api/bot",
    { mensagem_boas_vindas: "Salve! Aqui é a Barbearia Central ✂️" }, conta.token);

  var r = await ctx.cliente.post("/api/bot/simular", { mensagem: "oi" }, conta.token);
  contem(r.corpo.respostas[0].texto, "Barbearia Central");
});

teste(G, "simulador permite testar o horário sem esperar dar a hora", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "simular-hora");

  await ctx.cliente.put("/api/bot", {
    atendimento_ativo: true, atendimento_inicio: "08:00", atendimento_fim: "18:00"
  }, conta.token);

  var madrugada = await ctx.cliente.post("/api/bot/simular", {
    mensagem: "oi", agora: "2026-03-10T05:00:00Z"
  }, conta.token);

  verdade(madrugada.corpo.eventos.indexOf("fora_horario") !== -1);
  contem(madrugada.corpo.respostas[0].texto, "fora do horário");
});

teste(G, "simulador devolve os eventos que explicam a resposta", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "eventos");

  var r = await ctx.cliente.post("/api/bot/simular", {
    mensagem: "asdfghjkl", conversa: { bloco_chave: "menu" }
  }, conta.token);

  // É a diferença entre o cliente ver que o bot errou e entender ONDE.
  verdade(r.corpo.eventos.indexOf("fallback") !== -1);
});

// ════════════════════════════════════════
// DIAGNÓSTICO
// ════════════════════════════════════════
teste(G, "diagnóstico aprova o fluxo de exemplo", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "diag-ok");

  var r = await ctx.cliente.get("/api/bot/diagnostico", conta.token);
  igual(r.status, 200);
  igual(r.corpo.ok, true, "o fluxo que vem pronto não pode nascer com erro");
});

teste(G, "diagnóstico acusa opção apontando para bloco inexistente", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "diag-quebrado");

  await ctx.cliente.post("/api/bot/blocos", {
    chave: "quebrado", titulo: "Quebrado", tipo: "menu", mensagem: "Escolha:",
    gatilhos: ["quebrado"],
    opcoes: [{ rotulo: "Ir", proxima: "bloco-fantasma" }]
  }, conta.token);

  var r = await ctx.cliente.get("/api/bot/diagnostico", conta.token);
  igual(r.corpo.ok, false);
  verdade(r.corpo.problemas.some(function (p) {
    return p.nivel === "erro" && p.mensagem.indexOf("bloco-fantasma") !== -1;
  }), "o diagnóstico não apontou o destino inexistente");
});

teste(G, "diagnóstico avisa sobre bloco que ninguém alcança", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "diag-ilha");

  await ctx.cliente.post("/api/bot/blocos", {
    chave: "ilha", titulo: "Ilha", tipo: "menu", mensagem: "Ninguém chega aqui"
  }, conta.token);

  var r = await ctx.cliente.get("/api/bot/diagnostico", conta.token);
  verdade(r.corpo.problemas.some(function (p) {
    return p.bloco === "ilha" && p.mensagem.indexOf("inacess") !== -1;
  }), "bloco órfão deveria ser apontado");
});

teste(G, "restaurar o exemplo devolve um fluxo válido depois de apagar tudo", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "restaurar");

  var r = await ctx.cliente.post("/api/bot/blocos/restaurar-exemplo", {}, conta.token);
  igual(r.status, 200);
  verdade(r.corpo.length >= 5);

  var diag = await ctx.cliente.get("/api/bot/diagnostico", conta.token);
  igual(diag.corpo.ok, true);
});
