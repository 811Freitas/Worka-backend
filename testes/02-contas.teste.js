"use strict";

/**
 * Cadastro, login e — o mais importante — separação entre clientes.
 */

var { teste, igual, verdade, contem, criarConta } = require("./ajuda");

var G = "Contas e acesso";

teste(G, "cadastro cria a conta com bot e fluxo de exemplo prontos", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "cadastro");

  verdade(conta.token, "veio token");

  // Uma conta que nasce vazia é onde a maioria das pessoas desiste: um
  // editor em branco não ensina o que é um bloco.
  var blocos = await ctx.cliente.get("/api/bot/blocos", conta.token);
  igual(blocos.status, 200);
  verdade(blocos.corpo.length >= 5, "o fluxo de exemplo deveria ter vindo junto");
  verdade(blocos.corpo.some(function (b) { return b.inicial; }), "algum bloco tem que ser o inicial");

  // A conexão também nasce, com o verify_token sorteado: a tela de
  // conexão precisa ter o que mostrar ANTES de o cliente preencher algo.
  var conexao = await ctx.cliente.get("/api/whatsapp/conexao", conta.token);
  igual(conexao.status, 200);
  igual(conexao.corpo.status, "desconectado");
  verdade(conexao.corpo.verify_token && conexao.corpo.verify_token.length > 20);
});

teste(G, "cadastro recusa e-mail repetido", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "repetido");

  var r = await ctx.cliente.post("/api/cadastro", {
    nome: "Outra Pessoa", email: conta.email, senha: "outra-senha-123"
  });

  igual(r.status, 409);
  contem(r.corpo.erro, "Já existe");
});

teste(G, "cadastro recusa e-mail inválido e senha curta", async function (ctx) {
  var semEmail = await ctx.cliente.post("/api/cadastro", {
    nome: "X", email: "nao-e-email", senha: "senha-boa-123"
  });
  igual(semEmail.status, 400);

  var senhaCurta = await ctx.cliente.post("/api/cadastro", {
    nome: "X", email: "curta" + Date.now() + "@exemplo.com", senha: "123"
  });
  igual(senhaCurta.status, 400);
});

teste(G, "login funciona e senha errada é recusada", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "login");

  var ok = await ctx.cliente.post("/api/login", { email: conta.email, senha: conta.senha });
  igual(ok.status, 200);
  verdade(ok.corpo.token);

  var ruim = await ctx.cliente.post("/api/login", { email: conta.email, senha: "senha-errada-999" });
  igual(ruim.status, 401);
  // A mensagem não diz QUAL dos dois estava errado: dizer "senha
  // incorreta" confirma que o e-mail existe.
  contem(ruim.corpo.erro, "E-mail ou senha");
});

teste(G, "rotas privadas recusam quem não tem token", async function (ctx) {
  // O defeito mais caro possível é uma rota que esqueceu de exigir
  // login. Esta lista existe para que ele nunca chegue à produção.
  var privadas = [
    ["GET", "/api/eu"],
    ["GET", "/api/bot"],
    ["GET", "/api/bot/blocos"],
    ["GET", "/api/whatsapp/conexao"],
    ["POST", "/api/whatsapp/conexao"],
    ["POST", "/api/whatsapp/enviar"],
    ["GET", "/api/conversas"],
    ["GET", "/api/painel/resumo"],
    ["GET", "/api/registros"],
    ["GET", "/api/notificacoes"]
  ];

  for (var [metodo, caminho] of privadas) {
    var r = await ctx.cliente.cru(metodo, caminho, metodo === "POST" ? {} : null, null);
    verdade(r.status === 401, caminho + " deveria responder 401, respondeu " + r.status);
  }
});

teste(G, "token adulterado é recusado", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "adulterado");

  // Troca o último caractere da assinatura. Um verificador que comparasse
  // strings sem conferir tamanho, ou que aceitasse alg:none, passaria.
  var partes = conta.token.split(".");
  var ultimo = partes[2].slice(-1) === "a" ? "b" : "a";
  var falso = partes[0] + "." + partes[1] + "." + partes[2].slice(0, -1) + ultimo;

  var r = await ctx.cliente.get("/api/eu", falso);
  igual(r.status, 401);
});

teste(G, "um cliente não enxerga nem altera os dados do outro", async function (ctx) {
  // O caso que justifica a coluna conta_id repetida em toda tabela.
  var alice = await criarConta(ctx.cliente, "alice");
  var bruno = await criarConta(ctx.cliente, "bruno");

  var blocosAlice = await ctx.cliente.get("/api/bot/blocos", alice.token);
  var blocoDaAlice = blocosAlice.corpo[0];

  var blocosBruno = await ctx.cliente.get("/api/bot/blocos", bruno.token);
  var idsBruno = blocosBruno.corpo.map(function (b) { return b.id; });

  verdade(idsBruno.indexOf(blocoDaAlice.id) === -1, "o bloco da Alice apareceu para o Bruno");

  // Bruno tem o uuid do bloco da Alice e tenta editar. O uuid nunca é
  // autorização por si só — o WHERE tem conta_id junto.
  var edicao = await ctx.cliente.put("/api/bot/blocos/" + blocoDaAlice.id,
    { titulo: "Invadido", mensagem: "hackeado" }, bruno.token);
  igual(edicao.status, 404, "editar bloco de outra conta deveria dar 404");

  var remocao = await ctx.cliente.delete("/api/bot/blocos/" + blocoDaAlice.id, bruno.token);
  igual(remocao.status, 404, "apagar bloco de outra conta deveria dar 404");

  // E o bloco continua intacto na conta da Alice.
  var conferindo = await ctx.cliente.get("/api/bot/blocos", alice.token);
  var aindaLa = conferindo.corpo.find(function (b) { return b.id === blocoDaAlice.id; });
  verdade(aindaLa && aindaLa.titulo !== "Invadido", "o bloco da Alice foi alterado por outra conta");
});

teste(G, "troca de senha exige a senha atual", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "senha");

  var semAtual = await ctx.cliente.post("/api/senha",
    { atual: "chute-errado-123", nova: "nova-senha-456" }, conta.token);
  igual(semAtual.status, 400);

  var ok = await ctx.cliente.post("/api/senha",
    { atual: conta.senha, nova: "nova-senha-456" }, conta.token);
  igual(ok.status, 200);

  var loginNovo = await ctx.cliente.post("/api/login", { email: conta.email, senha: "nova-senha-456" });
  igual(loginNovo.status, 200, "a senha nova deveria funcionar");

  var loginVelho = await ctx.cliente.post("/api/login", { email: conta.email, senha: conta.senha });
  igual(loginVelho.status, 401, "a senha antiga não pode continuar valendo");
});

teste(G, "GET /api/eu devolve a sessão para o F5 não deslogar", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "sessao");

  var r = await ctx.cliente.get("/api/eu", conta.token);
  igual(r.status, 200);
  igual(r.corpo.usuario.email, conta.email);
  igual(r.corpo.usuario.papel, "dono");
  verdade(typeof r.corpo.notificacoes_nao_lidas === "number");
});

teste(G, "rate limit barra cadastro em rajada", async function (ctx) {
  // Cadastro em rajada é criação de contas descartáveis, nunca gente de
  // verdade se cadastrando. O limite é 10 por hora, por IP.
  var barrou = false;

  for (var i = 0; i < 14; i++) {
    var r = await ctx.cliente.post("/api/cadastro", {
      nome: "Rajada", email: "rajada-" + i + "-" + Date.now() + "@exemplo.com", senha: "senha-boa-123"
    });
    if (r.status === 429) {
      barrou = true;
      verdade(r.cabecalhos["retry-after"], "o 429 deveria dizer quando tentar de novo");
      break;
    }
  }

  verdade(barrou, "o limite de cadastros não foi aplicado");
});

teste(G, "a senha nunca volta em nenhuma resposta", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "vazamento");

  var respostas = [
    await ctx.cliente.get("/api/eu", conta.token),
    await ctx.cliente.post("/api/login", { email: conta.email, senha: conta.senha })
  ];

  for (var r of respostas) {
    var texto = JSON.stringify(r.corpo);
    verdade(texto.indexOf("senha_hash") === -1, "senha_hash vazou numa resposta");
    verdade(texto.indexOf(conta.senha) === -1, "a senha em texto puro vazou numa resposta");
  }
});
