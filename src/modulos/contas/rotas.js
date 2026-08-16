"use strict";

/**
 * Cadastro, login e dados da conta.
 */

var express = require("express");
var bcrypt = require("bcryptjs");

var db = require("../../db");
var config = require("../../config");
var v = require("../../lib/validar");
var sessao = require("../../lib/sessao");
var cripto = require("../../lib/cripto");
var registro = require("../../lib/registro");
var { rota, ErroHttp } = require("../../middlewares/erro");
var { limitar } = require("../../middlewares/limitar");
var { exigirLogin } = require("../../middlewares/autenticar");
var { criarExemplo } = require("../bots/exemplo");
var { diasRestantes } = require("../../lib/contaEstado");

// 7 dias, sem cartão. É a mesma janela do Workap: tempo suficiente para
// montar um fluxo, conectar o WhatsApp e ver o bot atender de verdade
// antes de decidir se vale pagar — curto o bastante para não virar uso
// grátis por tempo indeterminado disfarçado de trial.
var DIAS_TRIAL = 7;

var router = express.Router();

/**
 * Resposta padrão de sessão. Um único formato para cadastro e login —
 * duas formas diferentes obrigariam o front a tratar os dois casos, e é
 * onde nasce a tela que funciona no cadastro e quebra no login.
 */
function respostaSessao(usuario, conta) {
  return {
    token: sessao.assinar({ uid: usuario.id, cid: usuario.conta_id, papel: usuario.papel }),
    usuario: {
      id: usuario.id, nome: usuario.nome, email: usuario.email, papel: usuario.papel
    },
    conta: {
      id: conta.id, nome: conta.nome, plano: conta.plano, status: conta.status,
      trial_fim: conta.trial_fim || null,
      trial_dias_restantes: conta.status === "trial" ? diasRestantes(conta.trial_fim) : null
    }
  };
}

// ════════════════════════════════════════
// CADASTRO
// ════════════════════════════════════════
// Limite baixo: cadastro em rajada é criação de contas descartáveis,
// nunca gente de verdade se cadastrando.
router.post("/cadastro", limitar(10, 60 * 60 * 1000, "cadastro"), rota(async function (req, res) {
  var nome = v.texto(req.body.nome, v.LIMITES.nome);
  var empresa = v.texto(req.body.empresa, v.LIMITES.nome) || nome;
  var email = v.email(req.body.email);
  var senha = v.senha(req.body.senha);

  if (!nome) throw new ErroHttp(400, "Informe seu nome.");
  if (!email) throw new ErroHttp(400, "E-mail inválido.");
  if (!senha) throw new ErroHttp(400, "A senha precisa ter pelo menos 8 caracteres.");

  var jaExiste = await db.uma("select id from usuarios where lower(email) = lower($1)", [email]);
  if (jaExiste) {
    // Dizer que o e-mail já existe permite descobrir quem é cliente da
    // plataforma testando e-mails. É um vazamento real — e ainda assim a
    // mensagem é explícita, porque escondê-la produz o cadastro que
    // "falha sem motivo" para quem simplesmente esqueceu que já tem
    // conta. O custo de esconder é maior que o de contar, para este
    // produto: quem tem conta descobre isso de qualquer forma na tela de
    // recuperação de senha.
    throw new ErroHttp(409, "Já existe uma conta com este e-mail. Tente entrar.");
  }

  var senhaHash = await bcrypt.hash(senha, config.BCRYPT_ROUNDS);

  // Tudo numa transação: conta + usuário + bot + fluxo de exemplo +
  // conexão. Se o fluxo falhasse depois do usuário, a pessoa ficaria com
  // um login que abre um painel quebrado — e sem poder se cadastrar de
  // novo, porque o e-mail já estaria em uso.
  var criado = await db.transacao(async function (cliente) {
    var trialFim = new Date(Date.now() + DIAS_TRIAL * 24 * 60 * 60 * 1000);
    var conta = (await cliente.query(
      "insert into contas (nome, status, trial_fim) values ($1,'trial',$2) returning *",
      [empresa, trialFim]
    )).rows[0];

    var usuario = (await cliente.query(
      `insert into usuarios (conta_id, nome, email, senha_hash, papel)
       values ($1,$2,$3,$4,'dono') returning *`,
      [conta.id, nome, email, senhaHash]
    )).rows[0];

    var bot = (await cliente.query(
      "insert into bots (conta_id, nome) values ($1,$2) returning *",
      [conta.id, "Atendimento " + empresa]
    )).rows[0];

    await criarExemplo(cliente, conta.id, bot.id);

    // A linha de conexão nasce junto, já com o verify_token sorteado.
    // Assim a tela de conexão tem o que mostrar (URL do webhook e token
    // para colar na Meta) ANTES de o cliente preencher qualquer coisa —
    // que é justamente a ordem em que a configuração na Meta acontece.
    await cliente.query(
      "insert into conexoes (conta_id, verify_token) values ($1,$2)",
      [conta.id, cripto.segredoAleatorio(24)]
    );

    return { conta: conta, usuario: usuario };
  });

  registro.info(criado.conta.id, "conta_criada", "Conta criada por " + email);

  res.status(201).json(respostaSessao(criado.usuario, criado.conta));
}));

// ════════════════════════════════════════
// LOGIN
// ════════════════════════════════════════
router.post("/login", limitar(10, 15 * 60 * 1000, "login"), rota(async function (req, res) {
  var email = v.email(req.body.email);
  var senha = typeof req.body.senha === "string" ? req.body.senha : "";

  var usuario = email
    ? await db.uma(
        `select u.*, c.nome as conta_nome, c.plano, c.status as conta_status, c.trial_fim
           from usuarios u join contas c on c.id = u.conta_id
          where lower(u.email) = lower($1)`,
        [email]
      )
    : null;

  // bcrypt roda mesmo sem usuário, contra um hash descartável. Sem isso,
  // "e-mail não existe" responde em 1ms e "senha errada" em 100ms — e
  // essa diferença permite descobrir quais e-mails têm conta sem nem
  // olhar a mensagem de erro.
  var hashParaComparar = usuario ? usuario.senha_hash : "$2a$12$invalidoinvalidoinvalidoinvalidoinvalidoinvalidoinvalid";
  var confere = await bcrypt.compare(senha, hashParaComparar);

  if (!usuario || !confere || !usuario.ativo) {
    throw new ErroHttp(401, "E-mail ou senha incorretos.");
  }

  await db.consultar("update usuarios set ultimo_login_em = now() where id = $1", [usuario.id]);

  res.json(respostaSessao(usuario, {
    id: usuario.conta_id, nome: usuario.conta_nome,
    plano: usuario.plano, status: usuario.conta_status, trial_fim: usuario.trial_fim
  }));
}));

// ════════════════════════════════════════
// SESSÃO ATUAL
// ════════════════════════════════════════
// O painel chama isto ao abrir, com o token guardado no navegador. É o
// que faz o F5 não deslogar — e é onde um token de usuário desativado
// morre, porque exigirLogin confere no banco.
router.get("/eu", exigirLogin, rota(async function (req, res) {
  var naoLidas = await db.uma(
    "select count(*)::int as total from notificacoes where conta_id=$1 and not lida",
    [req.contaId]
  );

  res.json({
    usuario: {
      id: req.usuario.id, nome: req.usuario.nome,
      email: req.usuario.email, papel: req.usuario.papel
    },
    conta: {
      id: req.usuario.conta_id, nome: req.usuario.conta_nome,
      plano: req.usuario.plano, status: req.usuario.conta_status,
      trial_fim: req.usuario.trial_fim,
      trial_dias_restantes: req.usuario.conta_status === "trial"
        ? diasRestantes(req.usuario.trial_fim) : null
    },
    notificacoes_nao_lidas: naoLidas.total
  });
}));

// ════════════════════════════════════════
// TROCAR A SENHA
// ════════════════════════════════════════
router.post("/senha", exigirLogin, rota(async function (req, res) {
  var atual = typeof req.body.atual === "string" ? req.body.atual : "";
  var nova = v.senha(req.body.nova);

  if (!nova) throw new ErroHttp(400, "A nova senha precisa ter pelo menos 8 caracteres.");

  var linha = await db.uma("select senha_hash from usuarios where id=$1", [req.usuario.id]);
  // Confere a senha atual mesmo com a pessoa logada: se o token vazar
  // (aba aberta num computador emprestado), sem esta checagem quem
  // pegasse o token trocaria a senha e tomaria a conta para sempre.
  if (!(await bcrypt.compare(atual, linha.senha_hash))) {
    throw new ErroHttp(400, "Senha atual incorreta.");
  }

  await db.consultar("update usuarios set senha_hash=$1 where id=$2",
    [await bcrypt.hash(nova, config.BCRYPT_ROUNDS), req.usuario.id]);

  registro.info(req.contaId, "senha_alterada", "Senha alterada por " + req.usuario.email);
  res.json({ ok: true });
}));

// ════════════════════════════════════════
// NOTIFICAÇÕES
// ════════════════════════════════════════
router.get("/notificacoes", exigirLogin, rota(async function (req, res) {
  res.json(await db.varias(
    "select * from notificacoes where conta_id=$1 order by criado_em desc limit 50",
    [req.contaId]
  ));
}));

router.post("/notificacoes/lidas", exigirLogin, rota(async function (req, res) {
  await db.consultar("update notificacoes set lida = true where conta_id=$1 and not lida", [req.contaId]);
  res.json({ ok: true });
}));

// ════════════════════════════════════════
// REGISTROS (logs do cliente)
// ════════════════════════════════════════
router.get("/registros", exigirLogin, rota(async function (req, res) {
  var limite = v.inteiro(req.query.limite, 1, 200, 100);
  var nivel = v.umDe(req.query.nivel, ["info", "aviso", "erro"]);

  // O filtro por conta_id não é opcional em nenhuma consulta deste
  // projeto: é ele que impede o log de um cliente aparecer no painel de
  // outro. `$1` vem do token, nunca da query string.
  var sql = "select * from registros where conta_id=$1";
  var params = [req.contaId];
  if (nivel) { sql += " and nivel=$2"; params.push(nivel); }
  sql += " order by criado_em desc limit " + limite;

  res.json(await db.varias(sql, params));
}));

module.exports = router;
