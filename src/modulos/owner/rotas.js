"use strict";

/**
 * PAINEL DO DONO DA PLATAFORMA
 * ════════════════════════════════════════════════════════════
 * A visão de quem administra o Zapfy: quantas contas existem, quais
 * estão com o WhatsApp caído, quem parou de usar, quem cresceu.
 *
 * É o único módulo do sistema que consulta SEM filtrar por conta_id — e
 * por isso é o único que precisa de um portão próprio (exigirOwner).
 *
 * A LINHA QUE ESTE ARQUIVO NÃO CRUZA: nenhuma rota aqui devolve o
 * conteúdo das conversas dos clientes nem as credenciais da Meta que
 * eles cadastraram. Saber que a conta X trocou 400 mensagens ontem é
 * administrar a plataforma; ler o que o consumidor final escreveu para
 * aquela empresa é outra coisa, não é necessária para operar o negócio,
 * e é o tipo de acesso que destrói a confiança de um cliente no dia em
 * que ele descobre que existe.
 * ════════════════════════════════════════════════════════════
 */

var express = require("express");
var bcrypt = require("bcryptjs");

var db = require("../../db");
var config = require("../../config");
var v = require("../../lib/validar");
var sessao = require("../../lib/sessao");
var { rota, ErroHttp } = require("../../middlewares/erro");
var { limitar } = require("../../middlewares/limitar");
var { exigirOwner } = require("../../middlewares/autenticar");

var router = express.Router();

// ════════════════════════════════════════
// LOGIN
// ════════════════════════════════════════
// Limite bem mais apertado que o login de cliente: esta é a chave-mestra
// da plataforma inteira, e não existe "esqueci a senha" para ela.
router.post("/login", limitar(5, 15 * 60 * 1000, "owner-login"), rota(async function (req, res) {
  if (!config.OWNER_EMAIL || !config.OWNER_SENHA_HASH) {
    // 503 e não 401: a diferença importa para quem está configurando o
    // servidor. "Não configurado" manda olhar as variáveis de ambiente;
    // "senha errada" mandaria tentar outra senha, para sempre.
    throw new ErroHttp(503, "Painel administrativo não configurado neste servidor.");
  }

  var email = v.email(req.body.email);
  var senha = typeof req.body.senha === "string" ? req.body.senha : "";

  // bcrypt roda mesmo com o e-mail errado, contra um hash descartável —
  // senão o tempo de resposta revelaria qual é o e-mail do dono.
  var hashParaComparar = (email && email === config.OWNER_EMAIL)
    ? config.OWNER_SENHA_HASH
    : "$2a$12$invalidoinvalidoinvalidoinvalidoinvalidoinvalidoinvalid";

  var confere = await bcrypt.compare(senha, hashParaComparar);

  if (!confere || email !== config.OWNER_EMAIL) {
    console.warn("[owner] tentativa de login recusada");
    throw new ErroHttp(401, "E-mail ou senha incorretos.");
  }

  console.log("[owner] login administrativo em", new Date().toISOString());

  res.json({
    token: sessao.assinar({ owner: true, email: config.OWNER_EMAIL }),
    owner: { email: config.OWNER_EMAIL }
  });
}));

// A partir daqui, tudo exige o token administrativo.
router.use(exigirOwner);

router.get("/eu", rota(async function (req, res) {
  res.json({ owner: req.owner });
}));

// ════════════════════════════════════════
// RESUMO DA PLATAFORMA
// ════════════════════════════════════════
router.get("/resumo", rota(async function (req, res) {
  var n = await db.uma(`
    select
      (select count(*)::int from contas)                                        as contas_total,
      (select count(*)::int from contas where status = 'ativa')                 as contas_ativas,
      (select count(*)::int from contas where status = 'trial')                 as contas_trial,
      (select count(*)::int from contas where status = 'inadimplente')          as contas_inadimplentes,
      (select count(*)::int from contas where status = 'suspensa')              as contas_suspensas,
      (select count(*)::int from contas where criado_em > now() - interval '7 days')  as contas_7d,
      (select count(*)::int from contas where criado_em > now() - interval '30 days') as contas_30d,
      (select count(*)::int from usuarios)                                      as usuarios,

      (select count(*)::int from conexoes where status = 'conectado')           as conectadas,
      (select count(*)::int from conexoes where status = 'erro')                as com_erro,
      (select count(*)::int from conexoes where status = 'pausado')             as pausadas,
      (select count(*)::int from conexoes
         where status in ('desconectado','aguardando_webhook'))                 as nao_conectadas,

      (select count(*)::int from mensagens where criado_em > now() - interval '24 hours') as mensagens_24h,
      (select count(*)::int from mensagens where criado_em > now() - interval '7 days')   as mensagens_7d,
      (select count(*)::int from mensagens
         where status = 'falha' and criado_em > now() - interval '24 hours')     as falhas_24h,

      (select count(*)::int from conversas where ultima_interacao_em > now() - interval '24 hours') as conversas_24h,
      (select count(*)::int from contatos)                                      as contatos
  `);

  // Contas que USARAM a plataforma (não só se cadastraram). É a métrica
  // que diz se o produto está vivo — cadastro sem uso é vaidade.
  var ativas = await db.uma(`
    select count(distinct conta_id)::int as total
      from mensagens where criado_em > now() - interval '7 days'
  `);

  // Volume diário dos últimos 14 dias, com os dias vazios preenchidos.
  var serie = await db.varias(`
    select to_char(d.dia, 'YYYY-MM-DD') as dia,
           coalesce(count(m.id), 0)::int as mensagens,
           coalesce(count(distinct m.conta_id), 0)::int as contas
      from generate_series(current_date - interval '13 days', current_date, interval '1 day') d(dia)
      left join mensagens m on m.criado_em >= d.dia and m.criado_em < d.dia + interval '1 day'
     group by d.dia order by d.dia
  `);

  res.json({
    numeros: Object.assign({}, n, { contas_usando_7d: ativas.total }),
    serie: serie
  });
}));

// ════════════════════════════════════════
// CONTAS
// ════════════════════════════════════════
router.get("/contas", rota(async function (req, res) {
  var limite = v.inteiro(req.query.limite, 1, 200, 100);
  var filtro = v.umDe(req.query.filtro, ["todas", "ativas", "trial", "inadimplentes", "suspensas", "com_erro", "sem_conexao", "inativas"]) || "todas";
  var busca = req.query.busca ? String(req.query.busca).slice(0, 60) : null;

  var condicoes = [];
  var params = [];

  if (filtro === "ativas")       condicoes.push("c.status = 'ativa'");
  if (filtro === "trial")        condicoes.push("c.status = 'trial'");
  if (filtro === "inadimplentes") condicoes.push("c.status = 'inadimplente'");
  if (filtro === "suspensas")    condicoes.push("c.status = 'suspensa'");
  if (filtro === "com_erro")    condicoes.push("x.status = 'erro'");
  if (filtro === "sem_conexao") condicoes.push("(x.status is null or x.status in ('desconectado','aguardando_webhook'))");
  // "Inativa" é conta sem mensagem nenhuma nos últimos 14 dias. É a
  // lista de quem provavelmente vai cancelar — e a única com a qual dá
  // para fazer algo antes que aconteça.
  if (filtro === "inativas") {
    condicoes.push(`not exists (
      select 1 from mensagens m
       where m.conta_id = c.id and m.criado_em > now() - interval '14 days'
    )`);
  }

  if (busca) {
    params.push("%" + busca + "%");
    condicoes.push(`(c.nome ilike $${params.length} or exists (
      select 1 from usuarios u where u.conta_id = c.id and u.email ilike $${params.length}
    ))`);
  }

  var onde = condicoes.length ? "where " + condicoes.join(" and ") : "";

  // Um LEFT JOIN LATERAL por métrica, em vez de uma consulta por conta.
  // Com 500 contas na tela, o caminho ingênuo seria 1500 idas ao banco.
  var lista = await db.varias(`
    select c.id, c.nome, c.plano, c.status, c.criado_em, c.suspensa_em, c.observacao, c.trial_fim,
           x.status          as conexao_status,
           x.numero_exibicao as numero,
           x.ultimo_erro     as conexao_erro,
           x.verificado_em   as conexao_verificada_em,
           coalesce(u.total, 0)  as usuarios,
           coalesce(m7.total, 0) as mensagens_7d,
           m7.ultima             as ultima_mensagem,
           coalesce(cv.total, 0) as conversas,
           d.email               as email_dono
      from contas c
      left join conexoes x on x.conta_id = c.id
      left join lateral (
        select count(*)::int as total from usuarios where conta_id = c.id
      ) u on true
      left join lateral (
        select count(*)::int as total, max(criado_em) as ultima
          from mensagens where conta_id = c.id and criado_em > now() - interval '7 days'
      ) m7 on true
      left join lateral (
        select count(*)::int as total from conversas where conta_id = c.id
      ) cv on true
      left join lateral (
        select email from usuarios
         where conta_id = c.id and papel = 'dono' order by criado_em limit 1
      ) d on true
      ${onde}
     order by c.criado_em desc
     limit ${limite}
  `, params);

  res.json(lista);
}));

router.get("/contas/:id", rota(async function (req, res) {
  var id = v.uuid(req.params.id);
  if (!id) throw new ErroHttp(400, "Conta inválida.");

  var conta = await db.uma("select * from contas where id = $1", [id]);
  if (!conta) throw new ErroHttp(404, "Conta não encontrada.");

  var usuarios = await db.varias(
    "select id, nome, email, papel, ativo, ultimo_login_em, criado_em from usuarios where conta_id=$1 order by criado_em",
    [id]
  );

  // Note o que NÃO é selecionado: token_cifrado e app_secret_cifrado.
  // Nem cifrados eles saem daqui — não há motivo administrativo para o
  // dono da plataforma sequer ver que forma eles têm.
  var conexao = await db.uma(`
    select status, provedor, phone_number_id, numero_exibicao, nome_exibicao,
           ultimo_erro, ultimo_erro_em, verificado_em, conectado_em,
           webhook_verificado_em, total_enviadas, total_recebidas,
           (token_cifrado is not null)      as token_configurado,
           (app_secret_cifrado is not null) as app_secret_configurado
      from conexoes where conta_id = $1
  `, [id]);

  var bot = await db.uma(
    `select b.id, b.nome, b.ativo, b.atendimento_ativo, b.atualizado_em,
            (select count(*)::int from blocos where bot_id = b.id) as blocos
       from bots b where b.conta_id = $1 and b.ativo limit 1`,
    [id]
  );

  var uso = await db.uma(`
    select
      (select count(*)::int from conversas where conta_id = $1) as conversas,
      (select count(*)::int from contatos  where conta_id = $1) as contatos,
      (select count(*)::int from mensagens where conta_id = $1) as mensagens_total,
      (select count(*)::int from mensagens
         where conta_id = $1 and criado_em > now() - interval '7 days') as mensagens_7d,
      (select max(criado_em) from mensagens where conta_id = $1) as ultima_mensagem
  `, [id]);

  // Só os erros e avisos: o log de info de um cliente é ruído para quem
  // está diagnosticando a plataforma.
  var problemas = await db.varias(`
    select nivel, evento, mensagem, criado_em
      from registros
     where conta_id = $1 and nivel in ('erro','aviso')
     order by criado_em desc limit 20
  `, [id]);

  res.json({ conta: conta, usuarios: usuarios, conexao: conexao, bot: bot, uso: uso, problemas: problemas });
}));

// ════════════════════════════════════════
// AÇÕES SOBRE UMA CONTA
// ════════════════════════════════════════
async function registrarAcao(autor, acao, conta, detalhe) {
  await db.consultar(
    "insert into owner_acoes (autor, acao, conta_id, conta_nome, detalhe) values ($1,$2,$3,$4,$5)",
    [autor, acao, conta.id, conta.nome, detalhe ? JSON.stringify(detalhe) : null]
  );
}

async function acharConta(id) {
  var limpo = v.uuid(id);
  if (!limpo) throw new ErroHttp(400, "Conta inválida.");
  var conta = await db.uma("select * from contas where id=$1", [limpo]);
  if (!conta) throw new ErroHttp(404, "Conta não encontrada.");
  return conta;
}

router.post("/contas/:id/suspender", rota(async function (req, res) {
  var conta = await acharConta(req.params.id);
  var motivo = v.textoOpcional(req.body.motivo, 300);

  var salva = await db.uma(
    `update contas set status='suspensa', suspensa_em=now(), motivo_suspensao=$1, atualizado_em=now()
      where id=$2 returning *`,
    [motivo || null, conta.id]
  );

  // O bot para de responder na hora — o serviço checa `contas.status` a
  // cada mensagem recebida. A conexão NÃO é desfeita: suspensão é uma
  // pausa comercial, e apagar as credenciais obrigaria o cliente a
  // refazer tudo na Meta quando regularizasse.
  await registrarAcao(req.owner.email, "suspender", conta, { motivo: motivo || null });

  res.json(salva);
}));

router.post("/contas/:id/reativar", rota(async function (req, res) {
  var conta = await acharConta(req.params.id);

  var salva = await db.uma(
    `update contas set status='ativa', suspensa_em=null, motivo_suspensao=null, atualizado_em=now()
      where id=$1 returning *`,
    [conta.id]
  );

  await registrarAcao(req.owner.email, "reativar", conta, null);
  res.json(salva);
}));

router.post("/contas/:id/plano", rota(async function (req, res) {
  var conta = await acharConta(req.params.id);
  var plano = v.umDe(req.body.plano, ["gratis", "pro"]);
  if (!plano) throw new ErroHttp(400, "Plano inválido. Use 'gratis' ou 'pro'.");

  var salva = await db.uma(
    "update contas set plano=$1, atualizado_em=now() where id=$2 returning *",
    [plano, conta.id]
  );

  await registrarAcao(req.owner.email, "mudar_plano", conta, { de: conta.plano, para: plano });
  res.json(salva);
}));

router.post("/contas/:id/observacao", rota(async function (req, res) {
  var conta = await acharConta(req.params.id);
  var texto = v.textoOpcional(req.body.observacao, 1000);

  var salva = await db.uma(
    "update contas set observacao=$1, atualizado_em=now() where id=$2 returning *",
    [texto || null, conta.id]
  );

  await registrarAcao(req.owner.email, "anotar", conta, null);
  res.json(salva);
}));

// ════════════════════════════════════════
// SAÚDE DA PLATAFORMA
// ════════════════════════════════════════
// A tela que responde "tem alguém quebrado agora?" — que é a pergunta
// que o dono faz de manhã, antes de qualquer outra.
router.get("/saude", rota(async function (req, res) {
  var quebradas = await db.varias(`
    select c.id, c.nome, x.status, x.numero_exibicao, x.ultimo_erro, x.ultimo_erro_em, x.verificado_em
      from conexoes x join contas c on c.id = x.conta_id
     where x.status = 'erro'
     order by x.ultimo_erro_em desc nulls last
     limit 50
  `);

  // Falhas de envio nas últimas 24h, agrupadas por conta. Uma conta com
  // 200 falhas é um problema diferente de 20 contas com 1 falha cada.
  var falhas = await db.varias(`
    select c.id, c.nome, count(*)::int as falhas, max(m.criado_em) as ultima
      from mensagens m join contas c on c.id = m.conta_id
     where m.status = 'falha' and m.criado_em > now() - interval '24 hours'
     group by c.id, c.nome order by falhas desc limit 20
  `);

  var errosRecentes = await db.varias(`
    select r.nivel, r.evento, r.mensagem, r.criado_em, c.nome as conta_nome, c.id as conta_id
      from registros r join contas c on c.id = r.conta_id
     where r.nivel = 'erro' and r.criado_em > now() - interval '48 hours'
     order by r.criado_em desc limit 50
  `);

  res.json({ conexoes_quebradas: quebradas, falhas_por_conta: falhas, erros_recentes: errosRecentes });
}));

// ════════════════════════════════════════
// TRILHA DE AUDITORIA
// ════════════════════════════════════════
router.get("/acoes", rota(async function (req, res) {
  res.json(await db.varias(
    "select * from owner_acoes order by criado_em desc limit 100"
  ));
}));

module.exports = router;
