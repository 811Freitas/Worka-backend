"use strict";

/**
 * Conexão do WhatsApp — a tela onde o cliente liga o número dele.
 *
 * Regra que vale para o arquivo inteiro: NENHUMA rota daqui devolve o
 * token da Meta ao navegador, nem para o dono que o cadastrou. O que
 * volta é "está configurado" e os quatro últimos caracteres. Um segredo
 * que chega ao navegador chega também a qualquer extensão instalada, a
 * um XSS futuro e à aba deixada aberta num computador emprestado.
 */

var express = require("express");
var db = require("../../db");
var config = require("../../config");
var v = require("../../lib/validar");
var cripto = require("../../lib/cripto");
var registro = require("../../lib/registro");
var meta = require("./cloud-api");
var servico = require("./servico");
var { rota, ErroHttp } = require("../../middlewares/erro");
var { exigirLogin, exigirDono } = require("../../middlewares/autenticar");

var router = express.Router();
router.use(exigirLogin);

/** A linha de conexão da conta, criada se ainda não existir. */
async function conexaoDaConta(contaId) {
  var c = await db.uma("select * from conexoes where conta_id=$1", [contaId]);
  if (c) return c;
  return db.uma(
    "insert into conexoes (conta_id, verify_token) values ($1,$2) returning *",
    [contaId, cripto.segredoAleatorio(24)]
  );
}

/**
 * O que o painel pode ver. Tudo que sai daqui passou por este filtro —
 * é o que impede um campo novo no banco de vazar para a tela por
 * distração, que é como segredo costuma escapar.
 */
function paraPainel(c) {
  return {
    status: c.status,
    provedor: c.provedor,
    phone_number_id: c.phone_number_id,
    waba_id: c.waba_id,
    numero_exibicao: c.numero_exibicao,
    nome_exibicao: c.nome_exibicao,

    token_configurado: !!c.token_cifrado,
    token_final: c.token_cifrado ? cripto.mascarar(cripto.decifrar(c.token_cifrado)) : null,
    app_secret_configurado: !!c.app_secret_cifrado,

    // O verify_token PRECISA aparecer: o cliente cola este valor no
    // painel da Meta. É segredo compartilhado com a Meta, não
    // credencial de acesso — quem o tiver consegue, no máximo, fazer o
    // handshake de verificação da URL.
    verify_token: c.verify_token,
    webhook_url: config.URL_PUBLICA.replace(/\/+$/, "") + "/webhook",
    webhook_verificado_em: c.webhook_verificado_em,

    ultimo_erro: c.ultimo_erro,
    ultimo_erro_em: c.ultimo_erro_em,
    verificado_em: c.verificado_em,
    conectado_em: c.conectado_em,
    total_enviadas: Number(c.total_enviadas),
    total_recebidas: Number(c.total_recebidas)
  };
}

/**
 * Confere as credenciais contra a Meta e grava o resultado.
 *
 * Um único caminho para conectar, testar, retomar e para o monitor. Se
 * cada um tivesse a sua versão, um deles um dia esqueceria de limpar o
 * `ultimo_erro` — e o painel mostraria "conectado" com uma mensagem de
 * erro velha embaixo, sem ninguém saber qual das duas acreditar.
 */
async function revalidar(conexao) {
  var token = cripto.decifrar(conexao.token_cifrado);
  if (!conexao.phone_number_id || !token) {
    await db.consultar("update conexoes set status='desconectado', atualizado_em=now() where id=$1", [conexao.id]);
    return { ok: false, mensagem: "Nenhuma credencial cadastrada." };
  }

  var r = await meta.verificarNumero(conexao.phone_number_id, token);

  if (!r.ok) {
    if (r.permanente) {
      await servico.marcarErro(conexao, r.mensagem);
    } else {
      // Instabilidade da Meta ou da rede: registra, mas NÃO derruba o
      // status. Marcar "erro" a cada oscilação faria o cliente correr
      // para reconectar um número que nunca saiu do ar.
      registro.aviso(conexao.conta_id, "verificacao_falhou", r.mensagem);
    }
    return { ok: false, mensagem: r.mensagem, permanente: !!r.permanente };
  }

  // Credenciais boas. Só vira 'conectado' se o webhook também já estiver
  // validado — sem ele o bot envia mas não recebe, que é meio caminho e
  // não pode ser mostrado como pronto.
  var status = conexao.webhook_verificado_em ? "conectado" : "aguardando_webhook";

  var atualizada = await db.uma(
    `update conexoes
        set status=$1, numero_exibicao=$2, nome_exibicao=$3,
            verificado_em=now(), ultimo_erro=null, ultimo_erro_em=null,
            conectado_em=coalesce(conectado_em, now()), atualizado_em=now()
      where id=$4 returning *`,
    [status, r.numero, r.nome, conexao.id]
  );

  return { ok: true, conexao: atualizada, qualidade: r.qualidade };
}

// ════════════════════════════════════════
// STATUS EM TEMPO REAL
// ════════════════════════════════════════
// O painel chama isto a cada poucos segundos enquanto a tela de conexão
// está aberta. Barato de propósito: só lê a linha, sem falar com a Meta.
// Quem fala com a Meta é o monitor, de tempos em tempos — assim o painel
// aberto de 50 clientes não vira 50 chamadas por segundo lá.
router.get("/conexao", rota(async function (req, res) {
  res.json(paraPainel(await conexaoDaConta(req.contaId)));
}));

// ════════════════════════════════════════
// CONECTAR
// ════════════════════════════════════════
router.post("/conexao", exigirDono, rota(async function (req, res) {
  var conexao = await conexaoDaConta(req.contaId);

  var phoneNumberId = v.texto(req.body.phone_number_id, 40);
  var token = v.texto(req.body.token, 500);
  var wabaId = req.body.waba_id ? v.texto(req.body.waba_id, 40) : conexao.waba_id;
  var appSecret = req.body.app_secret ? v.texto(req.body.app_secret, 200) : null;

  if (!phoneNumberId) throw new ErroHttp(400, "Informe o Phone Number ID (o ID do número, não o número).");
  if (!/^\d{5,}$/.test(phoneNumberId)) {
    // O erro nº 1 de quem preenche esta tela: colar "+55 11 9..." no
    // lugar do ID. Barrar aqui, com a explicação, evita uma ida à Meta
    // que voltaria com "objeto não encontrado" — mensagem que não ajuda
    // ninguém a entender o que fazer.
    throw new ErroHttp(400, "O Phone Number ID é uma sequência de números do painel da Meta " +
                            "(algo como 123456789012345), não o telefone com DDD.");
  }

  // Token só é obrigatório na primeira vez. Salvar a tela de novo sem
  // recolar o token é o caso normal de quem só quer corrigir o App
  // Secret — e exigir o token de volta forçaria a pessoa a gerar um novo
  // na Meta sem necessidade.
  if (!token && !conexao.token_cifrado) {
    throw new ErroHttp(400, "Cole o token de acesso permanente gerado no painel da Meta.");
  }

  // Um número pertence a UMA conta: é pelo phone_number_id que o webhook
  // descobre de quem é cada mensagem, e dois donos para o mesmo número
  // tornariam essa pergunta sem resposta. O banco já garante isso com um
  // índice único — mas sem esta checagem a violação sobe como erro 500,
  // e o cliente lê "erro interno" onde a causa é concreta e explicável.
  var deOutraConta = await db.uma(
    "select id from conexoes where phone_number_id=$1 and conta_id<>$2",
    [phoneNumberId, req.contaId]
  );
  if (deOutraConta) {
    throw new ErroHttp(409,
      "Este número já está conectado a outra conta da plataforma. " +
      "Desconecte-o de lá antes de conectar aqui, ou use outro número.");
  }

  var salva = await db.uma(
    `update conexoes
        set phone_number_id=$1, waba_id=$2,
            token_cifrado=coalesce($3, token_cifrado),
            app_secret_cifrado=coalesce($4, app_secret_cifrado),
            atualizado_em=now()
      where id=$5 returning *`,
    [phoneNumberId, wabaId, cripto.cifrar(token), cripto.cifrar(appSecret), conexao.id]
  );

  var r = await revalidar(salva);
  if (!r.ok) {
    registro.erro(req.contaId, "conexao_recusada", r.mensagem);
    throw new ErroHttp(400, r.mensagem);
  }

  registro.info(req.contaId, "conexao_configurada",
    "Credenciais aceitas pela Meta" + (r.conexao.numero_exibicao ? " para o número " + r.conexao.numero_exibicao : ""));

  res.json(Object.assign(paraPainel(r.conexao), {
    // O painel usa isto para decidir se mostra o passo do webhook em
    // destaque ou o "tudo pronto".
    proximo_passo: r.conexao.status === "aguardando_webhook"
      ? "Cadastre a URL do webhook no painel da Meta e clique em Verificar."
      : null
  }));
}));

// ════════════════════════════════════════
// TESTAR AGORA
// ════════════════════════════════════════
// Pergunta à Meta se o token vale NESTE instante. É o botão de quem
// desconfia do painel — e o mesmo caminho que o monitor percorre sozinho.
router.post("/conexao/testar", rota(async function (req, res) {
  var conexao = await conexaoDaConta(req.contaId);
  var r = await revalidar(conexao);

  if (!r.ok) return res.status(400).json({ erro: r.mensagem, permanente: !!r.permanente });

  res.json(Object.assign(paraPainel(r.conexao), { qualidade: r.qualidade }));
}));

// ════════════════════════════════════════
// PAUSAR / RETOMAR
// ════════════════════════════════════════
// Pausar NÃO desconecta: as credenciais ficam, a mensagem do cliente
// continua entrando no histórico, e só a resposta automática para. É o
// que se quer quando alguém vai atender na mão por uma hora — e é
// diferente de desconectar, que obriga a refazer tudo na Meta depois.
router.post("/conexao/pausar", exigirDono, rota(async function (req, res) {
  var conexao = await conexaoDaConta(req.contaId);
  if (!conexao.token_cifrado) throw new ErroHttp(400, "Não há conexão para pausar.");

  var salva = await db.uma(
    "update conexoes set status='pausado', atualizado_em=now() where id=$1 returning *",
    [conexao.id]
  );
  registro.aviso(req.contaId, "bot_pausado", "Bot pausado pelo painel.");
  res.json(paraPainel(salva));
}));

router.post("/conexao/retomar", exigirDono, rota(async function (req, res) {
  var conexao = await conexaoDaConta(req.contaId);
  // Revalida ao retomar: o bot pode ter ficado pausado dias, e nesse
  // tempo o token pode ter sido revogado. Voltar direto para "conectado"
  // mostraria verde numa conexão morta.
  var r = await revalidar(conexao);
  if (!r.ok) return res.status(400).json({ erro: r.mensagem });

  registro.info(req.contaId, "bot_retomado", "Bot retomado pelo painel.");
  res.json(paraPainel(r.conexao));
}));

// ════════════════════════════════════════
// REINICIAR
// ════════════════════════════════════════
/**
 * O "desligar e ligar de novo" — e aqui ele faz algo concreto, em vez de
 * ser um botão decorativo.
 *
 * Com a Cloud API não existe socket para derrubar: o que trava de
 * verdade é (a) uma credencial que virou inválida sem o painel saber e
 * (b) conversas presas num estado que ninguém vai destravar sozinho —
 * alguém que pediu atendente e nunca foi atendido fica com o bot mudo
 * para sempre.
 *
 * Reiniciar resolve exatamente esses dois: revalida contra a Meta e
 * devolve ao bot as conversas paradas há mais de uma hora.
 */
router.post("/conexao/reiniciar", exigirDono, rota(async function (req, res) {
  var conexao = await conexaoDaConta(req.contaId);

  var destravadas = await db.consultar(
    `update conversas
        set status='bot', bloco_chave=null, variaveis='{}'::jsonb
      where conta_id=$1 and status='humano'
        and ultima_interacao_em < now() - interval '1 hour'`,
    [req.contaId]
  );

  var r = await revalidar(conexao);

  registro.aviso(req.contaId, "bot_reiniciado",
    "Bot reiniciado pelo painel. Conversas destravadas: " + destravadas.rowCount);

  if (!r.ok) {
    return res.status(400).json({ erro: r.mensagem, conversas_destravadas: destravadas.rowCount });
  }

  res.json(Object.assign(paraPainel(r.conexao), { conversas_destravadas: destravadas.rowCount }));
}));

// ════════════════════════════════════════
// DESCONECTAR
// ════════════════════════════════════════
router.delete("/conexao", exigirDono, rota(async function (req, res) {
  var conexao = await conexaoDaConta(req.contaId);

  var salva = await db.uma(
    `update conexoes
        set status='desconectado', token_cifrado=null, app_secret_cifrado=null,
            phone_number_id=null, numero_exibicao=null, nome_exibicao=null,
            webhook_verificado_em=null, conectado_em=null,
            -- Verify token novo: o webhook antigo, que ainda pode estar
            -- cadastrado no painel da Meta do cliente, deixa de casar com
            -- esta conta no mesmo instante. Sem trocar, uma conta
            -- desconectada continuaria aceitando o handshake de quem
            -- tivesse o token velho.
            verify_token=$1,
            ultimo_erro=null, ultimo_erro_em=null, atualizado_em=now()
      where id=$2 returning *`,
    [cripto.segredoAleatorio(24), conexao.id]
  );

  registro.aviso(req.contaId, "desconectado", "WhatsApp desconectado pelo painel.");
  res.json(paraPainel(salva));
}));

// ════════════════════════════════════════
// ENVIO MANUAL (atendente humano)
// ════════════════════════════════════════
router.post("/enviar", rota(async function (req, res) {
  var conexao = await conexaoDaConta(req.contaId);
  if (!conexao.token_cifrado || conexao.status === "desconectado") {
    throw new ErroHttp(400, "Conecte o WhatsApp antes de enviar mensagens.");
  }

  var telefone = v.telefone(req.body.telefone);
  var texto = v.texto(req.body.texto, v.LIMITES.mensagem);
  if (!telefone) throw new ErroHttp(400, "Telefone inválido. Use o formato com DDI, ex.: 5511987654321.");
  if (!texto) throw new ErroHttp(400, "Escreva a mensagem.");

  var contato = await servico.acharOuCriarContato(req.contaId, telefone, null);
  var bot = await db.uma("select id from bots where conta_id=$1 and ativo limit 1", [req.contaId]);
  var conversa = await servico.acharOuCriarConversa(req.contaId, contato, bot && bot.id);

  // Quem responde na mão assume a conversa: o bot se cala até alguém
  // devolvê-la. Sem isso, o atendente escreveria "vou verificar seu
  // pedido" e o bot emendaria "não entendi, escolha uma opção" logo
  // embaixo — na frente do cliente.
  if (conversa.status === "bot") {
    await db.consultar("update conversas set status='humano' where id=$1", [conversa.id]);
  }

  var r = await servico.enviarManual(conexao, conversa, telefone, texto);
  if (!r.ok) throw new ErroHttp(502, r.mensagem || "Não foi possível enviar agora.");

  res.json({ ok: true, conversa_id: conversa.id, wa_id: r.wa_id });
}));

module.exports = { router: router, revalidar: revalidar, conexaoDaConta: conexaoDaConta, paraPainel: paraPainel };
