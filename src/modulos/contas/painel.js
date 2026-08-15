"use strict";

/**
 * Números do dashboard.
 *
 * Tudo numa consulta só, com subselects, em vez de sete idas ao banco.
 * A tela inicial é a que abre com mais frequência em todo o produto —
 * cada requisição a mais aqui é multiplicada por todos os clientes, o
 * dia inteiro.
 */

var express = require("express");
var db = require("../../db");
var { rota } = require("../../middlewares/erro");
var { exigirLogin } = require("../../middlewares/autenticar");

var router = express.Router();
router.use(exigirLogin);

router.get("/resumo", rota(async function (req, res) {
  var n = await db.uma(
    `select
       (select count(*)::int from conversas where conta_id=$1)                        as conversas_total,
       (select count(*)::int from conversas where conta_id=$1 and status='humano')    as aguardando_humano,
       (select count(*)::int from conversas
          where conta_id=$1 and ultima_interacao_em > now() - interval '24 hours')    as conversas_24h,
       (select count(*)::int from contatos  where conta_id=$1)                        as contatos,
       (select count(*)::int from mensagens
          where conta_id=$1 and direcao='entrada' and criado_em > now() - interval '24 hours') as recebidas_24h,
       (select count(*)::int from mensagens
          where conta_id=$1 and direcao='saida'   and criado_em > now() - interval '24 hours') as enviadas_24h,
       (select count(*)::int from mensagens
          where conta_id=$1 and status='falha'    and criado_em > now() - interval '24 hours') as falhas_24h,
       (select count(*)::int from notificacoes where conta_id=$1 and not lida)        as notificacoes,
       (select count(*)::int from registros
          where conta_id=$1 and nivel='erro' and criado_em > now() - interval '24 hours')      as erros_24h`,
    [req.contaId]
  );

  var conexao = await db.uma(
    `select status, numero_exibicao, nome_exibicao, ultimo_erro, verificado_em, conectado_em,
            total_enviadas, total_recebidas
       from conexoes where conta_id=$1`,
    [req.contaId]
  );

  var bot = await db.uma(
    "select id, nome, ativo, atendimento_ativo from bots where conta_id=$1 and ativo limit 1",
    [req.contaId]
  );

  // Volume por dia dos últimos 7 dias, com os dias vazios preenchidos.
  // Sem o generate_series, um dia sem mensagem simplesmente não voltaria
  // — e o gráfico do painel emendaria segunda com quarta, mostrando uma
  // linha contínua onde houve silêncio.
  var serie = await db.varias(
    `select to_char(d.dia, 'YYYY-MM-DD') as dia,
            coalesce(sum(case when m.direcao='entrada' then 1 else 0 end), 0)::int as recebidas,
            coalesce(sum(case when m.direcao='saida'   then 1 else 0 end), 0)::int as enviadas
       from generate_series(current_date - interval '6 days', current_date, interval '1 day') d(dia)
       left join mensagens m
              on m.conta_id = $1 and m.criado_em >= d.dia and m.criado_em < d.dia + interval '1 day'
      group by d.dia order by d.dia`,
    [req.contaId]
  );

  res.json({
    numeros: n,
    conexao: conexao || { status: "desconectado" },
    bot: bot || null,
    serie: serie
  });
}));

module.exports = router;
