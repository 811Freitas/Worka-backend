/**
 * Tela inicial: estado da conexão, números do dia e conversas recentes.
 */

import { api, $, el, trocar, vazio, quando, telefoneBonito, iniciais, pintarSelo } from "./base.js";

export async function carregarPainel() {
  var dados = await api("GET", "/painel/resumo");

  pintarSelo($("selo-conexao"), dados.conexao.status);
  mostrarAvisos(dados);
  mostrarIndicadores(dados.numeros);
  mostrarGrafico(dados.serie);
  await mostrarRecentes();
}

/**
 * A faixa de aviso no topo.
 *
 * Só aparece quando há uma ação concreta a tomar, e diz QUAL. Um painel
 * que avisa sempre vira decoração que ninguém lê — e aí o aviso que
 * importava passa despercebido junto com o resto.
 */
function mostrarAvisos(dados) {
  var caixa = $("avisos-painel");
  var status = dados.conexao.status;
  var avisos = [];

  if (status === "desconectado") {
    avisos.push(faixa("atento",
      "Seu WhatsApp ainda não está conectado. Enquanto isso o bot não recebe nem responde nada.",
      "Conectar agora", "conexao"));
  } else if (status === "erro") {
    avisos.push(faixa("ruim",
      dados.conexao.ultimo_erro || "A conexão com a Meta falhou.",
      "Ver conexão", "conexao"));
  } else if (status === "aguardando_webhook") {
    avisos.push(faixa("atento",
      "Falta cadastrar o webhook no painel da Meta. Sem ele o bot envia, mas não recebe mensagens.",
      "Terminar configuração", "conexao"));
  } else if (status === "pausado") {
    avisos.push(faixa("atento",
      "O bot está pausado. As mensagens estão sendo gravadas, mas ninguém recebe resposta automática.",
      "Retomar", "conexao"));
  }

  if (dados.numeros.aguardando_humano > 0) {
    avisos.push(faixa("atento",
      dados.numeros.aguardando_humano + " conversa(s) esperando atendimento humano.",
      "Atender", "conversas"));
  }

  trocar(caixa, avisos);
}

function faixa(tipo, texto, rotuloBotao, destino) {
  return el("div", { classe: "aviso " + tipo }, [
    el("div", { estilo: "display:flex;align-items:center;gap:12px;flex-wrap:wrap" }, [
      el("span", { estilo: "flex:1;min-width:12rem", texto: texto }),
      el("button", { classe: "botao neutro pequeno", texto: rotuloBotao, "dados-ir": destino,
        aoClicar: function () {
          document.querySelector('#menu button[data-pagina="' + destino + '"]').click();
        } })
    ])
  ]);
}

function mostrarIndicadores(n) {
  trocar($("indicadores"), [
    indicador("Conversas hoje", n.conversas_24h),
    indicador("Mensagens recebidas", n.recebidas_24h),
    indicador("Respostas enviadas", n.enviadas_24h),
    indicador("Contatos", n.contatos),
    indicador("Esperando atendente", n.aguardando_humano, n.aguardando_humano > 0),
    indicador("Falhas (24h)", n.falhas_24h, n.falhas_24h > 0)
  ]);
}

function indicador(rotulo, valor, atencao) {
  return el("div", { classe: "indicador" }, [
    el("div", { classe: "rotulo", texto: rotulo }),
    el("div", { classe: "valor" + (atencao ? " atencao" : ""), texto: String(valor == null ? 0 : valor) })
  ]);
}

/**
 * Sete barras em divs, sem biblioteca de gráfico.
 *
 * A altura é proporcional ao maior dia da série; com tudo zerado, o
 * `|| 1` evita dividir por zero e deixa todas as barras no mínimo — que
 * é a leitura honesta de uma semana sem mensagem nenhuma.
 */
function mostrarGrafico(serie) {
  var maior = Math.max.apply(null, serie.map(function (d) {
    return Math.max(d.recebidas, d.enviadas);
  }).concat([1]));

  var nomes = ["dom", "seg", "ter", "qua", "qui", "sex", "sáb"];

  trocar($("grafico"), serie.map(function (d) {
    // O dia vem como "YYYY-MM-DD". Montar a data com os pedaços evita o
    // deslocamento de fuso que `new Date("2026-03-10")` provoca — ela é
    // lida como meia-noite UTC e, no Brasil, vira o dia anterior.
    var partes = d.dia.split("-");
    var data = new Date(+partes[0], +partes[1] - 1, +partes[2]);

    return el("div", { classe: "dia", title: d.recebidas + " recebidas, " + d.enviadas + " enviadas" }, [
      el("div", { classe: "barras" }, [
        el("div", { classe: "barra entrada", estilo: "height:" + (d.recebidas / maior * 100) + "%" }),
        el("div", { classe: "barra saida", estilo: "height:" + (d.enviadas / maior * 100) + "%" })
      ]),
      el("div", { classe: "rotulo-dia", texto: nomes[data.getDay()] })
    ]);
  }));
}

async function mostrarRecentes() {
  var conversas = await api("GET", "/conversas?limite=6");
  var lista = $("conversas-recentes");

  if (!conversas.length) {
    trocar(lista, [el("li", {}, [
      vazio("💬", "Nenhuma conversa ainda. Assim que alguém escrever para o seu número, aparece aqui.")
    ])]);
    return;
  }

  trocar(lista, conversas.map(function (c) {
    return el("li", {}, [
      el("div", { classe: "avatar", texto: iniciais(c.contato_nome || c.telefone) }),
      el("div", { classe: "item-corpo" }, [
        el("div", { classe: "item-titulo", texto: c.contato_nome || telefoneBonito(c.telefone) }),
        el("div", { classe: "item-linha", texto: (c.ultima_direcao === "saida" ? "→ " : "") + (c.ultima_mensagem || "") })
      ]),
      c.status === "humano" ? el("span", { classe: "selo esperando", texto: "atendente" }) : null,
      el("span", { classe: "fraco", texto: quando(c.ultima_interacao_em) })
    ]);
  }));
}
