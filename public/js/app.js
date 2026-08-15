/**
 * Arranque do painel: entrada, navegação e carregamento das telas.
 */

import { api, $, el, trocar, recado, ocupado, pegarToken, guardarToken, limparToken, dataHora } from "./base.js";
import { carregarPainel } from "./painel.js";
import { carregarConstrutor } from "./construtor.js";
import { carregarConversas } from "./conversas.js";
import { carregarConexao, pararRelogioConexao } from "./conexao.js";

var sessao = null;

// ════════════════════════════════════════
// ENTRADA
// ════════════════════════════════════════
function mostrarAba(qual) {
  $("aba-entrar").classList.toggle("ativa", qual === "entrar");
  $("aba-criar").classList.toggle("ativa", qual === "criar");
  $("forma-entrar").classList.toggle("oculto", qual !== "entrar");
  $("forma-criar").classList.toggle("oculto", qual !== "criar");
}

$("aba-entrar").addEventListener("click", function () { mostrarAba("entrar"); });
$("aba-criar").addEventListener("click", function () { mostrarAba("criar"); });

$("forma-entrar").addEventListener("submit", async function (e) {
  e.preventDefault();
  await ocupado($("botao-entrar"), "Entrando...", async function () {
    try {
      var r = await api("POST", "/login", {
        email: $("entrar-email").value,
        senha: $("entrar-senha").value
      });
      guardarToken(r.token);
      await entrar();
    } catch (erro) {
      recado(erro.message, "ruim");
    }
  });
});

$("forma-criar").addEventListener("submit", async function (e) {
  e.preventDefault();
  await ocupado($("botao-criar"), "Criando...", async function () {
    try {
      var r = await api("POST", "/cadastro", {
        nome: $("criar-nome").value,
        empresa: $("criar-empresa").value,
        email: $("criar-email").value,
        senha: $("criar-senha").value
      });
      guardarToken(r.token);
      await entrar();
      recado("Conta criada! Seu chatbot de exemplo já está pronto.", "bom");
      // Vai direto para o construtor: a conta nasce com um fluxo pronto,
      // e ver a conversa funcionando no simulador é o que faz a pessoa
      // entender o produto em dez segundos.
      abrir("construtor");
    } catch (erro) {
      recado(erro.message, "ruim");
    }
  });
});

// ════════════════════════════════════════
// NAVEGAÇÃO
// ════════════════════════════════════════
var carregadores = {
  painel: carregarPainel,
  construtor: carregarConstrutor,
  conversas: carregarConversas,
  conexao: carregarConexao,
  registros: carregarRegistros,
  conta: carregarConta
};

export function abrir(pagina) {
  document.querySelectorAll(".pagina").forEach(function (p) {
    p.classList.toggle("ativa", p.id === "pagina-" + pagina);
  });
  document.querySelectorAll("#menu button").forEach(function (b) {
    b.classList.toggle("ativa", b.dataset.pagina === pagina);
  });

  // O relógio da tela de conexão consulta o servidor a cada poucos
  // segundos. Deixá-lo rodando com a tela fechada seria uma requisição
  // por cliente, para sempre, sem ninguém olhando.
  if (pagina !== "conexao") pararRelogioConexao();

  fecharMenuLateral();
  location.hash = pagina;

  var carregar = carregadores[pagina];
  if (carregar) {
    Promise.resolve(carregar()).catch(function (e) { recado(e.message, "ruim"); });
  }
}

document.querySelectorAll("#menu button").forEach(function (botao) {
  botao.addEventListener("click", function () { abrir(botao.dataset.pagina); });
});

document.querySelectorAll("[data-ir]").forEach(function (botao) {
  botao.addEventListener("click", function () { abrir(botao.dataset.ir); });
});

// ── Menu lateral no celular ─────────────
function fecharMenuLateral() {
  $("lateral").classList.remove("aberta");
  var veu = document.querySelector(".veu");
  if (veu) veu.remove();
}

document.querySelectorAll(".abrir-menu").forEach(function (botao) {
  botao.addEventListener("click", function () {
    $("lateral").classList.add("aberta");
    var veu = el("div", { classe: "veu", aoClicar: fecharMenuLateral });
    document.body.appendChild(veu);
  });
});

$("botao-sair").addEventListener("click", function () {
  limparToken();
  location.reload();
});

// ════════════════════════════════════════
// REGISTROS
// ════════════════════════════════════════
async function carregarRegistros() {
  var nivel = $("filtro-nivel").value;
  var linhas = await api("GET", "/registros?limite=150" + (nivel ? "&nivel=" + nivel : ""));
  var corpo = $("corpo-registros");

  if (!linhas.length) {
    trocar(corpo, [el("tr", {}, [
      el("td", { colspan: "4" }, [el("div", { classe: "vazio", texto: "Nada registrado ainda." })])
    ])]);
    return;
  }

  trocar(corpo, linhas.map(function (r) {
    return el("tr", {}, [
      el("td", { classe: "fraco", texto: dataHora(r.criado_em) }),
      el("td", {}, [el("span", { classe: "nivel-" + r.nivel, texto: r.nivel })]),
      el("td", { texto: r.evento }),
      el("td", { texto: r.mensagem })
    ]);
  }));
}

$("filtro-nivel").addEventListener("change", function () {
  carregarRegistros().catch(function (e) { recado(e.message, "ruim"); });
});
$("atualizar-registros").addEventListener("click", function () {
  carregarRegistros().catch(function (e) { recado(e.message, "ruim"); });
});

// ════════════════════════════════════════
// CONTA
// ════════════════════════════════════════
async function carregarConta() {
  var avisos = await api("GET", "/notificacoes");
  var lista = $("lista-notificacoes");

  if (!avisos.length) {
    trocar(lista, [vazioItem("Nenhum aviso. Tudo em ordem por aqui.")]);
  } else {
    trocar(lista, avisos.map(function (n) {
      return el("li", {}, [
        el("div", { classe: "item-corpo" }, [
          el("div", { classe: "item-titulo", texto: n.titulo }),
          el("div", { classe: "item-linha", texto: n.mensagem })
        ]),
        el("span", { classe: "fraco", texto: dataHora(n.criado_em) }),
        !n.lida ? el("span", { classe: "selo erro", texto: "novo" }) : null
      ]);
    }));
  }

  trocar($("dados-conta"), [
    linhaDado("Empresa", sessao.conta.nome),
    linhaDado("Seu nome", sessao.usuario.nome),
    linhaDado("E-mail", sessao.usuario.email),
    linhaDado("Papel", sessao.usuario.papel === "dono" ? "Dono da conta" : "Operador"),
    linhaDado("Plano", sessao.conta.plano)
  ]);

  atualizarBolhaAvisos(avisos.filter(function (n) { return !n.lida; }).length);
}

function linhaDado(rotulo, valor) {
  return el("div", { estilo: "display:flex;justify-content:space-between;padding:9px 0;border-bottom:1px solid var(--linha)" }, [
    el("span", { classe: "sub", texto: rotulo }),
    el("strong", { texto: valor || "—" })
  ]);
}

function vazioItem(texto) {
  return el("li", {}, [el("div", { classe: "vazio", texto: texto })]);
}

$("marcar-lidas").addEventListener("click", async function () {
  await api("POST", "/notificacoes/lidas", {});
  await carregarConta();
  recado("Avisos marcados como lidos.", "bom");
});

$("forma-senha").addEventListener("submit", async function (e) {
  e.preventDefault();
  try {
    await api("POST", "/senha", {
      atual: $("senha-atual").value,
      nova: $("senha-nova").value
    });
    $("forma-senha").reset();
    recado("Senha trocada.", "bom");
  } catch (erro) {
    recado(erro.message, "ruim");
  }
});

export function atualizarBolhaAvisos(quantidade) {
  var botao = document.querySelector('#menu button[data-pagina="conta"]');
  var bolha = botao.querySelector(".conta-bolha");
  if (bolha) bolha.remove();
  if (quantidade > 0) {
    botao.appendChild(el("span", { classe: "conta-bolha", texto: String(quantidade) }));
  }
}

// ════════════════════════════════════════
// ARRANQUE
// ════════════════════════════════════════
async function entrar() {
  sessao = await api("GET", "/eu");

  $("tela-entrada").style.display = "none";
  $("tela-painel").classList.add("visivel");
  $("rotulo-conta").textContent = sessao.conta.nome;

  var hora = new Date().getHours();
  var cumprimento = hora < 12 ? "Bom dia" : (hora < 18 ? "Boa tarde" : "Boa noite");
  $("saudacao").textContent = cumprimento + ", " + sessao.usuario.nome.split(" ")[0] + ".";

  atualizarBolhaAvisos(sessao.notificacoes_nao_lidas);

  // Volta para a tela em que a pessoa estava antes do F5. Sem isto,
  // qualquer recarga durante a configuração da conexão jogaria de volta
  // para o painel, no meio do processo.
  var alvo = (location.hash || "").replace("#", "");
  abrir(carregadores[alvo] ? alvo : "painel");
}

export function sessaoAtual() { return sessao; }

(async function () {
  if (!pegarToken()) return;

  try {
    await entrar();
  } catch (e) {
    // Token velho ou servidor fora. A tela de entrada continua onde
    // está — insistir num painel que não carrega não leva a lugar nenhum.
    limparToken();
  }
})();
