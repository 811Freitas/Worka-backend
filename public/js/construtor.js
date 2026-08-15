/**
 * O construtor de chatbot: configuração do bot, editor de blocos e o
 * simulador de conversa.
 */

import { api, $, el, trocar, recado, ocupado } from "./base.js";

var bot = null;
var blocos = [];
var blocoAberto = null;      // null = nenhum; objeto = editando; "novo" = criando
var opcoesEditadas = [];
var conversaSimulada = null;

var DIAS = [
  { n: 0, r: "Dom" }, { n: 1, r: "Seg" }, { n: 2, r: "Ter" }, { n: 3, r: "Qua" },
  { n: 4, r: "Qui" }, { n: 5, r: "Sex" }, { n: 6, r: "Sáb" }
];
var diasEscolhidos = [];

var ROTULO_TIPO = {
  menu: "menu", texto: "mensagem", pergunta: "pergunta",
  humano: "atendente", encerrar: "encerra"
};

export async function carregarConstrutor() {
  bot = await api("GET", "/bot");
  blocos = await api("GET", "/bot/blocos");

  preencherFormularioBot();
  desenharBlocos();
  reiniciarSimulacao();
}

// ════════════════════════════════════════
// CONFIGURAÇÃO DO BOT
// ════════════════════════════════════════
function preencherFormularioBot() {
  $("bot-nome").value = bot.nome || "";
  $("bot-boas-vindas").value = bot.mensagem_boas_vindas || "";
  $("bot-fallback").value = bot.mensagem_fallback || "";
  $("bot-transbordo").value = bot.mensagem_transbordo || "";
  $("bot-fora-horario").value = bot.mensagem_fora_horario || "";
  $("bot-horario-ativo").checked = !!bot.atendimento_ativo;
  // O banco devolve "08:00:00"; o <input type=time> quer "08:00".
  $("bot-inicio").value = String(bot.atendimento_inicio || "08:00").slice(0, 5);
  $("bot-fim").value = String(bot.atendimento_fim || "18:00").slice(0, 5);
  $("bot-expirar").value = bot.expirar_apos_minutos;

  diasEscolhidos = (bot.atendimento_dias || []).slice();
  desenharDias();
  $("area-horario").classList.toggle("oculto", !bot.atendimento_ativo);
}

function desenharDias() {
  trocar($("dias-semana"), DIAS.map(function (d) {
    var escolhido = diasEscolhidos.indexOf(d.n) !== -1;
    return el("button", {
      type: "button",
      classe: "botao pequeno " + (escolhido ? "" : "neutro"),
      texto: d.r,
      aoClicar: function () {
        var i = diasEscolhidos.indexOf(d.n);
        if (i === -1) diasEscolhidos.push(d.n); else diasEscolhidos.splice(i, 1);
        desenharDias();
      }
    });
  }));
}

$("bot-horario-ativo").addEventListener("change", function () {
  $("area-horario").classList.toggle("oculto", !this.checked);
});

$("salvar-bot").addEventListener("click", async function () {
  await ocupado(this, "Salvando...", async function () {
    try {
      bot = await api("PUT", "/bot", {
        nome: $("bot-nome").value,
        mensagem_boas_vindas: $("bot-boas-vindas").value,
        mensagem_fallback: $("bot-fallback").value,
        mensagem_transbordo: $("bot-transbordo").value,
        mensagem_fora_horario: $("bot-fora-horario").value,
        atendimento_ativo: $("bot-horario-ativo").checked,
        atendimento_inicio: $("bot-inicio").value,
        atendimento_fim: $("bot-fim").value,
        atendimento_dias: diasEscolhidos,
        expirar_apos_minutos: parseInt($("bot-expirar").value, 10)
      });
      recado("Salvo. Já vale na próxima mensagem.", "bom");
      reiniciarSimulacao();
    } catch (e) {
      recado(e.message, "ruim");
    }
  });
});

// ════════════════════════════════════════
// LISTA DE BLOCOS
// ════════════════════════════════════════
function desenharBlocos() {
  var lista = $("lista-blocos");

  if (!blocos.length) {
    trocar(lista, [el("div", { classe: "vazio" }, [
      el("span", { classe: "emoji", texto: "◇" }),
      el("div", { texto: "Nenhum bloco ainda. Crie o primeiro ou recupere o exemplo." }),
      el("button", {
        classe: "botao neutro pequeno espaco", texto: "Restaurar fluxo de exemplo",
        aoClicar: restaurarExemplo
      })
    ])]);
    return;
  }

  trocar(lista, blocos.map(function (b) {
    return el("div", {
      classe: "bloco" + (blocoAberto && blocoAberto.id === b.id ? " selecionado" : ""),
      aoClicar: function () { abrirEditor(b); }
    }, [
      el("div", { classe: "bloco-topo" }, [
        el("span", { classe: "bloco-titulo", texto: b.titulo }),
        el("span", { classe: "etiqueta tipo-" + b.tipo, texto: ROTULO_TIPO[b.tipo] || b.tipo }),
        b.inicial ? el("span", { classe: "etiqueta inicial", texto: "início" }) : null,
        (b.gatilhos || []).length
          ? el("span", { classe: "etiqueta", texto: "🔑 " + b.gatilhos.length })
          : null
      ]),
      el("div", { classe: "bloco-mensagem", texto: b.mensagem || "(sem mensagem)" }),
      (b.opcoes || []).length
        ? el("div", { classe: "bloco-opcoes" }, b.opcoes.map(function (o) {
            return el("span", { classe: "etiqueta" }, [
              document.createTextNode(o.rotulo),
              el("span", { classe: "seta", texto: o.proxima ? " → " + o.proxima : " → ?" })
            ]);
          }))
        : null,
      b.tipo !== "menu" && b.proxima_chave
        ? el("div", { classe: "bloco-opcoes" }, [
            el("span", { classe: "etiqueta", texto: "→ " + b.proxima_chave })
          ])
        : null
    ]);
  }));
}

async function restaurarExemplo() {
  try {
    blocos = await api("POST", "/bot/blocos/restaurar-exemplo", {});
    fecharEditor();
    desenharBlocos();
    reiniciarSimulacao();
    recado("Fluxo de exemplo restaurado.", "bom");
  } catch (e) {
    recado(e.message, "ruim");
  }
}

// ════════════════════════════════════════
// EDITOR DE BLOCO
// ════════════════════════════════════════
function abrirEditor(bloco) {
  blocoAberto = bloco || "novo";
  var b = bloco || {
    titulo: "", chave: "", tipo: "menu", mensagem: "",
    gatilhos: [], opcoes: [], proxima_chave: null, salvar_em: null, inicial: false
  };

  $("editor-bloco").classList.remove("oculto");
  $("editor-titulo").textContent = bloco ? "Editar bloco" : "Novo bloco";
  $("apagar-bloco").classList.toggle("oculto", !bloco);

  $("bloco-titulo").value = b.titulo;
  $("bloco-chave").value = b.chave;
  $("bloco-tipo").value = b.tipo;
  $("bloco-mensagem").value = b.mensagem;
  $("bloco-gatilhos").value = (b.gatilhos || []).join(", ");
  $("bloco-salvar-em").value = b.salvar_em || "";
  $("bloco-inicial").checked = !!b.inicial;

  opcoesEditadas = (b.opcoes || []).map(function (o) { return { rotulo: o.rotulo, proxima: o.proxima }; });

  encherSeletorProxima(b.proxima_chave);
  desenharOpcoes();
  ajustarCamposPorTipo();
  desenharBlocos();

  $("editor-bloco").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function fecharEditor() {
  blocoAberto = null;
  $("editor-bloco").classList.add("oculto");
  desenharBlocos();
}

/**
 * Mostra só os campos que fazem sentido para o tipo escolhido.
 *
 * Um bloco de despedida com campo "opções do menu" e "guardar resposta
 * em" convida a preencher coisas que serão ignoradas — e a pessoa
 * conclui que o produto está quebrado quando o bot ignora o que ela
 * configurou.
 */
function ajustarCamposPorTipo() {
  var tipo = $("bloco-tipo").value;
  $("campo-opcoes").classList.toggle("oculto", tipo !== "menu");
  $("campo-salvar-em").classList.toggle("oculto", tipo !== "pergunta");
  $("campo-proxima").classList.toggle("oculto", tipo !== "texto" && tipo !== "pergunta");
}

$("bloco-tipo").addEventListener("change", ajustarCamposPorTipo);

function encherSeletorProxima(atual) {
  var select = $("bloco-proxima");
  trocar(select, [el("option", { value: "", texto: "— nenhum, volta ao início —" })].concat(
    blocos.map(function (b) {
      return el("option", { value: b.chave, texto: b.titulo + " (" + b.chave + ")" });
    })
  ));
  select.value = atual || "";
}

function desenharOpcoes() {
  var caixa = $("lista-opcoes");

  trocar(caixa, opcoesEditadas.map(function (opcao, indice) {
    var destino = el("select", {}, [el("option", { value: "", texto: "— sem destino —" })].concat(
      blocos.map(function (b) {
        return el("option", { value: b.chave, texto: b.titulo });
      })
    ));
    destino.value = opcao.proxima || "";
    destino.addEventListener("change", function () { opcao.proxima = destino.value || null; });

    var rotulo = el("input", { type: "text", value: opcao.rotulo, maxlength: "24", placeholder: "Texto do botão" });
    rotulo.addEventListener("input", function () { opcao.rotulo = rotulo.value; });

    return el("div", { estilo: "display:grid;grid-template-columns:1fr 1fr auto;gap:8px;margin-bottom:8px;align-items:center" }, [
      rotulo, destino,
      el("button", {
        type: "button", classe: "botao discreto pequeno", texto: "✕", title: "Remover opção",
        aoClicar: function () { opcoesEditadas.splice(indice, 1); desenharOpcoes(); }
      })
    ]);
  }));

  // Três é o limite de BOTÕES da Cloud API. Acima disso a mensagem ainda
  // sai, como lista — e é melhor dizer isso aqui do que deixar a pessoa
  // descobrir que o visual mudou sozinho.
  if (opcoesEditadas.length > 3) {
    caixa.appendChild(el("p", { classe: "fraco",
      texto: "Com mais de 3 opções o WhatsApp mostra uma lista em vez de botões. Até 10." }));
  }
}

$("nova-opcao").addEventListener("click", function () {
  if (opcoesEditadas.length >= 10) return recado("O WhatsApp aceita no máximo 10 opções.", "ruim");
  opcoesEditadas.push({ rotulo: "", proxima: null });
  desenharOpcoes();
});

$("novo-bloco").addEventListener("click", function () { abrirEditor(null); });
$("fechar-editor").addEventListener("click", fecharEditor);

$("salvar-bloco").addEventListener("click", async function () {
  var corpo = {
    titulo: $("bloco-titulo").value,
    chave: $("bloco-chave").value || $("bloco-titulo").value,
    tipo: $("bloco-tipo").value,
    mensagem: $("bloco-mensagem").value,
    gatilhos: $("bloco-gatilhos").value.split(",").map(function (s) { return s.trim(); }).filter(Boolean),
    opcoes: opcoesEditadas.filter(function (o) { return o.rotulo.trim(); }),
    proxima_chave: $("bloco-proxima").value || null,
    salvar_em: $("bloco-salvar-em").value || null,
    inicial: $("bloco-inicial").checked
  };

  await ocupado(this, "Salvando...", async function () {
    try {
      if (blocoAberto === "novo") {
        await api("POST", "/bot/blocos", corpo);
      } else {
        await api("PUT", "/bot/blocos/" + blocoAberto.id, corpo);
      }
      blocos = await api("GET", "/bot/blocos");
      fecharEditor();
      reiniciarSimulacao();
      recado("Bloco salvo.", "bom");
    } catch (e) {
      recado(e.message, "ruim");
    }
  });
});

$("apagar-bloco").addEventListener("click", async function () {
  if (blocoAberto === "novo" || !blocoAberto) return;
  if (!confirm("Apagar o bloco \"" + blocoAberto.titulo + "\"? As opções que apontavam para ele serão removidas.")) return;

  try {
    await api("DELETE", "/bot/blocos/" + blocoAberto.id);
    blocos = await api("GET", "/bot/blocos");
    fecharEditor();
    reiniciarSimulacao();
    recado("Bloco apagado.", "bom");
  } catch (e) {
    recado(e.message, "ruim");
  }
});

// ════════════════════════════════════════
// CONFERÊNCIA DO FLUXO
// ════════════════════════════════════════
$("conferir-fluxo").addEventListener("click", async function () {
  await ocupado(this, "Conferindo...", async function () {
    var r = await api("GET", "/bot/diagnostico");
    var caixa = $("resultado-conferencia");

    if (!r.problemas.length) {
      trocar(caixa, [el("div", { classe: "aviso bom",
        texto: "Fluxo íntegro: " + r.total_blocos + " blocos, nenhum caminho quebrado." })]);
      return;
    }

    trocar(caixa, r.problemas.map(function (p) {
      return el("div", { classe: "aviso " + (p.nivel === "erro" ? "ruim" : "atento") }, [
        el("strong", { texto: p.bloco ? p.bloco + ": " : "" }),
        document.createTextNode(p.mensagem)
      ]);
    }));
  });
});

// ════════════════════════════════════════
// SIMULADOR
// ════════════════════════════════════════
function reiniciarSimulacao() {
  conversaSimulada = null;
  trocar($("telefone"), [el("div", { classe: "fraco centro",
    texto: "Escreva abaixo como se fosse um cliente no WhatsApp." })]);
  $("eventos-simulacao").textContent = "";
}

$("reiniciar-simulacao").addEventListener("click", reiniciarSimulacao);

$("forma-simular").addEventListener("submit", function (e) {
  e.preventDefault();
  var texto = $("entrada-simulacao").value.trim();
  if (!texto) return;
  $("entrada-simulacao").value = "";
  simular(texto);
});

async function simular(texto) {
  var telefone = $("telefone");

  // Na primeira mensagem some o texto de instrução.
  if (!conversaSimulada) trocar(telefone, []);

  telefone.appendChild(el("div", { classe: "balao nossa", texto: texto }));
  telefone.scrollTop = telefone.scrollHeight;

  try {
    var r = await api("POST", "/bot/simular", {
      mensagem: texto,
      conversa: conversaSimulada,
      nome_contato: "Visitante"
    });
    conversaSimulada = r.conversa;

    if (!r.respostas.length) {
      telefone.appendChild(el("div", { classe: "fraco centro", estilo: "padding:8px",
        texto: "(o bot não responderia nada aqui)" }));
    }

    for (var resposta of r.respostas) {
      var balao = el("div", { classe: "balao deles", texto: resposta.texto });

      // Os botões do simulador são clicáveis e mandam o rótulo de volta
      // — exatamente o que a Meta faz quando alguém toca no botão de
      // verdade. Testar clicando é o que revela o menu que aponta para o
      // lugar errado.
      if (resposta.opcoes && resposta.opcoes.length) {
        balao.appendChild(el("div", { classe: "balao-botoes" }, resposta.opcoes.map(function (o) {
          return el("button", { type: "button", texto: o.rotulo,
            aoClicar: function () { simular(o.rotulo); } });
        })));
      }
      telefone.appendChild(balao);
    }

    $("eventos-simulacao").textContent = r.eventos.length ? "→ " + r.eventos.join(" · ") : "";
    telefone.scrollTop = telefone.scrollHeight;
  } catch (e) {
    recado(e.message, "ruim");
  }
}
