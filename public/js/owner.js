/**
 * Painel de administração da plataforma.
 *
 * Reaproveita os helpers de base.js (el, trocar, recado...) mas tem o
 * seu próprio token: a sessão de owner é separada da de cliente, e
 * misturar as duas no mesmo armazenamento faria "sair" de uma derrubar a
 * outra — ou, pior, mandar o token errado numa chamada administrativa.
 */

import { el, trocar, vazio, recado, ocupado, $, dataHora, quando } from "./base.js";

// Mesma chave que o login central (public/js/app.js) usa para guardar o
// token de quem entrou como dono da plataforma. É o que permite abrir
// esta página direto no painel, sem formulário nenhum, para quem acabou
// de entrar por "/" — e não precisa da senha de novo três segundos
// depois de já ter digitado.
var CHAVE_TOKEN_OWNER = "zapfy.token.owner";

var TOKEN = null;
var contas = [];

// ════════════════════════════════════════
// API ADMINISTRATIVA
// ════════════════════════════════════════
async function api(metodo, caminho, corpo) {
  var opcoes = { method: metodo, headers: {} };
  if (TOKEN) opcoes.headers["Authorization"] = "Bearer " + TOKEN;
  if (corpo !== undefined && corpo !== null) {
    opcoes.headers["Content-Type"] = "application/json";
    opcoes.body = JSON.stringify(corpo);
  }

  var resposta = await fetch("/api/owner" + caminho, opcoes);
  var dados = null;
  try { dados = await resposta.json(); } catch (e) { /* corpo vazio */ }

  if (resposta.status === 401) {
    TOKEN = null;
    localStorage.removeItem(CHAVE_TOKEN_OWNER);
    mostrarEntrada();
    throw new Error((dados && dados.erro) || "Sessão administrativa expirada.");
  }
  if (!resposta.ok) throw new Error((dados && dados.erro) || "Falha ao falar com o servidor.");
  return dados;
}

// ════════════════════════════════════════
// ENTRADA
// ════════════════════════════════════════
function mostrarEntrada() {
  $("tela-entrada-owner").style.display = "grid";
  $("painel-owner").classList.remove("visivel");
}

// Formulário mantido como caminho de reserva — o mesmo motivo do
// Workap manter a rota antiga de login do owner: se por algum motivo o
// token guardado pelo login central não chegar aqui (aba nova, storage
// limpo, link direto para /owner), ainda dá para entrar com e-mail e
// senha, direto nesta página.
$("forma-owner").addEventListener("submit", async function (e) {
  e.preventDefault();
  await ocupado($("botao-owner"), "Entrando...", async function () {
    try {
      var r = await api("POST", "/login", {
        email: $("owner-email").value,
        senha: $("owner-senha").value
      });
      TOKEN = r.token;
      localStorage.setItem(CHAVE_TOKEN_OWNER, r.token);
      $("owner-senha").value = "";
      await entrar(r.owner.email);
    } catch (erro) {
      recado(erro.message, "ruim");
    }
  });
});

async function entrar(email) {
  $("tela-entrada-owner").style.display = "none";
  $("painel-owner").classList.add("visivel");
  $("owner-identidade").textContent = email;
  await abrir("resumo");
}

$("sair-owner").addEventListener("click", function () {
  TOKEN = null;
  localStorage.removeItem(CHAVE_TOKEN_OWNER);
  location.reload();
});

// ════════════════════════════════════════
// ENTRADA AUTOMÁTICA
// ════════════════════════════════════════
// Quem acabou de entrar pelo login central (public/js/app.js) chega
// aqui com o token já em localStorage — o formulário acima nem aparece.
(async function () {
  var guardado = localStorage.getItem(CHAVE_TOKEN_OWNER);
  if (!guardado) return;

  TOKEN = guardado;
  try {
    var r = await api("GET", "/eu");
    await entrar(r.owner.email);
  } catch (e) {
    // Token velho ou revogado (troca de OWNER_EMAIL/SENHA no ambiente).
    // A tela de entrada continua disponível — sem isso, /owner ficaria
    // preso tentando um token que nunca mais vai funcionar.
    TOKEN = null;
    localStorage.removeItem(CHAVE_TOKEN_OWNER);
  }
})();

// ════════════════════════════════════════
// ABAS
// ════════════════════════════════════════
var carregadores = {
  resumo: carregarResumo,
  contas: carregarContas,
  saude: carregarSaude,
  auditoria: carregarAuditoria
};

async function abrir(aba) {
  document.querySelectorAll("#painel-owner .pagina").forEach(function (p) {
    p.classList.toggle("ativa", p.id === "aba-" + aba);
  });
  document.querySelectorAll("#abas-owner button").forEach(function (b) {
    b.classList.toggle("ativa", b.dataset.aba === aba);
  });

  try { await carregadores[aba](); }
  catch (e) { recado(e.message, "ruim"); }
}

document.querySelectorAll("#abas-owner button").forEach(function (b) {
  b.addEventListener("click", function () { abrir(b.dataset.aba); });
});

// ════════════════════════════════════════
// RESUMO
// ════════════════════════════════════════
async function carregarResumo() {
  var r = await api("GET", "/resumo");
  var n = r.numeros;

  $("resumo-atualizado").textContent = "Atualizado às " +
    new Date().toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" });

  // O alerta só aparece quando há alguém quebrado. Um painel que avisa
  // sempre vira decoração, e aí o aviso que importava passa junto.
  var alertas = [];
  if (n.com_erro > 0) {
    alertas.push(el("div", { classe: "aviso ruim" }, [
      el("strong", { texto: n.com_erro + " cliente(s) com o WhatsApp caído. " }),
      el("button", {
        classe: "botao neutro pequeno", texto: "Ver quem",
        aoClicar: function () { abrir("saude"); }
      })
    ]));
  }
  if (n.falhas_24h > 20) {
    alertas.push(el("div", { classe: "aviso atento",
      texto: n.falhas_24h + " mensagens falharam nas últimas 24h. Vale conferir se é um cliente só ou a plataforma." }));
  }
  trocar($("alerta-plataforma"), alertas);

  trocar($("indicadores-contas"), [
    ind("Contas", n.contas_total),
    ind("Ativas", n.contas_ativas),
    ind("Em trial", n.contas_trial),
    ind("Inadimplentes", n.contas_inadimplentes, n.contas_inadimplentes > 0),
    ind("Suspensas", n.contas_suspensas, n.contas_suspensas > 0),
    ind("Novas (7 dias)", n.contas_7d),
    ind("Novas (30 dias)", n.contas_30d),
    // A métrica que diz se o produto está vivo. Cadastro sem uso é vaidade.
    ind("Usando de fato (7d)", n.contas_usando_7d)
  ]);

  trocar($("indicadores-conexoes"), [
    ind("Conectadas", n.conectadas),
    ind("Com erro", n.com_erro, n.com_erro > 0),
    ind("Pausadas", n.pausadas),
    ind("Sem conectar", n.nao_conectadas)
  ]);

  trocar($("indicadores-uso"), [
    ind("Mensagens (24h)", n.mensagens_24h),
    ind("Mensagens (7 dias)", n.mensagens_7d),
    ind("Conversas (24h)", n.conversas_24h),
    ind("Contatos", n.contatos),
    ind("Falhas (24h)", n.falhas_24h, n.falhas_24h > 0)
  ]);

  desenharGrafico(r.serie);
}

function ind(rotulo, valor, atencao) {
  return el("div", { classe: "indicador" }, [
    el("div", { classe: "rotulo", texto: rotulo }),
    el("div", { classe: "valor" + (atencao ? " atencao" : ""),
                texto: (valor == null ? 0 : valor).toLocaleString("pt-BR") })
  ]);
}

function desenharGrafico(serie) {
  var maior = Math.max.apply(null, serie.map(function (d) { return d.mensagens; }).concat([1]));

  trocar($("grafico-owner"), serie.map(function (d) {
    // A data é montada pelos pedaços: `new Date("2026-08-14")` é lida
    // como meia-noite UTC e, no Brasil, cai no dia anterior.
    var p = d.dia.split("-");
    var data = new Date(+p[0], +p[1] - 1, +p[2]);

    return el("div", { classe: "dia",
      title: d.mensagens + " mensagens, " + d.contas + " contas ativas" }, [
      el("div", { classe: "barras" }, [
        el("div", { classe: "barra entrada", estilo: "height:" + (d.mensagens / maior * 100) + "%" })
      ]),
      el("div", { classe: "rotulo-dia", texto: data.getDate() + "/" + (data.getMonth() + 1) })
    ]);
  }));
}

// ════════════════════════════════════════
// CONTAS
// ════════════════════════════════════════
async function carregarContas() {
  var filtro = $("filtro-contas").value;
  var busca = $("busca-contas").value.trim();

  contas = await api("GET", "/contas?filtro=" + filtro +
    (busca ? "&busca=" + encodeURIComponent(busca) : ""));

  var corpo = $("corpo-contas");

  if (!contas.length) {
    trocar(corpo, [el("tr", {}, [
      el("td", { colspan: "9" }, [vazio("🏢", "Nenhuma conta com esse filtro.")])
    ])]);
    return;
  }

  trocar(corpo, contas.map(function (c) {
    var linha = el("tr", { classe: (c.status === "suspensa" || c.status === "inadimplente") ? "linha-suspensa" : "" }, [
      el("td", {}, [
        el("strong", { texto: c.nome }),
        c.observacao ? el("div", { classe: "fraco", texto: "📌 " + c.observacao }) : null
      ]),
      el("td", { classe: "fraco", texto: c.email_dono || "—" }),
      el("td", {}, [el("span", { classe: "etiqueta", texto: c.plano })]),
      el("td", {}, [seloStatusConta(c)]),
      el("td", {}, [seloConexao(c)]),
      el("td", { classe: "num", texto: Number(c.mensagens_7d).toLocaleString("pt-BR") }),
      el("td", { classe: "num", texto: String(c.conversas) }),
      el("td", { classe: "fraco", texto: quando(c.criado_em) }),
      el("td", {}, [el("span", { classe: "fraco", texto: "›" })])
    ]);

    linha.addEventListener("click", function () { abrirFicha(c.id); });
    return linha;
  }));
}

function selo(tipo, texto) {
  return el("span", { classe: "selo-mini " + tipo, texto: texto });
}

// 'ativa' e 'trial' atendem (bom/atenção); 'inadimplente' e 'suspensa'
// não (ruim) — a mesma regra de src/lib/contaEstado.js, só que em rótulo.
function seloStatusConta(c) {
  if (c.status === "ativa")        return selo("ok", "ativa");
  if (c.status === "trial") {
    var dias = diasRestantesTrial(c.trial_fim);
    return selo("atencao", dias == null ? "trial" : "trial · " + dias + "d");
  }
  if (c.status === "inadimplente")  return selo("ruim", "inadimplente");
  if (c.status === "suspensa")      return selo("ruim", "suspensa");
  return selo("neutro", c.status);
}

function diasRestantesTrial(trialFim) {
  if (!trialFim) return null;
  var ms = new Date(trialFim).getTime() - Date.now();
  return Math.max(0, Math.ceil(ms / (1000 * 60 * 60 * 24)));
}

function seloConexao(c) {
  if (!c.conexao_status || c.conexao_status === "desconectado") return selo("neutro", "sem conexão");
  if (c.conexao_status === "conectado") return selo("ok", c.numero || "conectado");
  if (c.conexao_status === "erro") return selo("ruim", "caiu");
  if (c.conexao_status === "pausado") return selo("atencao", "pausado");
  return selo("atencao", "falta webhook");
}

$("filtro-contas").addEventListener("change", function () {
  carregarContas().catch(function (e) { recado(e.message, "ruim"); });
});

var esperaBusca = null;
$("busca-contas").addEventListener("input", function () {
  clearTimeout(esperaBusca);
  esperaBusca = setTimeout(function () {
    carregarContas().catch(function (e) { recado(e.message, "ruim"); });
  }, 350);
});

// ════════════════════════════════════════
// FICHA DA CONTA
// ════════════════════════════════════════
async function abrirFicha(id) {
  var d = await api("GET", "/contas/" + id);

  $("ficha").classList.remove("oculto");
  $("ficha-nome").textContent = d.conta.nome;
  $("ficha-email").textContent = (d.usuarios[0] && d.usuarios[0].email) || "";

  var partes = [];

  if (d.conta.status === "suspensa") {
    partes.push(el("div", { classe: "aviso ruim" }, [
      el("strong", { texto: "Conta suspensa. " }),
      document.createTextNode(d.conta.motivo_suspensao || "Sem motivo registrado.")
    ]));
  }
  if (d.conta.status === "inadimplente") {
    partes.push(el("div", { classe: "aviso ruim" }, [
      el("strong", { texto: "Trial acabou. " }),
      document.createTextNode("O bot desta conta parou de responder até ela assinar um plano.")
    ]));
  }
  if (d.conta.status === "trial") {
    var diasT = diasRestantesTrial(d.conta.trial_fim);
    partes.push(el("div", { classe: "aviso atento" }, [
      el("strong", { texto: "Em trial. " }),
      document.createTextNode(diasT == null ? "" : "Faltam " + diasT + " dia(s) para o teste grátis acabar.")
    ]));
  }

  // ── Ações ──
  partes.push(el("div", { classe: "grupo-botoes", estilo: "margin-bottom:16px" }, [
    (d.conta.status === "ativa" || d.conta.status === "trial")
      ? el("button", { classe: "botao perigo pequeno", texto: "Suspender",
          aoClicar: function () { suspender(d.conta); } })
      : el("button", { classe: "botao pequeno", texto: "Reativar",
          aoClicar: function () { agir(d.conta.id, "reativar", {}, "Conta reativada."); } }),

    el("button", {
      classe: "botao neutro pequeno",
      texto: d.conta.plano === "pro" ? "Mudar para grátis" : "Mudar para Pro",
      aoClicar: function () {
        agir(d.conta.id, "plano", { plano: d.conta.plano === "pro" ? "gratis" : "pro" }, "Plano alterado.");
      }
    }),

    el("button", { classe: "botao neutro pequeno", texto: "Anotar",
      aoClicar: function () { anotar(d.conta); } })
  ]));

  // ── Dados ──
  partes.push(el("div", { classe: "ficha-secao", texto: "Conta" }));
  partes.push(fl("Plano", d.conta.plano));
  partes.push(fl("Status", d.conta.status +
    (d.conta.status === "trial" ? " (" + diasRestantesTrial(d.conta.trial_fim) + " dia(s) restantes)" : "")));
  partes.push(fl("Cadastro", dataHora(d.conta.criado_em)));
  if (d.conta.observacao) partes.push(fl("Anotação", d.conta.observacao));

  // ── Uso ──
  partes.push(el("div", { classe: "ficha-secao", texto: "Uso" }));
  partes.push(fl("Conversas", String(d.uso.conversas)));
  partes.push(fl("Contatos", String(d.uso.contatos)));
  partes.push(fl("Mensagens (total)", Number(d.uso.mensagens_total).toLocaleString("pt-BR")));
  partes.push(fl("Mensagens (7 dias)", Number(d.uso.mensagens_7d).toLocaleString("pt-BR")));
  partes.push(fl("Última mensagem", d.uso.ultima_mensagem ? dataHora(d.uso.ultima_mensagem) : "nunca"));

  // ── WhatsApp ──
  partes.push(el("div", { classe: "ficha-secao", texto: "WhatsApp" }));
  if (!d.conexao) {
    partes.push(el("p", { classe: "fraco", texto: "Nunca configurou." }));
  } else {
    partes.push(fl("Status", d.conexao.status));
    partes.push(fl("Número", d.conexao.numero_exibicao || "—"));
    partes.push(fl("Nome verificado", d.conexao.nome_exibicao || "—"));
    partes.push(fl("Credencial", d.conexao.token_configurado ? "cadastrada" : "não cadastrada"));
    partes.push(fl("App Secret", d.conexao.app_secret_configurado ? "cadastrado" : "não cadastrado"));
    partes.push(fl("Webhook validado", dataHora(d.conexao.webhook_verificado_em)));
    partes.push(fl("Última verificação", dataHora(d.conexao.verificado_em)));
    partes.push(fl("Enviadas / recebidas",
      Number(d.conexao.total_enviadas).toLocaleString("pt-BR") + " / " +
      Number(d.conexao.total_recebidas).toLocaleString("pt-BR")));
    if (d.conexao.ultimo_erro) partes.push(fl("Último erro", d.conexao.ultimo_erro));
  }

  // ── Bot ──
  partes.push(el("div", { classe: "ficha-secao", texto: "Chatbot" }));
  if (!d.bot) {
    partes.push(el("p", { classe: "fraco", texto: "Sem bot ativo." }));
  } else {
    partes.push(fl("Nome", d.bot.nome));
    partes.push(fl("Blocos no fluxo", String(d.bot.blocos)));
    partes.push(fl("Horário comercial", d.bot.atendimento_ativo ? "ligado" : "24h"));
    partes.push(fl("Última edição", dataHora(d.bot.atualizado_em)));
  }

  // ── Usuários ──
  partes.push(el("div", { classe: "ficha-secao", texto: "Pessoas com acesso" }));
  d.usuarios.forEach(function (u) {
    partes.push(fl(u.nome + " (" + u.papel + ")",
      u.email + (u.ultimo_login_em ? " · entrou " + quando(u.ultimo_login_em) : " · nunca entrou")));
  });

  // ── Problemas ──
  if (d.problemas.length) {
    partes.push(el("div", { classe: "ficha-secao", texto: "Erros e avisos recentes" }));
    d.problemas.forEach(function (p) {
      partes.push(el("div", { classe: "ficha-linha" }, [
        el("span", { classe: "nivel-" + p.nivel, texto: p.evento }),
        el("strong", { estilo: "font-weight:400;font-size:.8125rem", texto: p.mensagem })
      ]));
    });
  }

  // A ausência de "ver conversas" aqui é deliberada, não um esquecimento:
  // administrar a plataforma não exige ler o que os consumidores
  // escreveram para os clientes.
  partes.push(el("p", { classe: "fraco", estilo: "margin-top:20px",
    texto: "O conteúdo das conversas desta conta não é acessível por aqui — só o cliente vê as próprias mensagens." }));

  trocar($("ficha-corpo"), partes);
}

function fl(rotulo, valor) {
  return el("div", { classe: "ficha-linha" }, [
    el("span", { texto: rotulo }),
    el("strong", { texto: valor == null ? "—" : String(valor) })
  ]);
}

async function agir(id, acao, corpo, aviso) {
  try {
    await api("POST", "/contas/" + id + "/" + acao, corpo);
    recado(aviso, "bom");
    await abrirFicha(id);
    await carregarContas();
  } catch (e) {
    recado(e.message, "ruim");
  }
}

function suspender(conta) {
  var motivo = prompt("Motivo da suspensão (aparece para você, não para o cliente):", "");
  if (motivo === null) return;   // cancelou
  agir(conta.id, "suspender", { motivo: motivo }, "Conta suspensa. O bot dela parou de responder.");
}

function anotar(conta) {
  var texto = prompt("Anotação interna sobre esta conta:", conta.observacao || "");
  if (texto === null) return;
  agir(conta.id, "observacao", { observacao: texto }, "Anotação salva.");
}

$("fechar-ficha").addEventListener("click", function () {
  $("ficha").classList.add("oculto");
});

$("ficha").addEventListener("click", function (e) {
  // Só o fundo fecha; um clique dentro do painel não pode fechá-lo no
  // meio de uma leitura.
  if (e.target === $("ficha")) $("ficha").classList.add("oculto");
});

// ════════════════════════════════════════
// SAÚDE
// ════════════════════════════════════════
async function carregarSaude() {
  var s = await api("GET", "/saude");

  trocar($("conexoes-quebradas"), s.conexoes_quebradas.length
    ? s.conexoes_quebradas.map(function (c) {
        return el("div", { classe: "ficha-linha" }, [
          el("span", {}, [
            el("strong", { texto: c.nome }),
            el("div", { classe: "fraco", texto: c.ultimo_erro || "sem detalhe" })
          ]),
          el("span", { classe: "fraco", texto: quando(c.ultimo_erro_em) })
        ]);
      })
    : [el("p", { classe: "vazio", texto: "Nenhuma conexão com erro. 🎉" })]);

  trocar($("falhas-envio"), s.falhas_por_conta.length
    ? s.falhas_por_conta.map(function (f) {
        return el("div", { classe: "ficha-linha" }, [
          el("span", { texto: f.nome }),
          el("strong", { texto: f.falhas + " falha(s)" })
        ]);
      })
    : [el("p", { classe: "vazio", texto: "Nenhuma falha de envio nas últimas 24h." })]);

  trocar($("erros-plataforma"), s.erros_recentes.length
    ? s.erros_recentes.map(function (e) {
        return el("tr", {}, [
          el("td", { classe: "fraco", texto: dataHora(e.criado_em) }),
          el("td", { texto: e.conta_nome }),
          el("td", { classe: "nivel-erro", texto: e.evento }),
          el("td", { texto: e.mensagem })
        ]);
      })
    : [el("tr", {}, [el("td", { colspan: "4" }, [
        el("div", { classe: "vazio", texto: "Nenhum erro registrado nas últimas 48h." })
      ])])]);
}

$("atualizar-saude").addEventListener("click", function () {
  carregarSaude().catch(function (e) { recado(e.message, "ruim"); });
});
$("atualizar-resumo").addEventListener("click", function () {
  carregarResumo().catch(function (e) { recado(e.message, "ruim"); });
});

// ════════════════════════════════════════
// AUDITORIA
// ════════════════════════════════════════
var ROTULO_ACAO = {
  suspender: "suspendeu", reativar: "reativou",
  mudar_plano: "mudou o plano", anotar: "anotou"
};

async function carregarAuditoria() {
  var acoes = await api("GET", "/acoes");

  trocar($("corpo-auditoria"), acoes.length
    ? acoes.map(function (a) {
        return el("tr", {}, [
          el("td", { classe: "fraco", texto: dataHora(a.criado_em) }),
          el("td", { texto: a.autor }),
          el("td", { texto: ROTULO_ACAO[a.acao] || a.acao }),
          el("td", { texto: a.conta_nome || "—" }),
          el("td", { classe: "fraco", texto: a.detalhe ? JSON.stringify(a.detalhe) : "" })
        ]);
      })
    : [el("tr", {}, [el("td", { colspan: "5" }, [
        el("div", { classe: "vazio", texto: "Nenhuma ação administrativa ainda." })
      ])])]);
}
