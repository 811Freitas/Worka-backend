/**
 * Tela de conexão do WhatsApp.
 *
 * É a tela mais importante do produto e a que mais falha na mão do
 * cliente — porque metade do trabalho acontece num site que não é o
 * nosso (o painel da Meta). Por isso ela é um assistente por passos, com
 * os valores prontos para copiar e o estado real da conexão sempre
 * visível.
 */

import { api, $, el, trocar, recado, ocupado, dataHora, pintarSelo } from "./base.js";

var conexao = null;
var relogio = null;

export async function carregarConexao() {
  await atualizar();

  // Enquanto a tela estiver aberta, o estado se atualiza sozinho. É o
  // que faz o passo 3 virar "conectado" na hora em que a Meta valida o
  // webhook, sem a pessoa ficar apertando F5 sem saber se deu certo.
  pararRelogioConexao();
  relogio = setInterval(function () {
    atualizar().catch(function () { /* rede oscilando: a próxima volta */ });
  }, 5000);
}

export function pararRelogioConexao() {
  if (relogio) clearInterval(relogio);
  relogio = null;
}

async function atualizar() {
  conexao = await api("GET", "/whatsapp/conexao");

  pintarSelo($("selo-conexao-2"), conexao.status);
  desenharAviso();
  desenharResumo();
  desenharAcoes();
  desenharPassos();
}

function desenharAviso() {
  var caixa = $("aviso-conexao");

  if (conexao.status === "erro") {
    trocar(caixa, [el("div", { classe: "aviso ruim" }, [
      el("strong", { texto: "Seu bot está fora do ar. " }),
      document.createTextNode(conexao.ultimo_erro || "A Meta recusou as credenciais.")
    ])]);
  } else if (conexao.status === "conectado") {
    trocar(caixa, [el("div", { classe: "aviso bom",
      texto: "Tudo certo. Seu chatbot está atendendo automaticamente, 24 horas por dia." })]);
  } else if (conexao.status === "aguardando_webhook") {
    trocar(caixa, [el("div", { classe: "aviso atento",
      texto: "As credenciais foram aceitas — falta só o passo 3, cadastrar o webhook no painel da Meta. Sem ele o bot envia, mas não recebe." })]);
  } else if (conexao.status === "pausado") {
    trocar(caixa, [el("div", { classe: "aviso atento",
      texto: "Bot pausado. As mensagens continuam chegando e sendo gravadas, mas ninguém recebe resposta automática." })]);
  } else {
    trocar(caixa, []);
  }

  if (conexao.token_configurado && !conexao.app_secret_configurado) {
    caixa.appendChild(el("div", { classe: "aviso atento",
      texto: "Sem o App Secret não conseguimos provar que uma mensagem veio mesmo da Meta. Recomendamos preencher no passo 2." }));
  }
}

function desenharResumo() {
  trocar($("resumo-conexao"), [
    linha("Número", conexao.numero_exibicao || "—"),
    linha("Nome verificado", conexao.nome_exibicao || "—"),
    linha("Phone Number ID", conexao.phone_number_id || "—"),
    linha("Token", conexao.token_configurado ? conexao.token_final : "não cadastrado"),
    linha("App Secret", conexao.app_secret_configurado ? "configurado" : "não cadastrado"),
    linha("Webhook validado em", dataHora(conexao.webhook_verificado_em)),
    // A diferença entre "estava conectado quando você configurou" e
    // "está conectado agora" — é esta linha que o monitor alimenta.
    linha("Última verificação com a Meta", dataHora(conexao.verificado_em)),
    linha("Mensagens recebidas", String(conexao.total_recebidas)),
    linha("Mensagens enviadas", String(conexao.total_enviadas))
  ]);
}

function linha(rotulo, valor) {
  return el("div", { estilo: "display:flex;justify-content:space-between;gap:16px;padding:9px 0;border-bottom:1px solid var(--linha)" }, [
    el("span", { classe: "sub", texto: rotulo }),
    el("strong", { estilo: "text-align:right;word-break:break-all", texto: valor })
  ]);
}

function desenharAcoes() {
  var acoes = [];

  if (conexao.token_configurado) {
    acoes.push(botao("Testar agora", "neutro", "/whatsapp/conexao/testar",
      "Credenciais conferidas com a Meta."));

    if (conexao.status === "pausado") {
      acoes.push(botao("Retomar", "", "/whatsapp/conexao/retomar", "Bot retomado."));
    } else {
      acoes.push(botao("Pausar bot", "neutro", "/whatsapp/conexao/pausar",
        "Bot pausado. As mensagens continuam sendo gravadas."));
    }

    acoes.push(botao("Reiniciar", "neutro", "/whatsapp/conexao/reiniciar",
      "Reiniciado: credenciais revalidadas e conversas travadas devolvidas ao bot."));

    acoes.push(el("button", {
      classe: "botao perigo pequeno", texto: "Desconectar",
      aoClicar: async function () {
        if (!confirm("Desconectar o WhatsApp? O bot para de atender na hora, e você precisará cadastrar o webhook de novo na Meta para religar.")) return;
        try {
          await api("DELETE", "/whatsapp/conexao");
          await atualizar();
          recado("WhatsApp desconectado.", "bom");
        } catch (e) {
          recado(e.message, "ruim");
        }
      }
    }));
  }

  trocar($("acoes-conexao"), acoes);
}

function botao(rotulo, estilo, caminho, aviso) {
  return el("button", {
    classe: "botao pequeno " + estilo, texto: rotulo,
    aoClicar: async function () {
      var esse = this;
      await ocupado(esse, "...", async function () {
        try {
          await api("POST", caminho, {});
          await atualizar();
          recado(aviso, "bom");
        } catch (e) {
          await atualizar();
          recado(e.message, "ruim");
        }
      });
    }
  });
}

/**
 * Marca os passos já cumpridos.
 *
 * Ver o passo 2 verde e o 3 cinza responde, sem ler nada, a pergunta que
 * a pessoa tem na cabeça: "onde eu parei?".
 */
function desenharPassos() {
  $("passo-1").classList.toggle("pronto", !!conexao.token_configurado);
  $("passo-2").classList.toggle("pronto", !!conexao.token_configurado);
  $("passo-3").classList.toggle("pronto", !!conexao.webhook_verificado_em);

  $("webhook-url").textContent = conexao.webhook_url;
  $("webhook-token").textContent = conexao.verify_token;

  if (conexao.phone_number_id && !$("conexao-phone-id").value) {
    $("conexao-phone-id").value = conexao.phone_number_id;
  }
}

$("salvar-conexao").addEventListener("click", async function () {
  await ocupado(this, "Conectando...", async function () {
    try {
      await api("POST", "/whatsapp/conexao", {
        phone_number_id: $("conexao-phone-id").value,
        token: $("conexao-token").value || undefined,
        app_secret: $("conexao-app-secret").value || undefined
      });

      // Os campos de segredo são esvaziados assim que são aceitos: nada
      // ganha em ficar um token da Meta escrito num input, visível a
      // quem passar atrás da pessoa ou abrir o DevTools.
      $("conexao-token").value = "";
      $("conexao-app-secret").value = "";

      await atualizar();
      recado("Credenciais aceitas pela Meta!", "bom");
    } catch (e) {
      recado(e.message, "ruim");
    }
  });
});

document.querySelectorAll("[data-copiar]").forEach(function (botao) {
  botao.addEventListener("click", async function () {
    var texto = $(botao.dataset.copiar).textContent;
    try {
      await navigator.clipboard.writeText(texto);
      recado("Copiado.", "bom");
    } catch (e) {
      // navigator.clipboard não existe fora de HTTPS (ou de localhost).
      // Selecionar o texto deixa a pessoa copiar com Ctrl+C, em vez de
      // ficar sem saída porque o navegador recusou.
      var faixa = document.createRange();
      faixa.selectNodeContents($(botao.dataset.copiar));
      var selecao = window.getSelection();
      selecao.removeAllRanges();
      selecao.addRange(faixa);
      recado("Selecionado — use Ctrl+C para copiar.", "");
    }
  });
});
