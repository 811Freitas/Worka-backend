/**
 * Chat da demonstração pública.
 *
 * O estado da conversa vive só nesta variável, na aba do navegador — o
 * mesmo desenho do simulador do construtor (veja construtor.js), e pelo
 * mesmo motivo: sem isso, cada tecla exigiria o servidor guardar sessão
 * de gente que nunca criou conta.
 */
import { api, el, $, ocupado, limpar } from "./base.js";

var conversa = null;   // null = conversa nova
var primeiraMensagemEnviada = false;

var caixa = $("demo-mensagens");

function balaoDoBot(texto, opcoes) {
  var balao = el("div", { classe: "balao deles", texto: texto });
  if (opcoes && opcoes.length) {
    balao.appendChild(el("div", { classe: "balao-botoes" }, opcoes.map(function (o) {
      return el("button", { type: "button", texto: o.rotulo,
        aoClicar: function () { enviar(o.rotulo); } });
    })));
  }
  caixa.appendChild(balao);
}

function balaoDaPessoa(texto) {
  caixa.appendChild(el("div", { classe: "balao nossa", texto: texto }));
}

function rolarParaFinal() {
  caixa.scrollTop = caixa.scrollHeight;
}

async function chamarMotor(texto) {
  try {
    var r = await api("POST", "/demo/mensagem", {
      mensagem: texto,
      conversa: conversa
    });

    conversa = r.conversa;
    r.respostas.forEach(function (resposta) {
      balaoDoBot(resposta.texto, resposta.opcoes);
    });
    rolarParaFinal();
  } catch (e) {
    balaoDoBot("(A demonstração está indisponível agora. Tente de novo em instantes.)");
  }
}

async function enviar(texto) {
  var limpo = String(texto || "").trim();
  if (!limpo) return;

  balaoDaPessoa(limpo);
  rolarParaFinal();

  // Um atendente humano "assumiu" a conversa no fluxo de exemplo (opção
  // "Falar com atendente"). Na demo não existe atendente de verdade do
  // outro lado — a próxima mensagem simplesmente devolve para o bot, com
  // um aviso, em vez de ficar em silêncio para sempre.
  if (conversa && conversa.status === "humano") {
    conversa = Object.assign({}, conversa, { status: "bot", bloco_chave: null });
    balaoDoBot("(Em uma conta de verdade, um atendente humano responderia por aqui. Nesta demonstração, volto a ser o bot.) 🤖");
  }

  await chamarMotor(limpo);
}

$("demo-forma").addEventListener("submit", function (e) {
  e.preventDefault();
  var campo = $("demo-entrada");
  var texto = campo.value;
  campo.value = "";
  ocupado($("demo-enviar"), "...", function () { return enviar(texto); });
});

$("demo-reiniciar").addEventListener("click", function () {
  conversa = null;
  primeiraMensagemEnviada = false;
  limpar(caixa);
  arrancar();
});

// A primeira mensagem do bot (boas-vindas + menu) sai sozinha, sem
// esperar a pessoa digitar nada e sem um balão falso em nome dela — é
// assim que um contato novo experimenta o bot de verdade no WhatsApp:
// ele fala primeiro, antes de qualquer coisa ser digitada.
function arrancar() {
  if (primeiraMensagemEnviada) return;
  primeiraMensagemEnviada = true;
  chamarMotor("");
}

document.getElementById("ano-rodape") &&
  (document.getElementById("ano-rodape").textContent = new Date().getFullYear());

arrancar();
