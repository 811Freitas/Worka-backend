/**
 * Página de apresentação (landing) — sem formulário, sem chamada à API.
 * Só decoração: revelar seções ao rolar, o celular do hero "conversando"
 * sozinho, e o botão flutuante que aparece depois do topo.
 */

var ano = document.getElementById("ano-rodape");
if (ano) ano.textContent = new Date().getFullYear();

var SEM_MOVIMENTO = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

// Marca o <html> só depois que este script rodou de verdade — os
// elementos .reveal começam OCULTOS apenas quando .js-pronto existe
// (ver site.css). Sem essa marca condicional, JS travado ou desligado
// deixaria a página inteira em branco para sempre.
document.documentElement.classList.add("js-pronto");

// ════════════════════════════════════════
// REVELAR AO ROLAR
// ════════════════════════════════════════
(function () {
  var alvos = document.querySelectorAll(".reveal");
  if (!alvos.length) return;

  if (SEM_MOVIMENTO || !("IntersectionObserver" in window)) {
    alvos.forEach(function (el) { el.classList.add("visivel"); });
    return;
  }

  var observador = new IntersectionObserver(function (entradas) {
    entradas.forEach(function (entrada) {
      if (entrada.isIntersecting) {
        entrada.target.classList.add("visivel");
        observador.unobserve(entrada.target);
      }
    });
  }, { threshold: 0.15, rootMargin: "0px 0px -40px 0px" });

  alvos.forEach(function (el) { observador.observe(el); });
})();

// ════════════════════════════════════════
// BOTÃO FLUTUANTE
// ════════════════════════════════════════
(function () {
  var botao = document.getElementById("botao-flutuante");
  var hero = document.querySelector(".site-hero");
  if (!botao || !hero) return;

  function atualizar() {
    var passouDoHero = window.scrollY > hero.offsetHeight * 0.6;
    botao.classList.toggle("mostrar", passouDoHero);
  }

  window.addEventListener("scroll", atualizar, { passive: true });
  atualizar();
})();

// ════════════════════════════════════════
// CELULAR DO HERO — conversa em loop
// ════════════════════════════════════════
(function () {
  var balões = Array.prototype.slice.call(document.querySelectorAll(".site-celular-balao"));
  var digitando = document.getElementById("celular-digitando");
  if (!balões.length) return;

  // Sem movimento: mostra a conversa inteira, parada, e some com o
  // indicador de "digitando" — que não faz sentido continuar piscando.
  if (SEM_MOVIMENTO) {
    balões.forEach(function (b) { b.classList.add("mostrar"); });
    return;
  }

  var indice = 0;

  function esperar(ms) {
    return new Promise(function (resolver) { setTimeout(resolver, ms); });
  }

  // Um laço só, para sempre — landing page não desmonta este script no
  // meio, então não há "cancelar" para coordenar. Enquanto a aba está em
  // segundo plano, o navegador já atrasa os timers sozinho; não precisa
  // de lógica própria para isso.
  async function ciclo() {
    for (;;) {
      var balao = balões[indice];

      // Mensagem "nossa" (do cliente) aparece direto — só a resposta do
      // bot é precedida do indicador de digitação, porque é o bot quem
      // está "pensando" na conversa.
      if (balao.classList.contains("deles") && digitando) {
        digitando.classList.add("mostrar");
        await esperar(900);
        digitando.classList.remove("mostrar");
      }

      balao.classList.add("mostrar");
      await esperar(indice === balões.length - 1 ? 3200 : 1400);

      indice++;
      if (indice >= balões.length) {
        await esperar(1600);
        balões.forEach(function (b) { b.classList.remove("mostrar"); });
        indice = 0;
        await esperar(600);
      }
    }
  }

  ciclo();
})();
