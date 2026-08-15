"use strict";

/**
 * Rate limiting por IP + rota, em memória.
 *
 * Em memória e não em Redis por uma escolha consciente de estágio: com
 * uma instância, o Map resolve; com várias, cada uma contaria por si e o
 * limite efetivo viraria N vezes o configurado. Está anotado aqui, e não
 * numa issue, porque é o ponto exato que precisa mudar no dia em que a
 * plataforma escalar horizontalmente — e é uma troca de implementação
 * desta função, nada além.
 */

var contadores = new Map();

// Faxina periódica. Sem ela, cada IP que passou uma vez pelo sistema
// ocupa memória para sempre — o vazamento clássico de rate limiter
// caseiro, que só aparece semanas depois como "o servidor incha".
setInterval(function () {
  var agora = Date.now();
  for (var [chave, dado] of contadores) {
    if (agora > dado.reinicia) contadores.delete(chave);
  }
}, 5 * 60 * 1000).unref();   // unref: não segura o processo vivo nos testes

/**
 * @param {number} maximo   requisições permitidas na janela
 * @param {number} janelaMs tamanho da janela
 * @param {string} nome     rótulo do balde (rotas diferentes não se somam)
 */
function limitar(maximo, janelaMs, nome) {
  return function (req, res, proximo) {
    // `x-forwarded-for` só é confiável atrás de um proxy que o
    // sobrescreve (Render, Railway, Cloudflare fazem isso). Direto na
    // internet, o cliente pode forjar o cabeçalho e furar o limite —
    // por isso o socket é o fallback, nunca o contrário.
    var encaminhado = req.headers["x-forwarded-for"];
    var ip = encaminhado
      ? String(encaminhado).split(",")[0].trim()
      : (req.socket.remoteAddress || "desconhecido");

    var chave = nome + ":" + ip;
    var agora = Date.now();
    var dado = contadores.get(chave);

    if (!dado || agora > dado.reinicia) {
      dado = { contagem: 0, reinicia: agora + janelaMs };
    }

    dado.contagem++;
    contadores.set(chave, dado);

    if (dado.contagem > maximo) {
      var segundos = Math.ceil((dado.reinicia - agora) / 1000);
      res.set("Retry-After", String(segundos));
      return res.status(429).json({
        erro: "Muitas tentativas. Tente de novo em " + segundos + " segundos."
      });
    }

    proximo();
  };
}

/** Zera os contadores — usado entre casos de teste. */
function zerar() { contadores.clear(); }

module.exports = { limitar, zerar };
