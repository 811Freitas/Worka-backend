"use strict";

/**
 * MOTOR DE CONVERSA
 * ════════════════════════════════════════════════════════════
 * Dada a configuração do bot, os blocos do fluxo, o estado atual da
 * conversa e o que a pessoa acabou de escrever, decide o que responder e
 * qual passa a ser o novo estado.
 *
 * ESTE ARQUIVO NÃO FAZ I/O. Não lê banco, não chama a Meta, não olha o
 * relógio por conta própria (a hora entra por parâmetro). É uma função
 * de (estado, entrada) para (respostas, novo estado).
 *
 * Por que isso importa mais do que parece:
 *
 * 1. Testar. O comportamento do bot — que é o produto — é verificável
 *    sem WhatsApp, sem banco e sem rede. A suíte roda o fluxo inteiro,
 *    com dezenas de caminhos, em milissegundos.
 * 2. Simular. O painel tem um "testar bot" que conversa de verdade com
 *    o cliente antes de ele conectar número nenhum. É este mesmo motor,
 *    chamado direto — não uma imitação que um dia diverge do real.
 * 3. Trocar de provedor. Se um dia entrar um segundo canal, o motor não
 *    muda: ele nunca soube que existia WhatsApp.
 * ════════════════════════════════════════════════════════════
 */

/**
 * Normaliza texto para comparação: minúsculas, sem acento, sem
 * pontuação nas pontas, espaços colapsados.
 *
 * É o que faz "Preço", "preco", "PREÇO!" e " preço " serem a mesma
 * palavra-chave. Sem isso, o cliente cadastra o gatilho "preço" e todo
 * mundo que digita "preco" cai no fallback — o defeito mais comum de
 * bot em português, e o mais irritante para quem está do outro lado.
 */
function normalizar(texto) {
  return String(texto == null ? "" : texto)
    .normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^\w\s@+-]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Troca {{variavel}} pelo valor guardado na conversa.
 *
 * Variável inexistente vira string vazia, nunca o texto "{{nome}}" na
 * cara do cliente: um erro de digitação do dono do bot não pode virar
 * mensagem quebrada para o consumidor final.
 */
function interpolar(texto, variaveis) {
  if (!texto) return "";
  return String(texto).replace(/\{\{\s*([\w.-]+)\s*\}\}/g, function (_, nome) {
    var v = variaveis && variaveis[nome];
    return v === null || v === undefined ? "" : String(v);
  });
}

/** Índice chave → bloco, para não varrer o array a cada salto. */
function indexar(blocos) {
  var mapa = new Map();
  for (var b of blocos || []) mapa.set(b.chave, b);
  return mapa;
}

function blocoInicial(blocos) {
  var lista = blocos || [];
  // `inicial` é a fonte da verdade; a ordem é só a rede de segurança
  // para um fluxo importado sem nenhum marcado.
  return lista.find(function (b) { return b.inicial; }) ||
         lista.slice().sort(function (a, b) { return a.ordem - b.ordem; })[0] ||
         null;
}

/**
 * Está dentro do horário de atendimento?
 *
 * A hora chega como Date em UTC e é convertida para o fuso do bot com
 * Intl — não com `getHours()`, que usaria o fuso do SERVIDOR. Um
 * servidor em UTC atenderia das 5h às 15h para um cliente que
 * configurou 8h às 18h, e ninguém entenderia por quê.
 */
function dentroDoHorario(bot, agora) {
  if (!bot.atendimento_ativo) return true;

  var partes;
  try {
    partes = new Intl.DateTimeFormat("en-US", {
      timeZone: bot.fuso || "America/Sao_Paulo",
      weekday: "short", hour: "2-digit", minute: "2-digit", hour12: false
    }).formatToParts(agora);
  } catch (e) {
    // Fuso inválido gravado no banco. Atender é o padrão seguro: um bot
    // que se cala por causa de um campo de configuração errado parece
    // um bot quebrado para o consumidor, e o dono não faz ideia do motivo.
    return true;
  }

  var pega = function (tipo) {
    var p = partes.find(function (x) { return x.type === tipo; });
    return p ? p.value : "";
  };

  var mapaDias = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
  var dia = mapaDias[pega("weekday")];
  var dias = bot.atendimento_dias || [];
  if (dias.indexOf(dia) === -1) return false;

  // "24" aparece à meia-noite em algumas plataformas com hour12:false.
  var hora = parseInt(pega("hour"), 10) % 24;
  var minuto = parseInt(pega("minute"), 10);
  var agoraMin = hora * 60 + minuto;

  var ini = paraMinutos(bot.atendimento_inicio);
  var fim = paraMinutos(bot.atendimento_fim);

  // Janela que atravessa a meia-noite (22:00 → 06:00). Sem este caso, um
  // atendimento noturno ficaria fechado a noite inteira, que é
  // exatamente quando ele deveria estar aberto.
  if (fim <= ini) return agoraMin >= ini || agoraMin < fim;
  return agoraMin >= ini && agoraMin < fim;
}

/**
 * A conversa ficou parada tempo demais?
 *
 * Exportada porque quem persiste (o serviço do WhatsApp) precisa da
 * MESMA regra para decidir outra coisa: encerrar a conversa antiga no
 * banco e abrir uma nova, em vez de reaproveitar a linha. Se cada lado
 * tivesse a sua cópia da regra, um dia o motor recomeçaria o fluxo e o
 * histórico continuaria costurando tudo numa conversa só — ou o
 * contrário, pior: conversa nova no banco, estado velho no motor.
 */
function expirou(bot, conversa, agora) {
  if (!conversa || !conversa.ultima_interacao_em) return false;
  if (!bot || !(bot.expirar_apos_minutos > 0)) return false;
  var minutos = (agora - new Date(conversa.ultima_interacao_em)) / 60000;
  return minutos > bot.expirar_apos_minutos;
}

function paraMinutos(hhmm) {
  var m = /^(\d{1,2}):(\d{2})/.exec(String(hhmm || "00:00"));
  return m ? parseInt(m[1], 10) * 60 + parseInt(m[2], 10) : 0;
}

/**
 * Procura um bloco cujo gatilho case com o que a pessoa escreveu.
 *
 * Casa por palavra inteira, não por "contém": o gatilho "oi" com
 * `includes` dispararia em "moinho", "coisa" e "foi". Palavra inteira é
 * o que separa um atalho útil de um bot que salta de assunto sozinho.
 *
 * Gatilho de várias palavras ("quanto custa") é comparado como trecho,
 * porque aí a intenção já é específica o bastante.
 */
function acharPorGatilho(blocos, entradaNormalizada) {
  if (!entradaNormalizada) return null;
  var palavras = entradaNormalizada.split(" ");

  for (var b of blocos || []) {
    for (var g of b.gatilhos || []) {
      var alvo = normalizar(g);
      if (!alvo) continue;
      if (alvo.indexOf(" ") !== -1) {
        if (entradaNormalizada.indexOf(alvo) !== -1) return b;
      } else if (palavras.indexOf(alvo) !== -1) {
        return b;
      }
    }
  }
  return null;
}

/**
 * Casa a resposta com uma opção do menu.
 *
 * Três formas, em ordem de confiança:
 *  1. O número da opção ("2") — é o que a maioria digita.
 *  2. O rótulo exato ("Ver preços") — é o que chega quando a pessoa
 *     toca no BOTÃO da mensagem interativa, e a Meta devolve o texto.
 *  3. O rótulo contido na frase ("quero ver preços por favor").
 *
 * A ordem importa: um menu cuja primeira opção se chama "2ª via de
 * boleto" faria o "2" digitado casar com o rótulo antes de casar com a
 * posição, e a pessoa escolheria a opção errada.
 */
function acharOpcao(bloco, entradaNormalizada, entradaCrua) {
  var opcoes = bloco.opcoes || [];
  if (!opcoes.length) return null;

  var numero = /^(\d{1,2})$/.exec(String(entradaCrua || "").trim());
  if (numero) {
    var i = parseInt(numero[1], 10) - 1;
    if (i >= 0 && i < opcoes.length) return opcoes[i];
  }

  for (var op of opcoes) {
    if (normalizar(op.rotulo) === entradaNormalizada) return op;
  }
  for (var op2 of opcoes) {
    var alvo = normalizar(op2.rotulo);
    if (alvo && entradaNormalizada.indexOf(alvo) !== -1) return op2;
  }
  return null;
}

/**
 * Monta as respostas de um bloco e segue a corrente enquanto o bloco for
 * do tipo que não espera resposta ('texto').
 *
 * O `visitados` não é paranoia: um fluxo com "início → aviso → início" é
 * fácil de montar sem querer no editor visual, e sem a trava o servidor
 * entraria em laço infinito na primeira mensagem — derrubando o processo
 * e, com ele, os bots de TODOS os clientes.
 */
function percorrer(mapa, bloco, estado, saida) {
  var visitados = new Set();

  while (bloco) {
    if (visitados.has(bloco.chave)) {
      saida.eventos.push("laco_detectado");
      break;
    }
    visitados.add(bloco.chave);

    var mensagem = interpolar(bloco.mensagem, estado.variaveis);

    if (bloco.tipo === "humano") {
      if (mensagem) saida.respostas.push({ texto: mensagem, opcoes: [] });
      estado.status = "humano";
      estado.bloco_chave = bloco.chave;
      saida.eventos.push("transbordo");
      return;
    }

    if (bloco.tipo === "encerrar") {
      if (mensagem) saida.respostas.push({ texto: mensagem, opcoes: [] });
      estado.status = "encerrada";
      estado.bloco_chave = bloco.chave;
      saida.eventos.push("encerrou");
      return;
    }

    if (bloco.tipo === "menu") {
      saida.respostas.push({ texto: mensagem, opcoes: bloco.opcoes || [] });
      estado.bloco_chave = bloco.chave;
      return;
    }

    if (bloco.tipo === "pergunta") {
      saida.respostas.push({ texto: mensagem, opcoes: [] });
      estado.bloco_chave = bloco.chave;
      return; // espera a resposta; quem grava a variável é processar()
    }

    // 'texto': fala e segue adiante sem esperar nada.
    if (mensagem) saida.respostas.push({ texto: mensagem, opcoes: [] });
    estado.bloco_chave = bloco.chave;

    var proximo = bloco.proxima_chave ? mapa.get(bloco.proxima_chave) : null;
    if (!proximo) return;
    bloco = proximo;
  }
}

/**
 * Ponto de entrada do motor.
 *
 * @param {object}  opcoes.bot      configuração do bot (linha da tabela)
 * @param {array}   opcoes.blocos   blocos do fluxo
 * @param {object}  opcoes.conversa { bloco_chave, variaveis, status, ultima_interacao_em }
 * @param {string}  opcoes.entrada  o que a pessoa escreveu
 * @param {Date}    opcoes.agora    momento da mensagem (injetado para testar)
 * @param {string}  opcoes.nomeContato nome do perfil, se a Meta enviou
 *
 * @returns {{respostas: array, conversa: object, eventos: array}}
 */
function processar(opcoes) {
  var bot = opcoes.bot;
  var blocos = opcoes.blocos || [];
  var entradaCrua = opcoes.entrada || "";
  var agora = opcoes.agora || new Date();
  var conversa = opcoes.conversa || {};

  var estado = {
    bloco_chave: conversa.bloco_chave || null,
    variaveis: Object.assign({}, conversa.variaveis || {}),
    status: conversa.status || "bot"
  };

  var saida = { respostas: [], conversa: estado, eventos: [] };

  // O nome do perfil fica disponível como {{nome}} sem ninguém precisar
  // perguntar. É a personalização que custa zero e muda o tom da
  // primeira mensagem.
  if (opcoes.nomeContato && !estado.variaveis.nome) {
    estado.variaveis.nome = opcoes.nomeContato;
  }

  // ── 1. Bot desligado ────────────────────────────────────
  // A mensagem que chegou continua sendo gravada pelo chamador; o bot
  // só não responde. É a diferença entre "desligado" e "surdo".
  if (!bot || !bot.ativo) {
    saida.eventos.push("bot_inativo");
    return saida;
  }

  // ── 2. Conversa nas mãos de um atendente ────────────────
  // Silêncio total, de propósito. Enquanto uma pessoa de verdade está
  // respondendo, qualquer intromissão do bot atrapalha — inclusive
  // palavra-chave, porque um cliente escrevendo "quanto custa" para o
  // atendente humano não está pedindo o menu de preços. A devolução ao
  // bot é feita no painel, por quem está atendendo.
  if (estado.status === "humano") {
    saida.eventos.push("em_atendimento_humano");
    return saida;
  }

  var mapa = indexar(blocos);
  var entrada = normalizar(entradaCrua);

  // ── 3. Conversa expirada ────────────────────────────────
  // Voltar do meio do fluxo depois de horas é pior que recomeçar: a
  // pessoa não lembra do menu e responde "3" para uma pergunta que não
  // está mais na tela dela.
  if (expirou(bot, conversa, agora)) {
    estado.bloco_chave = null;
    // As variáveis morrem junto: reaproveitar o "pedido" de ontem numa
    // conversa nova produz resposta confiante e errada.
    estado.variaveis = opcoes.nomeContato ? { nome: opcoes.nomeContato } : {};
    saida.eventos.push("expirou");
  }

  // ── 4. Fora do horário de atendimento ───────────────────
  if (!dentroDoHorario(bot, agora)) {
    saida.eventos.push("fora_horario");
    // Avisa UMA vez por conversa. Sem esta marca, alguém mandando cinco
    // mensagens seguidas às 2h da manhã receberia cinco vezes "estamos
    // fechados" — que lê como deboche.
    if (!estado.variaveis.__avisado_fora) {
      estado.variaveis.__avisado_fora = true;
      saida.respostas.push({ texto: interpolar(bot.mensagem_fora_horario, estado.variaveis), opcoes: [] });
    }
    estado.status = "bot";
    return saida;
  }
  // Voltou a funcionar: limpa a marca para o aviso valer de novo amanhã.
  if (estado.variaveis.__avisado_fora) delete estado.variaveis.__avisado_fora;

  estado.status = "bot";

  var atual = estado.bloco_chave ? mapa.get(estado.bloco_chave) : null;

  // ── 5. Conversa nova (ou recomeçada) ────────────────────
  if (!atual) {
    var inicio = blocoInicial(blocos);
    if (!inicio) {
      // Bot ligado, sem nenhum bloco. Acontece com quem criou a conta e
      // conectou o número antes de montar o fluxo. Responder as boas-
      // vindas é melhor que o silêncio: prova para o dono que a conexão
      // está de pé, e é a única pista que ele tem do que falta fazer.
      saida.respostas.push({ texto: interpolar(bot.mensagem_boas_vindas, estado.variaveis), opcoes: [] });
      saida.eventos.push("sem_fluxo");
      return saida;
    }

    if (bot.mensagem_boas_vindas) {
      saida.respostas.push({ texto: interpolar(bot.mensagem_boas_vindas, estado.variaveis), opcoes: [] });
    }
    saida.eventos.push("iniciou");

    // A primeira mensagem da pessoa quase nunca é uma escolha de menu
    // ("oi", "bom dia"). Mas se ela JÁ escreveu o que quer ("quero saber
    // o preço"), pular o menu e ir direto ao ponto é o certo — e é o que
    // separa um bot que ajuda de um que obriga a navegar.
    var atalho = acharPorGatilho(blocos, entrada);
    percorrer(mapa, atalho || inicio, estado, saida);
    return saida;
  }

  // ── 6. Bloco de pergunta: guarda a resposta e segue ─────
  if (atual.tipo === "pergunta") {
    var campo = atual.salvar_em || "resposta";
    // O texto CRU, não o normalizado: quem responde "João da Silva" tem
    // que virar "João da Silva" no painel, não "joao da silva".
    estado.variaveis[campo] = String(entradaCrua).trim().slice(0, 500);
    saida.eventos.push("guardou:" + campo);

    var depois = atual.proxima_chave ? mapa.get(atual.proxima_chave) : null;
    percorrer(mapa, depois || blocoInicial(blocos), estado, saida);
    return saida;
  }

  // ── 7. Escolha dentro do menu ───────────────────────────
  var escolhida = acharOpcao(atual, entrada, entradaCrua);
  if (escolhida) {
    saida.eventos.push("escolheu:" + escolhida.rotulo);
    var destino = escolhida.proxima ? mapa.get(escolhida.proxima) : null;
    if (destino) {
      percorrer(mapa, destino, estado, saida);
    } else {
      // Opção sem destino (ou apontando para um bloco apagado). Repetir
      // o menu é o comportamento honesto: a conversa não avança, mas
      // também não morre num silêncio que a pessoa não sabe interpretar.
      saida.eventos.push("opcao_sem_destino");
      percorrer(mapa, atual, estado, saida);
    }
    return saida;
  }

  // ── 8. Palavra-chave global ─────────────────────────────
  var porGatilho = acharPorGatilho(blocos, entrada);
  if (porGatilho) {
    saida.eventos.push("gatilho:" + porGatilho.chave);
    percorrer(mapa, porGatilho, estado, saida);
    return saida;
  }

  // ── 9. Não entendi ──────────────────────────────────────
  // O fallback repete o menu ATUAL junto. Só dizer "não entendi" deixa a
  // pessoa exatamente onde ela já estava perdida.
  saida.eventos.push("fallback");
  saida.respostas.push({ texto: interpolar(bot.mensagem_fallback, estado.variaveis), opcoes: [] });
  percorrer(mapa, atual, estado, saida);
  return saida;
}

module.exports = {
  processar,
  normalizar,
  interpolar,
  dentroDoHorario,
  expirou,
  blocoInicial,
  acharOpcao,
  acharPorGatilho
};
