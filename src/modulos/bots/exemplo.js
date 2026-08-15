"use strict";

/**
 * Fluxo de exemplo criado junto com a conta.
 *
 * Uma conta nova NÃO nasce vazia de propósito. Um editor de fluxo em
 * branco é onde a maioria das pessoas desiste: não é óbvio o que é um
 * "bloco", nem que o menu precisa apontar para algum lugar. Com este
 * fluxo, a pessoa entra, aperta "Testar bot" e vê uma conversa
 * funcionando em dez segundos — depois troca os textos pelos dela, que é
 * uma tarefa que qualquer um sabe fazer.
 *
 * Todos os blocos são editáveis e apagáveis. Isto é ponto de partida,
 * não estrutura fixa.
 */

var BLOCOS_EXEMPLO = [
  {
    chave: "menu",
    titulo: "Menu principal",
    tipo: "menu",
    mensagem: "Escolha uma opção para eu te ajudar:",
    gatilhos: ["menu", "inicio", "voltar", "oi", "ola", "bom dia", "boa tarde", "boa noite"],
    inicial: true,
    ordem: 0,
    opcoes: [
      { rotulo: "Ver produtos", proxima: "produtos" },
      { rotulo: "Horário e endereço", proxima: "horario" },
      { rotulo: "Falar com atendente", proxima: "atendente" }
    ]
  },
  {
    chave: "produtos",
    titulo: "Produtos e preços",
    tipo: "menu",
    // As palavras-chave cobrem as formas reais de perguntar preço. É o
    // atalho de quem não quer navegar menu — digita "quanto custa" de
    // qualquer ponto da conversa e chega aqui.
    gatilhos: ["preco", "precos", "valor", "quanto custa", "produto", "produtos", "catalogo"],
    mensagem: "Aqui está o que oferecemos:\n\n• Plano Básico — R$ 99/mês\n• Plano Completo — R$ 199/mês\n\n(Edite este texto no painel com os seus produtos de verdade.)",
    ordem: 1,
    opcoes: [
      { rotulo: "Quero contratar", proxima: "contratar" },
      { rotulo: "Voltar ao menu", proxima: "menu" }
    ]
  },
  {
    chave: "horario",
    titulo: "Horário e endereço",
    tipo: "menu",
    gatilhos: ["horario", "endereco", "onde fica", "aberto", "funcionamento", "local"],
    mensagem: "Funcionamos de segunda a sexta, das 8h às 18h.\n📍 Rua Exemplo, 123 — Centro\n\n(Troque por seu endereço real no painel.)",
    ordem: 2,
    opcoes: [{ rotulo: "Voltar ao menu", proxima: "menu" }]
  },
  {
    chave: "contratar",
    titulo: "Coletar o nome",
    // 'pergunta' guarda o que a pessoa responder na variável `nome`, e a
    // partir daí {{nome}} funciona em qualquer mensagem seguinte.
    tipo: "pergunta",
    mensagem: "Ótimo! Qual é o seu nome?",
    salvar_em: "nome",
    proxima_chave: "confirmar",
    ordem: 3,
    opcoes: []
  },
  {
    chave: "confirmar",
    titulo: "Confirmação",
    tipo: "menu",
    mensagem: "Prazer, {{nome}}! 🙂 Anotei seu interesse. Quer falar com um atendente agora?",
    ordem: 4,
    opcoes: [
      { rotulo: "Sim, quero falar", proxima: "atendente" },
      { rotulo: "Não, obrigado", proxima: "despedida" }
    ]
  },
  {
    chave: "atendente",
    titulo: "Chamar atendente",
    // 'humano' silencia o bot e acende a conversa no painel. É o
    // transbordo: a partir daqui quem responde é gente.
    tipo: "humano",
    gatilhos: ["atendente", "humano", "pessoa", "suporte", "ajuda"],
    mensagem: "Certo! Já chamei um atendente. É só aguardar aqui neste chat. 🙂",
    ordem: 5,
    opcoes: []
  },
  {
    chave: "despedida",
    titulo: "Despedida",
    tipo: "encerrar",
    gatilhos: ["tchau", "obrigado", "obrigada", "valeu"],
    mensagem: "Obrigado pelo contato! Se precisar, é só mandar uma mensagem que eu volto a te atender. 👋",
    ordem: 6,
    opcoes: []
  }
];

/**
 * Grava o fluxo de exemplo. Recebe o cliente da transação para que a
 * criação da conta seja tudo-ou-nada: uma conta com bot mas sem blocos
 * abriria um editor quebrado no primeiro login.
 */
async function criarExemplo(cliente, contaId, botId) {
  for (var b of BLOCOS_EXEMPLO) {
    await cliente.query(
      `insert into blocos
         (conta_id, bot_id, chave, titulo, tipo, mensagem, gatilhos, inicial, opcoes, proxima_chave, salvar_em, ordem)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [contaId, botId, b.chave, b.titulo, b.tipo, b.mensagem,
       b.gatilhos || [], !!b.inicial, JSON.stringify(b.opcoes || []),
       b.proxima_chave || null, b.salvar_em || null, b.ordem]
    );
  }
}

module.exports = { BLOCOS_EXEMPLO, criarExemplo };
