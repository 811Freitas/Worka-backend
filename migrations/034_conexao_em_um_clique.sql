-- 034 — Conectar o WhatsApp em um clique
--
-- O caminho manual funciona e continua existindo, mas ele pede que o
-- dono de uma padaria crie um aplicativo no painel da Meta, ache o ID
-- do número no meio da tela, gere um token de usuário de sistema e
-- copie a chave secreta. São dez passos, em inglês na metade das telas.
-- Cada cliente parado nesse guia é um Plano Master que não acontece.
--
-- O Embedded Signup troca tudo isso por um botão: a pessoa faz login
-- do Facebook numa janelinha e o número dela é criado ali. Quem fala
-- com a Meta é a Workap, não ela.
--
-- O QUE MUDA NO BANCO é pouco, e de propósito: o bot continua sendo o
-- mesmo, com o mesmo motor e a mesma tela. O que precisa ser guardado
-- é só POR ONDE a conexão entrou, porque isso muda quem assina o
-- webhook.

alter table public.chatbots
  add column if not exists wa_origem text not null default 'manual';

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'chatbots_wa_origem_check') then
    alter table public.chatbots
      add constraint chatbots_wa_origem_check
      check (wa_origem in ('manual','embedded'));
  end if;
end $$;

comment on column public.chatbots.wa_origem is
  'manual = o dono colou as chaves da Meta dele. embedded = conectou pelo botão, e o aplicativo é o da Workap.';

-- POR QUE ISSO IMPORTA NA HORA DE CONFERIR A ASSINATURA:
--
-- No caminho manual, cada empresa tem o próprio aplicativo na Meta, e
-- portanto a própria chave secreta — é ela que valida o webhook, e
-- mora em wa_app_secret.
--
-- No Embedded Signup o aplicativo é UM só, o da Workap. Todos os
-- clientes chegam pelo mesmo webhook, assinados pela mesma chave, que
-- é variável de ambiente e não coluna. Guardar uma cópia dela em cada
-- linha seria espalhar o mesmo segredo por centenas de registros para
-- ter que trocar todos juntos no dia em que ela mudar.
--
-- Daí wa_app_secret ficar NULO nas conexões por botão, e o servidor
-- cair para META_APP_SECRET quando encontra nulo. A coluna abaixo é o
-- que torna essa escolha legível, em vez de deduzida de um campo vazio.
