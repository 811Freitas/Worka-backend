-- O aviso só é considerado repetido depois que o acesso foi processado.
-- Uma tentativa interrompida pode ser enviada de novo sem ficar presa
-- pelo identificador já gravado em eventos_pagamento.
alter table public.eventos_pagamento
  add column if not exists processado_em timestamptz;
