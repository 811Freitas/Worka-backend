-- Incorporar à migration inicial ANTES da primeira aplicação; não executado automaticamente.
ALTER TABLE "Bot" ADD CONSTRAINT "bot_bounds" CHECK ("delayMinMs" >= 0 AND "delayMaxMs" >= "delayMinMs" AND "delayMaxMs" <= 60000 AND "maxOutputTokens" > 0 AND "temperature" BETWEEN 0 AND 2 AND "promptVersion" > 0);
ALTER TABLE "Plan" ADD CONSTRAINT "plan_bounds" CHECK ("monthlyPriceCents" >= 0 AND "connectionLimit" > 0 AND "botLimit" > 0 AND "monthlyMessageLimit" > 0 AND "logRetentionDays" > 0);
ALTER TABLE "Subscription" ADD CONSTRAINT "subscription_period" CHECK ("periodEnd" > "periodStart");
ALTER TABLE "UsageBucket" ADD CONSTRAINT "usage_bounds" CHECK ("periodEnd" > "periodStart" AND "inbound" >= 0 AND "outbound" >= 0 AND "aiInputTokens" >= 0 AND "aiOutputTokens" >= 0);
ALTER TABLE "Message" ADD CONSTRAINT "message_bounds" CHECK ("inputTokens" >= 0 AND "outputTokens" >= 0 AND "costUsd" >= 0);
ALTER TABLE "Log" ADD CONSTRAINT "log_duration" CHECK ("durationMs" IS NULL OR "durationMs" >= 0);
ALTER TABLE "BotTrigger" ADD CONSTRAINT "keyword_value" CHECK ("type" <> 'KEYWORD' OR length(trim("value")) > 0 AND "value" IS NOT NULL);
