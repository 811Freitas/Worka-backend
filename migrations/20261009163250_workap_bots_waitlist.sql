CREATE TABLE public.worka_bots_leads (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 name text NOT NULL CHECK (length(name) BETWEEN 2 AND 100),
 email text NOT NULL UNIQUE CHECK (length(email) <= 254 AND email = lower(email)),
 plan text NOT NULL CHECK (plan IN ('Starter','Pro','Enterprise')),
 consent_version text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.worka_bots_leads ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.worka_bots_leads FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.worka_bots_leads TO service_role;
COMMENT ON TABLE public.worka_bots_leads IS 'Workap Bots waitlist. Backend-only access; no public SELECT or direct INSERT.';
