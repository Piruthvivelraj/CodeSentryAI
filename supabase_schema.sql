-- CREATE TABLE FOR SCAN STATES AND RESULTS
CREATE TABLE IF NOT EXISTS public.scan_states (
    scan_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    message TEXT,
    progress_percent INTEGER DEFAULT 0,
    repo_size TEXT,
    estimated_time TEXT,
    result JSONB, -- Stores the full ScanResult object as JSON
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ADD MISSING COLUMNS TO SCAN_STATES (IDEMPOTENT)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='scan_states' AND column_name='user_id') THEN
        ALTER TABLE public.scan_states ADD COLUMN user_id TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='scan_states' AND column_name='health_score') THEN
        ALTER TABLE public.scan_states ADD COLUMN health_score INTEGER DEFAULT 0;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='scan_states' AND column_name='repository_name') THEN
        ALTER TABLE public.scan_states ADD COLUMN repository_name TEXT;
    END IF;
END $$;

-- ENABLE ROW LEVEL SECURITY (RLS)
ALTER TABLE public.scan_states ENABLE ROW LEVEL SECURITY;

-- CREATE POLICIES (IDEMPOTENT)
DROP POLICY IF EXISTS "Allow authenticated read" ON public.scan_states;
CREATE POLICY "Allow authenticated read" ON public.scan_states
    FOR SELECT TO authenticated USING (true);

DROP POLICY IF EXISTS "Allow authenticated insert" ON public.scan_states;
CREATE POLICY "Allow authenticated insert" ON public.scan_states
    FOR INSERT TO authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "Allow authenticated update" ON public.scan_states;
CREATE POLICY "Allow authenticated update" ON public.scan_states
    FOR UPDATE TO authenticated USING (true);

-- Function to handle timestamp updates
CREATE OR REPLACE FUNCTION handle_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS set_updated_at ON public.scan_states;
CREATE TRIGGER set_updated_at
BEFORE UPDATE ON public.scan_states
FOR EACH ROW
EXECUTE FUNCTION handle_updated_at();

-- BILLING & SUBSCRIPTION SCHEMA (IDEMPOTENT)
CREATE TABLE IF NOT EXISTS public.users (
    id UUID PRIMARY KEY, -- This should correspond to auth.users.id
    email TEXT,
    display_name TEXT
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='users' AND column_name='plan_type') THEN
        ALTER TABLE public.users ADD COLUMN plan_type VARCHAR(20) DEFAULT 'FREE';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='users' AND column_name='scans_this_month') THEN
        ALTER TABLE public.users ADD COLUMN scans_this_month INT DEFAULT 0;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='users' AND column_name='plan_reset_date') THEN
        ALTER TABLE public.users ADD COLUMN plan_reset_date DATE;
    END IF;
END $$;

-- TEAMS SCHEMA
CREATE TABLE IF NOT EXISTS public.teams (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  owner_id UUID REFERENCES public.users(id)
);

CREATE TABLE IF NOT EXISTS public.team_members (
  team_id UUID REFERENCES public.teams(id) ON DELETE CASCADE,
  user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
  role VARCHAR(20) DEFAULT 'member',
  PRIMARY KEY (team_id, user_id)
);

-- API KEYS SCHEMA
CREATE TABLE IF NOT EXISTS public.api_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
  key_hash VARCHAR(255) NOT NULL,
  name VARCHAR(100),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  last_used_at TIMESTAMP WITH TIME ZONE
);
