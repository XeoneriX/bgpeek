-- Optional region field for device grouping in UI.
-- Admin sets this to any value they want (e.g. "RU", "DE", "US-East").
ALTER TABLE devices ADD COLUMN IF NOT EXISTS region TEXT;
