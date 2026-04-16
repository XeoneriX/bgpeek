-- Add optional color token to community labels for badge rendering.
-- Allowed tokens are a whitelist of Tailwind-friendly color names;
-- NULL means the community is rendered as plain text (no badge).

ALTER TABLE community_labels
    ADD COLUMN IF NOT EXISTS color TEXT DEFAULT NULL
    CHECK (color IS NULL OR color IN (
        'amber', 'emerald', 'rose', 'sky', 'violet', 'slate', 'red', 'orange', 'cyan', 'pink'
    ));
