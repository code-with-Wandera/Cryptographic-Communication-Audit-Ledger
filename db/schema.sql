CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 1. Government Staff Accounts
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(120) NOT NULL,
    department VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    account_status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE' -- 'ACTIVE' or 'COMPROMISED'
);

-- 2. Communication Messages with SHA-256 Hash Chain
CREATE TABLE IF NOT EXISTS messages (
    id BIGSERIAL PRIMARY KEY,
    sender_id INT NOT NULL REFERENCES users(id),
    channel_name VARCHAR(100) NOT NULL DEFAULT 'General-Ops',
    message_body TEXT NOT NULL,
    file_sha256 CHAR(64), -- Optional SHA-256 digest if a file was attached
    prev_hash CHAR(64) NOT NULL,
    current_hash CHAR(64) NOT NULL,
    auth_context VARCHAR(100) NOT NULL DEFAULT 'NORMAL_SESSION',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 3. Shared Files Registry
CREATE TABLE IF NOT EXISTS shared_files (
    id SERIAL PRIMARY KEY,
    message_id BIGINT REFERENCES messages(id) ON DELETE SET NULL,
    uploaded_by INT NOT NULL REFERENCES users(id),
    filename VARCHAR(255) NOT NULL,
    stored_path VARCHAR(500) NOT NULL,
    file_sha256 CHAR(64) NOT NULL,
    uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 4. Automated Verification & Tamper Alerts Log
CREATE TABLE IF NOT EXISTS tamper_alerts (
    id SERIAL PRIMARY KEY,
    alert_type VARCHAR(60) NOT NULL, -- 'HASH_MISMATCH', 'CHAIN_BROKEN', 'ROW_DELETED', 'FILE_TAMPERED', 'COMPROMISED_SENDER'
    target_table VARCHAR(50) NOT NULL,
    target_id VARCHAR(100) NOT NULL,
    details TEXT NOT NULL,
    detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- PL/pgSQL TRIGGER: Compute & Link SHA-256 Hash Chain on INSERT
-- ============================================================================
CREATE OR REPLACE FUNCTION compute_message_hash_chain()
RETURNS TRIGGER AS $$
DECLARE
    last_hash CHAR(64);
    payload TEXT;
BEGIN
    -- 1. Lock the latest row to get the previous message's SHA-256 hash
    SELECT current_hash INTO last_hash
    FROM messages
    ORDER BY id DESC
    LIMIT 1
    FOR UPDATE;

    -- 2. Use the genesis hash if this is the very first message
    IF last_hash IS NULL THEN
        last_hash := encode(digest('GENESIS_GOV_COMM_LEDGER_V1', 'sha256'), 'hex');
    END IF;

    -- 3. Ensure created_at is populated before formatting it into the payload
    IF NEW.created_at IS NULL THEN
        NEW.created_at := CURRENT_TIMESTAMP;
    END IF;

    -- 4. Link to the previous hash
    NEW.prev_hash := last_hash;

    -- 5. Build the canonical payload string (THIS IS WHERE YOUR CODE GOES)
    payload := COALESCE(NEW.sender_id::TEXT, '') || '|' ||
               COALESCE(NEW.channel_name, '') || '|' ||
               COALESCE(NEW.message_body, '') || '|' ||
               COALESCE(NEW.file_sha256, 'NO_FILE') || '|' ||
               TRIM(NEW.prev_hash) || '|' ||
               to_char(NEW.created_at, 'YYYY-MM-DD HH24:MI:SS.US');

    -- 6. Compute the SHA-256 hash of the payload and store it in NEW.current_hash
    NEW.current_hash := encode(digest(payload, 'sha256'), 'hex');

    -- 7. Flag if sender account is marked COMPROMISED
    IF EXISTS (SELECT 1 FROM users WHERE id = NEW.sender_id AND account_status = 'COMPROMISED') THEN
        INSERT INTO tamper_alerts (alert_type, target_table, target_id, details)
        VALUES (
            'COMPROMISED_SENDER',
            'messages',
            COALESCE(NEW.id::TEXT, 'NEW'),
            'Message logged under COMPROMISED user_id=' || NEW.sender_id || ' (auth=' || NEW.auth_context || ')'
        );
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_messages_hash_chain ON messages;
CREATE TRIGGER trg_messages_hash_chain
BEFORE INSERT ON messages
FOR EACH ROW
EXECUTE FUNCTION compute_message_hash_chain();

-- ============================================================================
-- OPTIONAL: Prevent Direct SQL UPDATE / DELETE on Messages (For Attack Demo)
-- Note: For Objective 2 (demonstrating unprotected weaknesses vs protected ledger),
-- you can run attacks BEFORE enabling this trigger, then turn this on to show
-- database-level immutability enforcement.
-- ============================================================================
CREATE OR REPLACE FUNCTION block_message_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Integrity Violation: Direct % on messages ledger is prohibited.', TG_OP;
END;
$$ LANGUAGE plpgsql;

-- Seed initial government staff accounts
INSERT INTO users (full_name, department, email, account_status) VALUES
('Amina Okafor', 'Procurement', 'amina.okafor@gov.example', 'ACTIVE'),
('David Mensah', 'Legal & Compliance', 'david.mensah@gov.example', 'ACTIVE'),
('Grace Kiprop', 'Records & ICT', 'grace.kiprop@gov.example', 'ACTIVE')
ON CONFLICT (email) DO NOTHING;

