-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (c) 2026 LabLynx, Inc.
--
-- 0002: the audit chain hashes the STORED row in a canonical, time-zone-independent form.
--
-- Migration 0001 hashed jsonb_build_object('at', <timestamptz>, 'payload', <input>)::text. The text
-- of a timestamptz depends on the session's TimeZone, and the input payload is not what is stored,
-- so a verifier could not recompute a row's hash from the row. From this migration:
--
--   hash = sha256(prev_hash || UTF-8 bytes of occ.audit_canonical(row))
--
-- occ.audit_canonical is the jsonb text of an object holding every stored column except prev_hash
-- and hash, with both times written as UTC 'YYYY-MM-DDTHH:MM:SS.ffffffZ' and "v": 1 naming this form.
-- jsonb text output is fixed by the stored value alone (keys ordered by length, then bytes; ', '
-- and ': ' separators), so any session in any time zone, and the independent Python verifier in
-- occ/audit/verify.py, produce the same bytes.
--
-- Chain order is id order: the transaction-scoped advisory lock is taken BEFORE the row's id is
-- drawn, so ids and chain positions agree even under concurrent writers. A BEFORE INSERT trigger
-- does the chaining, so a row inserted by any route is chained the same way.

CREATE FUNCTION occ.audit_canonical(r occ.audit_events) RETURNS text LANGUAGE sql STABLE AS $$
    SELECT jsonb_build_object(
        'v',             1,
        'id',            r.id,
        'at',            to_char(r.at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'actor_kind',    r.actor_kind,
        'actor_user_id', r.actor_user_id,
        'api_key_id',    r.api_key_id,
        'team_id',       r.team_id,
        'category',      r.category,
        'kind_id',       r.kind_id,
        'record_id',     r.record_id,
        'rid',           r.rid,
        'target',        r.target,
        'old_value',     r.old_value,
        'new_value',     r.new_value,
        'detail',        r.detail,
        'request_id',    r.request_id::text,
        'origin',        r.origin,
        'orig_at',       to_char(r.orig_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
    )::text
$$;

CREATE FUNCTION occ.audit_chain() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    v_prev bytea;
    v_last bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(7031001);
    SELECT id, hash INTO v_last, v_prev FROM occ.audit_events ORDER BY id DESC LIMIT 1;
    IF v_last IS NOT NULL AND NEW.id <= v_last THEN
        -- the id was drawn before this writer held the lock and another row overtook it
        NEW.id := nextval(pg_get_serial_sequence('occ.audit_events', 'id'));
    END IF;
    NEW.at := clock_timestamp();
    NEW.prev_hash := coalesce(v_prev, '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea);
    NEW.hash := sha256(NEW.prev_hash || convert_to(occ.audit_canonical(NEW), 'UTF8'));
    RETURN NEW;
END $$;

CREATE TRIGGER audit_events_chain BEFORE INSERT ON occ.audit_events
    FOR EACH ROW EXECUTE FUNCTION occ.audit_chain();

-- The writer keeps its signature; the trigger now does the hashing.
CREATE OR REPLACE FUNCTION occ.audit_append(p jsonb) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE
    v_id bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(7031001);
    INSERT INTO occ.audit_events (actor_kind, actor_user_id, api_key_id, team_id, category, kind_id,
            record_id, rid, target, old_value, new_value, detail, request_id, origin, orig_at, prev_hash, hash)
    VALUES (p->>'actor_kind', (p->>'actor_user_id')::int, (p->>'api_key_id')::int, (p->>'team_id')::int,
            p->>'category', (p->>'kind_id')::smallint, (p->>'record_id')::int, (p->>'rid')::bigint,
            p->>'target', p->>'old_value', p->>'new_value', p->'detail', (p->>'request_id')::uuid,
            coalesce(p->>'origin', 'occ'), (p->>'orig_at')::timestamptz,
            '\x'::bytea, '\x'::bytea)                    -- placeholders; audit_events_chain sets both
    RETURNING id INTO v_id;
    RETURN v_id;
END $$;
