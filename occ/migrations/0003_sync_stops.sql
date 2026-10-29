-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (c) 2026 LabLynx, Inc.
--
-- 0003: the sync's delay target counts only changes made while the sync was running.
--
-- When occ-sync is stopped (a restart, an update, a reboot, or the sync switched off), people keep
-- working on the source. The first cycle after the stop carries those changes at once, but each is
-- "late" by however long the sync was stopped, which says nothing about how fast the sync is. So:
--
--   * occ.sync_lag.catch_up marks the changes the first cycle after a stop carried; the delay
--     target (95% within lag_target_s, none over twice that) is measured over the others;
--   * occ.sync_stops records each stop on its own: when the sync was last active, when it resumed,
--     when the catch-up finished, and how many changes it carried;
--   * occ.sync_settings.catch_up_target_s is the catch-up's own limit, five minutes by default.
ALTER TABLE occ.sync_lag ADD COLUMN catch_up boolean NOT NULL DEFAULT false;
ALTER TABLE occ.sync_settings ADD COLUMN catch_up_target_s integer NOT NULL DEFAULT 300;

CREATE TABLE occ.sync_stops (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id          bigint      REFERENCES occ.sync_runs(id) ON DELETE SET NULL,
    stopped_at      timestamptz NOT NULL,                   -- the sync was last active
    resumed_at      timestamptz NOT NULL,                   -- the first cycle after the stop began
    caught_up_at    timestamptz NOT NULL,                   -- that cycle finished
    changes         integer     NOT NULL DEFAULT 0,         -- changes it carried (marked catch_up)
    catch_up_s      numeric(10,2) NOT NULL                  -- caught_up_at - resumed_at
);
CREATE INDEX sync_stops_resumed_ix ON occ.sync_stops (resumed_at);
