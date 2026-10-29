# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The occ command.

    occ migrate                    apply every pending migration to the configured database
    occ status                     where the database stands against the migration files
    occ fresh-compare              build a scratch database from the migrations and compare it
    occ init-pepper                create the API key pepper file if it is missing (0600)
    occ init-secret-key            create the secret-sealing key file (OCC_SECRET_KEY_FILE) if it is
                                   missing (32 random bytes, 0600); without it, secrets cannot be set or read
    occ bootstrap --email E --firstname F --lastname L --team T --key-file PATH
                                   first sysadmin, first team and an API key, on an empty database
    occ mint-key --user N --team N --name NAME --key-file PATH [--read-only] [--site-scope]
    occ audit-verify [--checkpoint]
                                   walk the whole audit chain; --checkpoint records the result
                                   in occ.audit_checkpoints (the nightly job's work), with the timestamp
                                   authority's RFC 3161 token over the head hash when ts_url is set;
                                   exit 1 on a break
    occ sweep-files [--dry-run] [--grace-hours N]
                                   remove stored blobs no file_blobs row names, older than the grace
                                   period (the weekly worker job does the same)
    occ worker [--once] [--seconds N]
                                   the background worker: schedules and jobs, one at a time;
                                   stops cleanly on SIGTERM; --once runs what is due and stops

--database NAME points any command at another database on the same socket (a scratch one in
tests). A key is written to --key-file with mode 0600 and never printed.
"""
import argparse
import json
import os
import sys

from . import db, settings as settings_mod
from .auth import apikeys
from .db import migrate, scratch


def _cfg(args):
    cfg = settings_mod.load()
    if getattr(args, "database", None):
        cfg.database_url = "postgresql:///%s" % args.database
    return cfg


def _write_key(path, key):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(key + "\n")


SITE_DEFAULTS = {"read_only": "0", "min_delta_revisions": "100", "max_revisions": "10", "min_days_revisions": "23",
                 "allow_purge": "0"}


def bootstrap(cfg, email, firstname, lastname, team_name, key_file):
    pepper = apikeys.read_pepper(cfg.api_key_pepper_file)
    pool = db.Pool(cfg.db_params(), size=1)
    try:
        with pool.tx() as tx:
            if tx.val("SELECT count(*) FROM occ.users"):
                raise SystemExit("bootstrap runs only on an empty OCC database (users exist already)")
            uid = tx.val("INSERT INTO occ.users (email, firstname, lastname, is_sysadmin, validated, write_exempt) "
                         "VALUES (:e, :f, :l, true, true, true) RETURNING id", e=email, f=firstname, l=lastname)
            tid = tx.val("INSERT INTO occ.teams (name) VALUES (:n) RETURNING id", n=team_name)
            tx.run("INSERT INTO occ.memberships (user_id, team_id, is_admin, is_owner) VALUES (:u, :t, true, true)",
                   u=uid, t=tid)
            for k, v in SITE_DEFAULTS.items():
                tx.run("INSERT INTO occ.site_config (name, value) VALUES (:n, :v) ON CONFLICT (name) DO NOTHING", n=k, v=v)
            kid, key = apikeys.create(tx, pepper, uid, tid, "bootstrap", can_write=True, site_scope=False)
            tx.val("SELECT occ.audit_append(CAST(:p AS jsonb))", p=db.jsonb({
                "actor_kind": "system", "category": "user.create", "team_id": tid, "target": "bootstrap",
                "new_value": email, "detail": {"userid": uid, "team": tid, "api_key_id": kid}}))
        _write_key(key_file, key)
        return {"user": uid, "team": tid, "api_key_id": kid, "key_file": key_file}
    finally:
        pool.close()


def mint_key(cfg, user, team, name, key_file, read_only=False, site_scope=False):
    pepper = apikeys.read_pepper(cfg.api_key_pepper_file)
    pool = db.Pool(cfg.db_params(), size=1)
    try:
        with pool.tx() as tx:
            if not tx.val("SELECT 1 FROM occ.memberships WHERE user_id = :u AND team_id = :t", u=user, t=team):
                raise SystemExit("that user is not a member of that team")
            kid, key = apikeys.create(tx, pepper, user, team, name, can_write=not read_only, site_scope=site_scope)
            tx.val("SELECT occ.audit_append(CAST(:p AS jsonb))", p=db.jsonb({
                "actor_kind": "system", "category": "apikey.create", "team_id": team, "target": "api_key",
                "new_value": name, "detail": {"userid": user, "api_key_id": kid}}))
        _write_key(key_file, key)
        return {"api_key_id": kid, "key_file": key_file}
    finally:
        pool.close()


def audit_verify(cfg, write_checkpoint=False):
    from .audit import verify as V
    from .signing import service as SG
    pool = db.Pool(cfg.db_params(), size=1)
    try:
        with pool.tx(readonly=True) as tx:
            res = V.verify(tx)
            auth = SG.authority_or_none(tx, cfg) if write_checkpoint else None
        if write_checkpoint:
            h = V.head_hash(res)
            token, why = SG.checkpoint_token(auth, h) if h is not None else (None, None)
            with pool.tx() as tx:
                res["checkpoint_id"] = V.checkpoint(tx, res, note_suffix=why, tsa_token=token)
            res["timestamped"] = bool(token)
        print(json.dumps(res))
        return 0 if res["ok"] else 1
    finally:
        pool.close()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="occ")
    ap.add_argument("--database")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate")
    sub.add_parser("status")
    sub.add_parser("fresh-compare")
    sub.add_parser("init-pepper")
    sub.add_parser("init-secret-key")
    sw = sub.add_parser("sweep-files")
    sw.add_argument("--dry-run", action="store_true")
    sw.add_argument("--grace-hours", type=float, default=24.0)
    b = sub.add_parser("bootstrap")
    for a in ("--email", "--firstname", "--lastname", "--team", "--key-file"):
        b.add_argument(a, required=True)
    m = sub.add_parser("mint-key")
    m.add_argument("--user", type=int, required=True)
    m.add_argument("--team", type=int, required=True)
    m.add_argument("--name", required=True)
    m.add_argument("--key-file", required=True)
    m.add_argument("--read-only", action="store_true")
    m.add_argument("--site-scope", action="store_true")
    v = sub.add_parser("audit-verify")
    v.add_argument("--checkpoint", action="store_true")
    w = sub.add_parser("worker")
    w.add_argument("--once", action="store_true")
    w.add_argument("--seconds", type=float)
    args = ap.parse_args(argv)
    cfg = _cfg(args)
    params = cfg.db_params()

    if args.cmd == "migrate":
        done = migrate.migrate(params)
        print("nothing to apply" if not done else "applied %d migration(s)" % len(done))
    elif args.cmd == "status":
        print(json.dumps(migrate.status(params), indent=1))
    elif args.cmd == "fresh-compare":
        same, rep = scratch.compare_fresh(params, params["database"])
        print(json.dumps({"same": same, **{k: v for k, v in rep.items() if k != "diff"}}, indent=1, default=str))
        if not same:
            print("\n".join(rep["diff"]))
        return 0 if same else 1
    elif args.cmd == "init-pepper":
        made = apikeys.make_pepper_file(cfg.api_key_pepper_file)
        print("created" if made else "exists already")
    elif args.cmd == "init-secret-key":
        from .people import config as C
        made = C.make_secret_key(cfg.secret_key_file)
        print("created" if made else "exists already")
    elif args.cmd == "sweep-files":
        from .files import sweep
        pool = db.Pool(params, size=1)
        try:
            print(json.dumps(sweep.sweep(pool, cfg, grace_hours=args.grace_hours, dry_run=args.dry_run)))
        finally:
            pool.close()
    elif args.cmd == "bootstrap":
        print(json.dumps(bootstrap(cfg, args.email, args.firstname, args.lastname, args.team, args.key_file)))
    elif args.cmd == "audit-verify":
        return audit_verify(cfg, args.checkpoint)
    elif args.cmd == "worker":
        from .worker import runner
        return runner.run(cfg, once=args.once, seconds=args.seconds)
    elif args.cmd == "mint-key":
        print(json.dumps(mint_key(cfg, args.user, args.team, args.name, args.key_file, args.read_only,
                                  args.site_scope)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
