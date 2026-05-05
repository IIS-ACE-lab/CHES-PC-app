#!/usr/bin/env python3
import argparse
import csv
import secrets
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Optional


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS reviewers (
    token TEXT PRIMARY KEY,
    invite_email TEXT NOT NULL UNIQUE,
    review_email TEXT,
    given_names TEXT,
    family_name TEXT,
    affiliation TEXT,
    ror_id TEXT,
    country TEXT,
    status TEXT,
    created_at TEXT,
    updated_at TEXT,
    expertise TEXT,
    cryptodb_mode TEXT,
    cryptodb_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_reviewers_invite_email ON reviewers(invite_email);
CREATE INDEX IF NOT EXISTS idx_reviewers_status ON reviewers(status);
"""


@dataclass
class Invitee:
    invite_email: str
    given_names: str
    family_name: str


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_email(s: str) -> str:
    return s.strip().lower()


def generate_token() -> str:
    # 32 hex chars, matches PHP regex /^[a-f0-9]{32}$/
    return secrets.token_hex(16)

def load_template(path: Path) -> str:
    with path.open("r", encoding="utf-8") as f:
        return f.read()


def open_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = FULL;")
    conn.executescript(SCHEMA_SQL)
    return conn


def load_csv(csv_path: Path) -> list[Invitee]:
    rows: list[Invitee] = []
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)

        required = {"invite_email"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV missing required columns: {sorted(missing)}")

        for i, row in enumerate(reader, start=2):
            email = normalize_email(row.get("invite_email", ""))
            if not email:
                print(f"[WARN] Line {i}: missing invite_email, skipped", file=sys.stderr)
                continue

            rows.append(
                Invitee(
                    invite_email=email,
                    given_names=row.get("given_names", "").strip(),
                    family_name=row.get("family_name", "").strip(),
                )
            )
    return rows


def get_existing_by_email(conn: sqlite3.Connection, invite_email: str) -> Optional[sqlite3.Row]:
    cur = conn.execute(
        "SELECT * FROM reviewers WHERE invite_email = ?",
        (invite_email,),
    )
    return cur.fetchone()


def upsert_invitee(
    conn: sqlite3.Connection,
    invitee: Invitee,
    regenerate_token: bool = False,
    skip_if_exists: bool = False,
) -> tuple[sqlite3.Row, bool]:
    """
    Returns (row, inserted_or_updated_now)
    """
    existing = get_existing_by_email(conn, invitee.invite_email)
    ts = now_iso()

    if existing is not None:
        if skip_if_exists:
            return existing, False

        token = generate_token() if regenerate_token else str(existing["token"])
        review_email = existing["review_email"] or invitee.invite_email
        status = existing["status"] or "invited"

        conn.execute(
            """
            UPDATE reviewers
            SET token = ?,
                given_names = CASE WHEN ? <> '' THEN ? ELSE given_names END,
                family_name = CASE WHEN ? <> '' THEN ? ELSE family_name END,
                review_email = CASE WHEN review_email IS NULL OR review_email = '' THEN ? ELSE review_email END,
                updated_at = ?
            WHERE invite_email = ?
            """,
            (
                token,
                invitee.given_names, invitee.given_names,
                invitee.family_name, invitee.family_name,
                review_email,
                ts,
                invitee.invite_email,
            ),
        )
        conn.commit()
        row = get_existing_by_email(conn, invitee.invite_email)
        assert row is not None
        return row, True

    token = generate_token()
    conn.execute(
        """
        INSERT INTO reviewers (
            token, invite_email, review_email,
            given_names, family_name,
            affiliation, ror_id, country,
            status, created_at, updated_at,
            expertise,
            cryptodb_mode, cryptodb_id
        ) VALUES (?, ?, ?, ?, ?, '', '', '', ?, ?, ?, '', '', '')
        """,
        (
            token,
            invitee.invite_email,
            invitee.invite_email,
            invitee.given_names,
            invitee.family_name,
            "invited",
            ts,
            ts,
        ),
    )
    conn.commit()
    row = get_existing_by_email(conn, invitee.invite_email)
    assert row is not None
    return row, True


def build_invitation_email(
    *,
    to_email: str,
    from_email: str,
    reply_to: Optional[str],
    subject: str,
    website_url: str,
    token: str,
    given_names: str,
    family_name: str,
    template: str,
) -> EmailMessage:
    full_name = " ".join(x for x in [given_names.strip(), family_name.strip()] if x)
    link = f"{website_url}?t={token}"

    body = template.replace("{name}", full_name).replace("{link}", link)

    msg = EmailMessage()
    msg["To"] = to_email
    msg["From"] = from_email
    msg["Subject"] = subject
    if reply_to:
        msg["Reply-To"] = reply_to
    msg.set_content(body)
    return msg


def send_via_sendmail(msg: EmailMessage, sendmail_path: str = "/usr/sbin/sendmail") -> None:
    proc = subprocess.run(
        [sendmail_path, "-t", "-oi"],
        input=msg.as_bytes(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"sendmail failed with exit code {proc.returncode}: {stderr}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Load reviewer invitees into SQLite and send invitation emails."
    )
    ap.add_argument("csv_file", help="Input CSV with at least invite_email, optionally given_names,family_name")
    ap.add_argument("db_file", help="SQLite database path, e.g. /home/you/ches-data/reviewers.sqlite")
    ap.add_argument(
        "--website-url",
        required=True,
        help="Base invitation URL without token, e.g. https://xyz.iacr.org/PC/index.php",
    )
    ap.add_argument("--from-email", required=True, help="From: address for invitation email")
    ap.add_argument("--reply-to", default="", help="Optional Reply-To address")
    ap.add_argument(
        "--subject",
        default="Reviewer invitation",
        help="Invitation to the Program Committee of CHES 2027",
    )
    ap.add_argument(
        "--sendmail-path",
        default="/usr/sbin/sendmail",
        help="Path to sendmail executable",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not send email, just print actions",
    )
    ap.add_argument(
        "--skip-if-exists",
        action="store_true",
        help="If invite_email already exists, keep existing row and do not modify or resend unless combined with your own logic",
    )
    ap.add_argument(
        "--regenerate-token",
        action="store_true",
        help="When invite_email already exists, regenerate token before sending",
    )
    ap.add_argument(
        "--template",
        required=True,
        help="Path to invitation email template file",
    )

    args = ap.parse_args()

    csv_path = Path(args.csv_file)
    db_path = Path(args.db_file)

    template_text = load_template(Path(args.template))

    if not csv_path.is_file():
        print(f"[ERROR] CSV file not found: {csv_path}", file=sys.stderr)
        return 1

    db_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        invitees = load_csv(csv_path)
    except Exception as e:
        print(f"[ERROR] Failed to read CSV: {e}", file=sys.stderr)
        return 1

    if not invitees:
        print("[INFO] No valid invitees found.")
        return 0

    conn = open_db(db_path)

    ok_count = 0
    fail_count = 0

    for inv in invitees:
        try:
            row, changed = upsert_invitee(
                conn,
                inv,
                regenerate_token=args.regenerate_token,
                skip_if_exists=args.skip_if_exists,
            )

            if not changed and args.skip_if_exists:
                print(f"[SKIP] Already exists, not sending: {inv.invite_email}")
                continue

            token = str(row["token"])
            to_email = str(row["invite_email"])

            msg = build_invitation_email(
                to_email=to_email,
                from_email=args.from_email,
                reply_to=args.reply_to or None,
                subject=args.subject,
                website_url=args.website_url,
                token=token,
                given_names=str(row["given_names"] or ""),
                family_name=str(row["family_name"] or ""),
                template=template_text,
            )

            if args.dry_run:
                print(f"[DRY-RUN] Would send to {to_email} token={token}")
            else:
                send_via_sendmail(msg, sendmail_path=args.sendmail_path)
                print(f"[OK] Sent to {to_email}")

            ok_count += 1

        except Exception as e:
            fail_count += 1
            print(f"[FAIL] {inv.invite_email}: {e}", file=sys.stderr)

    print(f"[SUMMARY] sent={ok_count} failed={fail_count}")
    return 0 if fail_count == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())

