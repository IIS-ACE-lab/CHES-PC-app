#!/usr/bin/env python3
import argparse
import sqlite3
import subprocess
import time
from pathlib import Path
from email.message import EmailMessage
from typing import Optional


DEFAULT_FROM = "ches2027programchairs@iacr.org"


def load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def send_via_sendmail(msg: EmailMessage, sendmail_path: str) -> None:
    proc = subprocess.run(
        [sendmail_path, "-t", "-oi"],
        input=msg.as_bytes(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", errors="replace"))


def quote_text(text: str) -> str:
    return "\n".join("> " + line for line in text.splitlines())


def build_email(
    *,
    to_email: str,
    from_email: str,
    cc_email: str,
    subject: str,
    website_url: str,
    token: str,
    given_names: str,
    family_name: str,
    reminder_template: str,
    original_template: Optional[str],
) -> EmailMessage:
    full_name = " ".join(x for x in [given_names.strip(), family_name.strip()] if x)
    greeting = f"Dear {full_name}," if full_name else "Dear colleague,"
    link = f"{website_url}?t={token}"

    body = (
        reminder_template
        .replace("{greeting}", greeting)
        .replace("{link}", link)
        .replace("{name}", full_name)
    )

    if original_template:
        original_body = (
            original_template
            .replace("{greeting}", greeting)
            .replace("{link}", link)
            .replace("{name}", full_name)
        )

        body += (
            "\n\n"
            "----- Original invitation below -----\n\n"
            f"{quote_text(original_body)}\n"
        )

    msg = EmailMessage()
    msg["To"] = to_email
    msg["From"] = from_email
    msg["Cc"] = cc_email
    msg["Subject"] = subject
    msg.set_content(body)

    return msg


def main() -> int:
    ap = argparse.ArgumentParser(description="Send reminders to invitees with status='invited'.")
    ap.add_argument("db_file", help="SQLite database path")
    ap.add_argument("--website-url", required=True, help="Base URL, e.g. https://xyz.iacr.org/PC/index.php")
    ap.add_argument("--template", required=True, help="Reminder email template with {greeting} and {link}")
    ap.add_argument("--original-template", default="", help="Optional original invitation template to quote at bottom")
    ap.add_argument("--from-email", default=DEFAULT_FROM)
    ap.add_argument("--cc", default=DEFAULT_FROM)
    ap.add_argument("--subject", default="Reminder: CHES 2027 reviewer invitation")
    ap.add_argument("--sendmail-path", default="/usr/sbin/sendmail")
    ap.add_argument("--delay", type=float, default=1.5, help="Seconds between emails")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    reminder_template = load_text(Path(args.template))
    original_template = load_text(Path(args.original_template)) if args.original_template else None

    conn = sqlite3.connect(args.db_file)
    conn.row_factory = sqlite3.Row

    rows = conn.execute("""
        SELECT token, invite_email, given_names, family_name, status
        FROM reviewers
        WHERE lower(trim(status)) = 'invited'
        ORDER BY family_name COLLATE NOCASE, given_names COLLATE NOCASE, invite_email COLLATE NOCASE
    """).fetchall()

    print(f"[INFO] Found {len(rows)} invitees with status='invited'.")

    sent = 0
    failed = 0

    for r in rows:
        try:
            msg = build_email(
                to_email=r["invite_email"],
                from_email=args.from_email,
                cc_email=args.cc,
                subject=args.subject,
                website_url=args.website_url,
                token=r["token"],
                given_names=r["given_names"] or "",
                family_name=r["family_name"] or "",
                reminder_template=reminder_template,
                original_template=original_template,
            )

            if args.dry_run:
                print(f"[DRY-RUN] Would send reminder to {r['invite_email']} link={args.website_url}?t={r['token']}")
            else:
                send_via_sendmail(msg, args.sendmail_path)
                print(f"[OK] Sent reminder to {r['invite_email']}")
                time.sleep(args.delay)

            sent += 1

        except Exception as e:
            failed += 1
            print(f"[FAIL] {r['invite_email']}: {e}")

    print(f"[SUMMARY] sent_or_would_send={sent} failed={failed}")
    return 0 if failed == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())

