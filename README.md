# Setup:

Build ROR index once:

```
  wget https://github.com/ror-community/ror-data/raw/refs/heads/main/v2.2-2026-01-29-ror-data.zip

  unzip v2.2-2026-01-29-ror-data.zip

  php build_ror_index.php v2.2-2026-01-29-ror-data.json
```

Move file `secrets.php` to a safe location (out of the web root) and set an amdin password.

Set the paths in `config.php` accordingly.

# Testing:
## Fill database:

Run:

```
   python3 invite_reviewers.py invitees.csv data/reviewers.sqlite   --website-url "https://example.org/index.php"   --from-email "mail@example.org"   --reply-to "ches2027@example.org"   --subject "reviewer invitation"   --template invite_email.txt --dry-run
```

This prints invitees with access token.


## Start the service:

```
  php -S localhost:8000 > /dev/null 2>&1 &
```

Open one of the inivtation links in the browser.

There is also an admin console with stat data reachable via:

```
  http://localhost:8000/admin.php?k=...
```

