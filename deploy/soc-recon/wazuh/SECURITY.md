# Credential rotation

How to rotate the stack off Wazuh's published default credentials, and how to verify it
actually happened. Every command here was run against this stack on 2026-07-26 — this is a
record of what worked, not a draft.

## What you're rotating, and where each password lives

**Every secret here lives in at least two places, and the copies fail independently and
silently.** This table is the whole job — miss one cell and something breaks far from the cause.

| Password | Account | Server-side copy | Client-side copy | Format |
|---|---|---|---|---|
| `WAZUH_INDEXER_PASS` | `admin` | bcrypt in `config/wazuh_indexer/internal_users.yml`, pushed via `securityadmin` | `.env` → filebeat, dashboard, CASA digest, indexer healthcheck | hash / plaintext |
| `WAZUH_DASHBOARD_PASS` | `kibanaserver` | bcrypt in `internal_users.yml`, pushed via `securityadmin` | `.env` → dashboard service account | hash / plaintext |
| `WAZUH_API_PASS` | `wazuh-wui` | `.env` → manager `API_PASSWORD`, applied every start | **`config/wazuh_dashboard/wazuh.yml`** → dashboard's API connection | plaintext / plaintext |

Plus the password manager (PHOENIX Tier 3), which is the only place any of them can be
*recovered* from — a Tier 2 snapshot restores hashes, never passwords.

`wazuh-wui` is **not** an indexer internal user. It's a manager API account: no bcrypt hash, no
`securityadmin` run. It needs `.env` **and** `wazuh.yml`.

> **The `wazuh.yml` copy is the one that gets forgotten.** Rotate `.env` without it and the
> manager API is completely healthy while the dashboard overview reports
> **"No API available to connect"**. Testing `curl -u wazuh-wui:<new> :55000` returns `200` and
> looks like proof — it isn't. That proves the *server* accepted the new password. It says
> nothing about whether every *client* was updated. Verified the hard way, 2026-07-26.

Both `internal_users.yml` and `wazuh.yml` are **gitignored** — they hold a real bcrypt hash and
a real plaintext password respectively. Only their `.example` files are tracked. After any
`git pull` that first introduces the ignore rule, git **deletes** your local copy; recreate it
from the `.example` before restarting anything, or Docker will create a directory at the
bind-mount path.

## Why lockout isn't a risk

`securityadmin.sh` authenticates with the **admin TLS certificate**, not a password. It does not
care what the current credentials are, or whether they're broken, or whether you pasted a
malformed hash. If a rotation goes wrong, fix the file and re-run the same command. Cert-based
admin access is independent of password state — iterate freely.

## Procedure

### 1. Generate passwords

**Alphanumeric only.** These are interpolated into the indexer healthcheck's `curl -u admin:...`
inside a `CMD-SHELL`, and `$` triggers compose variable expansion. 32 alphanumeric characters is
~190 bits; punctuation buys nothing and breaks things subtly.

```bash
for n in INDEXER DASHBOARD API; do
  printf '%s=' "$n"
  LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32; echo
done
```

Store all three in the password manager **now** (PHOENIX Tier 3). A Tier 2 volume snapshot
restores bcrypt *hashes*, never passwords — lose these and it's a full reset, not a restore.

### 2. Update `.env`

```bash
nano .env    # WAZUH_INDEXER_PASS, WAZUH_DASHBOARD_PASS, WAZUH_API_PASS
```

**No inline comments.** Everything after `=` is the value. A trailing `# note` becomes part of
the password. Verify by length, never by eye:

```bash
awk -F= '/_PASS=/ {print $1" = "length($2)" chars"}' .env
```

All three must read `32`. Anything longer means a comment or trailing whitespace came along.

### 3. Generate bcrypt hashes

Prime `sudo` first, so the only password prompt you see belongs to `hash.sh`. Two
indistinguishable prompts back-to-back is how you end up hashing your system password.

```bash
sudo -v

sudo docker compose exec wazuh.indexer \
  env OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk \
  bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh
```

Run once for the admin password, once for kibanaserver. Paste each `$2y$...` into the matching
account in `config/wazuh_indexer/internal_users.yml`. The file is bind-mounted — the container
sees your edit immediately, no restart needed.

### 4. Push to the running indexer

Editing the YAML changes nothing on its own. Live credentials live in the `.opendistro_security`
index; this is what moves them.

```bash
sudo docker compose exec -T wazuh.indexer \
  env OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk \
  bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
    -f /usr/share/wazuh-indexer/config/opensearch-security/internal_users.yml \
    -t internalusers -icl -nhnv \
    -cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem \
    -cert /usr/share/wazuh-indexer/config/certs/admin.pem \
    -key /usr/share/wazuh-indexer/config/certs/admin-key.pem \
    -h localhost -p 9200 < /dev/null
```

`-f` with `-t internalusers` pushes one file and one config type. **Do not use `-cd`** — that
pushes the entire security config directory and overwrites `roles` and `roles_mapping` with
image defaults.

Expect `Connected as "CN=admin,OU=Wazuh,..."`, `Force type: internalusers`, and
`updated_config_size: 1`.

### 5. Update the dashboard's copy of the API password

Separate file, plaintext, and easy to miss because nothing references it during the indexer work.

```bash
nano config/wazuh_dashboard/wazuh.yml    # password: must equal WAZUH_API_PASS in .env
```

If the file is absent (a `git pull` removed it when the ignore rule landed):

```bash
cp config/wazuh_dashboard/wazuh.yml.example config/wazuh_dashboard/wazuh.yml
ls -la config/wazuh_dashboard/    # confirm it's a FILE, not a directory
```

### 6. Recreate

```bash
sudo docker compose up -d --force-recreate
```

Containers bake env at creation, so the manager and dashboard keep old credentials until they're
recreated. Between step 4 and here the indexer will read **unhealthy** and the dashboard won't
start at all — `depends_on: condition: service_healthy` gates it. Both are expected.

**Three containers in `docker compose ps` is the signal.** The dashboard cannot start unless the
indexer went healthy, and the indexer cannot go healthy unless `.env` matches the pushed hash.

## Verify

```bash
read -rs -p "new admin password: " NEWPASS; echo

sudo docker compose exec -T wazuh.indexer \
  curl -sk -u admin:"$NEWPASS" https://localhost:9200/_cluster/health < /dev/null | jq -c

# the negative test — this is the one that matters
sudo docker compose exec -T wazuh.indexer \
  curl -sk -o /dev/null -w 'HTTP %{http_code}\n' \
  -u admin:SecretPassword https://localhost:9200/_cluster/health < /dev/null

sudo docker compose exec -T wazuh.indexer \
  curl -sk -u admin:"$NEWPASS" \
  https://localhost:9200/_plugins/_security/api/internalusers < /dev/null | jq 'keys'

sudo docker compose exec wazuh.manager filebeat test output
unset NEWPASS
```

| Check | Expected |
|---|---|
| New password | `status: yellow`, cluster responds |
| **Old password `SecretPassword`** | **`HTTP 401`** |
| Internal users | exactly `["admin","kibanaserver"]` |
| filebeat | handshake OK, talk to server OK, TLSv1.2 |

The negative test is not optional. A healthy stack and a working new password are both
consistent with the old credential *also* still working — which is what a failed hash update
looks like. Only the old password being rejected distinguishes rotation from addition.

Same for the API:

```bash
curl -sk -o /dev/null -w 'HTTP %{http_code}\n' \
  -u wazuh-wui:'MyS3cr37P450r.*-' \
  -X POST https://localhost:55000/security/user/authenticate
```

Want `401`. Verified 2026-07-26: `API_PASSWORD` is applied on every manager start, so the
*manager side* rotates from `.env` alone, despite the RBAC database persisting in the
`wazuh_api_configuration` volume.

### Client-side check — do not skip this

Server-side `200`/`401` results say nothing about whether clients were updated. Finish by
confirming the dashboard itself:

- Log into the dashboard and check the **API card on the overview page reads `Online v4.14.6`**.
  "No API available to connect" means `wazuh.yml` still holds the old password.
- `docker compose ps` shows all three containers, with the indexer `(healthy)` — the dashboard
  cannot start at all unless the indexer's healthcheck authenticated with the `.env` password.

A rotation is only complete when both the old credential is rejected **and** every client
presents the new one.

## Accounts deliberately removed

Wazuh ships six demo users. Four are unused here and were dropped rather than rotated, because
unused accounts with published credentials are pure attack surface:

`kibanaro` · `logstash` · `readall` · `snapshotrestore`

They carry `backend_roles` (`readall`, `kibanauser`, `logstash`) and their hashes are in a public
GitHub repo. PHOENIX Tier 2 uses volume tarballs rather than OpenSearch snapshots, so
`snapshotrestore` has no role here either.

## After a `down -v`

`internal_users.yml` is gitignored. Restore it and redo this whole procedure — the
`.example` carries Wazuh's **published demo hashes**, so a restored stack that skips this is
running default credentials.

```bash
cp config/wazuh_indexer/internal_users.yml.example \
   config/wazuh_indexer/internal_users.yml
```

See [`PHOENIX.md`](../../../phase-a-foundation/PHOENIX.md) Stage 1.
