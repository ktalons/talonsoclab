# Credential rotation

How to rotate the stack off Wazuh's published default credentials, and how to verify it
actually happened. The rotation commands were run against this stack on 2026-07-26, and the
argv-safe forms (`bin/idx`, `idx_as`, `api_as`, the authd sha256 check) on 2026-09-30. This is
a record of what worked, not a draft.

## What you're rotating, and where each password lives

**Every secret here lives in at least two places, and the copies fail independently and
silently.** This table is the whole job — miss one cell and something breaks far from the cause.

| Password | Account | Server-side copy | Client-side copy | Format |
|---|---|---|---|---|
| `WAZUH_INDEXER_PASS` | `admin` | bcrypt in `config/wazuh_indexer/internal_users.yml`, pushed via `securityadmin` | `.env` → filebeat, dashboard, CASA digest | hash / plaintext |
| `WAZUH_DASHBOARD_PASS` | `kibanaserver` | bcrypt in `internal_users.yml`, pushed via `securityadmin` | `.env` → dashboard service account | hash / plaintext |
| `WAZUH_API_PASS` | `wazuh-wui` | `.env` → manager `API_PASSWORD`, applied every start | **`config/wazuh_dashboard/wazuh.yml`** → dashboard's API connection | plaintext / plaintext |
| enrollment password | authd (`:1515`) | `wazuh/authd.pass` → synced to `/var/ossec/etc/authd.pass` | every agent, once at enrollment (`authd.pass` placed by hand, then removed) | plaintext / plaintext |

Plus the password manager (PHOENIX Tier 3), which is the only place any of them can be
*recovered* from — a Tier 2 snapshot restores hashes, never passwords.

`wazuh-wui` is **not** an indexer internal user. It's a manager API account: no bcrypt hash, no
`securityadmin` run. It needs `.env` **and** `wazuh.yml`.

> **The `wazuh.yml` copy is the one that gets forgotten.** Rotate `.env` without it and the
> manager API is completely healthy while the dashboard overview reports
> **"No API available to connect"**. Testing the new password against `:55000` returns `200` and
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

## Keep every secret out of argv

The SOC host runs auditd execve rules and Wazuh indexes each command line it sees (rule 80792).
A password passed as a command argument, like `curl -u admin:<pass>` or
`docker exec -e P=<pass>`, ends up in the alert index and in the manager's alert logs. The
stack's original indexer healthcheck did exactly that on every run, until 2026-09-30.

Every command in this file follows two rules:

- Query the indexer as admin with `bin/idx`. It authenticates with the admin **client
  certificate**, so there is no password to leak.
- When a password itself is under test, it reaches curl **on stdin** as a config line
  (`curl -K -`), written by `printf`. `printf` and `read` are shell builtins. They never exec,
  so auditd never sees them.

## Procedure

### 1. Generate passwords

**Alphanumeric only.** `$` in `.env` triggers compose variable expansion, and the verify steps
below pass each password inside a quoted curl config line, where `"` and `\` would need
escaping. 32 alphanumeric characters is ~190 bits; punctuation buys nothing and breaks things
subtly.

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

**Positive control first.** Steps 2 and 3 only changed files, so the indexer and the manager
still accept the old passwords. Prove that now. A `401` after the push only means the rotation
worked if the same old password returned `200` before it; otherwise it could just be a typo.
Keep this shell open until Verify.

```bash
# idx_as <password> <path> [curl args...]: basic auth as admin, password on stdin only
idx_as() {
  local pass=$1 urlpath=$2
  shift 2
  case $pass in
    ''|*[\"\\]*) echo 'idx_as: empty password or unsupported character' >&2; return 1 ;;
  esac
  printf 'user = "admin:%s"\n' "$pass" | docker compose exec -T wazuh.indexer \
    curl -s -K - --cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem \
    --resolve wazuh.indexer:9200:127.0.0.1 "$@" "https://wazuh.indexer:9200$urlpath"
}

# api_as <password>: authenticate as wazuh-wui against :55000, password on stdin only
api_as() {
  case $1 in
    ''|*[\"\\]*) echo 'api_as: empty password or unsupported character' >&2; return 1 ;;
  esac
  printf 'user = "wazuh-wui:%s"\n' "$1" | curl -sk -K - -o /dev/null \
    -w 'HTTP %{http_code}\n' -X POST https://localhost:55000/security/user/authenticate
}

read -rs -p "old admin password: " OLDPASS; echo
read -rs -p "old API password: " OLDAPI; echo
idx_as "$OLDPASS" /_cluster/health -o /dev/null -w 'HTTP %{http_code}\n'    # want HTTP 200
api_as "$OLDAPI"                                                             # want HTTP 200
```

The old passwords are the ones you are rotating off: `SecretPassword` and `MyS3cr37P450r.*-` on
a fresh stack, the previous values on every rotation after that. Both lines must print
`HTTP 200` before you go on. The helpers are bash (`read -s -p`), and they call
`docker compose` without `sudo` because the SOC host user is in the `docker` group, which is
the form that was tested.

Now push. Editing the YAML changes nothing on its own. Live credentials live in the
`.opendistro_security` index; this is what moves them.

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

Containers bake env at creation, so the manager's filebeat and the dashboard keep presenting the
old credentials until they're recreated. Between step 4 and here, expect filebeat publish errors
and a dashboard that can't reach the indexer. Both are expected.

The indexer itself stays `(healthy)` the whole time. Its healthcheck authenticates with the admin
certificate, not a password, so a healthy indexer says nothing about whether `.env` matches the
pushed hash. **`filebeat test output` is the signal** (see Verify). Filebeat logs in as `admin`
with the `.env` password, so it passes only when `.env` and the pushed hash agree.

## Verify

In the same shell as step 4, so `idx_as`, `api_as`, `OLDPASS` and `OLDAPI` are still set:

```bash
read -rs -p "new admin password: " NEWPASS; echo

idx_as "$NEWPASS" /_cluster/health | jq -c

# the negative test: the same old password that returned 200 in step 4
idx_as "$OLDPASS" /_cluster/health -o /dev/null -w 'HTTP %{http_code}\n'

idx_as "$NEWPASS" /_plugins/_security/api/internalusers | jq 'keys'

sudo docker compose exec wazuh.manager filebeat test output
```

| Check | Expected |
|---|---|
| New password | `status: yellow`, cluster responds |
| **Old password** | **`HTTP 401`** |
| Internal users | exactly `["admin","kibanaserver"]` |
| filebeat | handshake OK, talk to server OK, TLSv1.2 |

The negative test is not optional. A healthy stack and a working new password are both
consistent with the old credential *also* still working — which is what a failed hash update
looks like. Only the old password being rejected distinguishes rotation from addition, and the
`401` only counts because the step 4 positive control got `200` from the same value.

Same for the API, then clear the shell:

```bash
api_as "$OLDAPI"          # want HTTP 401; it returned 200 in step 4
unset NEWPASS OLDPASS OLDAPI
unset -f idx_as api_as
```

Verified 2026-07-26: `API_PASSWORD` is applied on every manager start, so the *manager side*
rotates from `.env` alone, despite the RBAC database persisting in the
`wazuh_api_configuration` volume.

### Client-side check — do not skip this

Server-side `200`/`401` results say nothing about whether clients were updated. Finish by
confirming the dashboard itself:

- Log into the dashboard and check the **API card on the overview page reads `Online v4.14.6`**.
  "No API available to connect" means `wazuh.yml` still holds the old password.
- `filebeat test output` passes. The indexer's own `(healthy)` status is not evidence here: its
  healthcheck uses the admin certificate, so it never presents the `.env` password at all.

A rotation is only complete when both the old credential is rejected **and** every client
presents the new one.

## Agent enrollment password (authd)

Without this, `:1515` accepts enrollment from **anything that can reach it**. UFW restricts that
to the LAN /24, but "any device on the home network" includes whatever you don't fully control.
An unauthenticated peer can register as an agent and inject events into the SIEM.

Enabled in `config/wazuh_cluster/wazuh_manager.conf`:

```xml
<use_password>yes</use_password>
```

The password itself goes in `wazuh/authd.pass` — one line, no trailing content. Gitignored;
`authd.pass.example` is the tracked placeholder.

```bash
LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32 > wazuh/authd.pass
echo >> wazuh/authd.pass
sudo docker compose up -d --force-recreate wazuh.manager
```

**Recreate, never `restart`.** The file is mounted at `/wazuh-config-mount/etc/authd.pass` and
only reaches `/var/ossec/etc/` when the manager's init copies it across. On a plain `restart`
that init step fails early and skips the copy, so authd keeps the previous password. Runbook 06
§ 3 has the full mechanism
([`06-suricata-ids-dashboards.md`](../../../phase-a-foundation/runbooks/06-suricata-ids-dashboards.md)).

Store it in the password manager — every future agent install needs it. If the host copy is
lost before the next rotation, Verify below shows how to copy the manager's value back.

> **The failure mode is generous, not loud.** If `use_password` is `yes` and `authd.pass` is
> missing or unreadable, authd does not refuse to start — it **generates a random password**
> and carries on. Agents then fail enrollment with `Invalid password` while the manager looks
> perfectly healthy. Always verify what authd actually loaded rather than what you wrote.

### Verify

```bash
# what authd actually has, not what you think you wrote. The two hashes must match.
sha256sum < wazuh/authd.pass
sudo docker compose exec -T wazuh.manager sha256sum /var/ossec/etc/authd.pass < /dev/null

sudo docker compose exec -T wazuh.manager \
  stat -c '%U:%G %a %n' /var/ossec/etc/authd.pass < /dev/null

# count only: this log line carries the generated password in clear
sudo docker compose logs wazuh.manager | grep -c 'Random password chosen'    # want 0
```

Two hashes that differ mean the container holds an older copy. The host file changed after the
manager was created, and nothing copied it across. Recreate. An error in place of a hash
(`Is a directory`, `No such file or directory`), or a non-zero count on the last line, means
authd generated its own password. It logs that value and never writes it to the file, so fix
`wazuh/authd.pass` and recreate.

If you lose the host copy while the container still holds the value your agents use, write it
straight back without displaying it, then re-run the hash pair:

```bash
(umask 077; sudo docker compose exec -T wazuh.manager cat /var/ossec/etc/authd.pass \
  < /dev/null > wazuh/authd.pass)
```

### Agent side

Install without the password, then place it as a file. Sysmon records every command line as
Event ID 1, so a `WAZUH_REGISTRATION_PASSWORD` on the msiexec line lands in the alert index,
the same way the indexer healthcheck did on Linux.

```powershell
Start-Process msiexec.exe -Wait -ArgumentList '/i', 'wazuh-agent-4.14.6-1.msi', '/qn', '/norestart', `
  'WAZUH_MANAGER=<manager-ip>', 'WAZUH_AGENT_NAME=<hostname>', `
  'WAZUH_AGENT_GROUP=phase-a-windows', 'WAZUH_PROTOCOL=tcp'
```

Copy `wazuh/authd.pass` to the agent without it entering a command line, move it to
`C:\Program Files (x86)\ossec-agent\authd.pass`, start `WazuhSvc`, and wait for `client.keys`
to go non-zero. Then delete `authd.pass`. It's only used at enrollment, not per-message.
[`04-windows-agent-sysmon.md`](../../../phase-a-foundation/runbooks/04-windows-agent-sysmon.md)
§3 to §5 has the full sequence, including the negative control.

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

See the recovery runbook, Stage 1.
