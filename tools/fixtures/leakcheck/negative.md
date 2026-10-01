# leakcheck negative fixture

Nothing in this file may trip a rule. The shell lines are the argv-safe forms the
stack actually uses (`wazuh/SECURITY.md`, runbooks 02, 04, 06 and 07).

## Placeholders and look-alikes

Real addresses are `<DELL-IP>` and `<MANAGER-IP>`; the LAN is `192.168.x.0/24`.
RFC 1918 blocks: 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16.
CGNAT is 100.64.0.0/10 and link-local is 169.254.0.0/16; the cloud metadata
address 169.254.169.254 is the same on every host.
Documentation addresses are fine: 192.0.2.10, 198.51.100.7, 203.0.113.5.
Windows 11 build 10.0.26200.8894 is a version string, not an address.
Broadcast ff:ff:ff:ff:ff:ff, all-zero 00:00:00:00:00:00, doc MAC 00:00:5e:00:53:01.
Multicast 01:80:c2:00:00:0e (STP) and 33:33:00:00:00:01 (IPv6 all-nodes) name no device.
The name fixture-excluded-name is on an included list and dropped again by `@exclude`.
Fingerprint AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89 is not a MAC.
IPv6 prefixes fe80::/10 and fc00::/7, and the documentation address 2001:db8::1.
A docker digest sha256:0242ac110002aabbccddeeff00112233445566778899aabbccddeeff00112233 is not a host key.
In prose, the old healthcheck ran `curl -sk -u admin:<pass>` every 30 seconds.

## Safe command forms

```bash
bin/idx /_cluster/health
bin/idx /_plugins/_ism/policies/wazuh-alerts-retention -X PUT --data-binary @- \
  < wazuh/ism/wazuh-alerts-retention.json
bin/idx '/_plugins/_ism/add/wazuh-alerts-*' -X POST -d '{"policy_id":"wazuh-alerts-retention"}'
printf 'user = "admin:%s"\n' "$pass" | docker compose exec -T wazuh.indexer \
  curl -s -K - --cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem \
  https://localhost:9200/_cluster/health
printf 'user = "wazuh-wui:%s"\n' "$1" | curl -sk -K - -o /dev/null \
  -w 'HTTP %{http_code}\n' -X POST 'https://localhost:55000/security/user/authenticate'
idx_as "$OLDPASS" /_cluster/health -o /dev/null -w 'HTTP %{http_code}\n'    # want HTTP 200
PASS=$(sudo docker compose exec -T wazuh.manager cat /var/ossec/etc/authd.pass < /dev/null)
sha256sum < wazuh/authd.pass
sudo docker compose exec -T wazuh.manager sha256sum /var/ossec/etc/authd.pass < /dev/null
sudo -u talon docker compose exec -u 1000:1000 wazuh.manager true
docker compose exec -e TZ wazuh.manager date
curl -s -H @headers.txt https://api.example.test/
curl -s -H 'Accept: application/json' https://api.example.test/
curl -sk -d '{"policy_id":"wazuh-alerts-retention"}' https://localhost:9200/_plugins/_ism/add/wazuh-alerts-1
curl -sk -d @body.json -X POST https://localhost:55000/security/policies
mysql -u root -p wazuh
mysql -u root --password wazuh
mariadb-dump -u root --password wazuh
mariadb-admin -u root --password status
docker login -u fixture-user --password-stdin registry.example.test < token.txt
gh auth login --with-token < token.txt
echo "$KEYSTORE_PASS" | /usr/share/wazuh-indexer/bin/wazuh-keystore -f indexer -k password
sshpass -e ssh <USERNAME>@<DELL-IP>
ssh -i ~/.ssh/<KEY> <USERNAME>@<DELL-IP>
git clone git@github.com:ktalons/talonsoclab.git
```

```cmd
net user alice /add
net user alice * /add
```

An anti-pattern quoted on purpose carries the marker on the line above:

```bash
# leakcheck: allow (the pre-2026-09-30 healthcheck, quoted as a warning)
curl -sk -u admin:<pass> https://localhost:9200/_cluster/health
```

```powershell
# leakcheck: allow (quoted from the vendor page to show what not to run)
msiexec.exe /i wazuh-agent.msi /q WAZUH_REGISTRATION_PASSWORD="<PASSWORD>"
```

The repo's own indexer healthcheck, in exec form, authenticates with a client
certificate and holds no secret:

```yaml
healthcheck:
  test: ["CMD", "curl", "-sf", "-o", "/dev/null", "-m", "8",
         "--cacert", "/usr/share/wazuh-indexer/certs/root-ca.pem",
         "--cert", "/usr/share/wazuh-indexer/certs/admin.pem",
         "--key", "/usr/share/wazuh-indexer/certs/admin-key.pem",
         "--resolve", "wazuh.indexer:9200:127.0.0.1",
         "https://wazuh.indexer:9200/_cluster/health?wait_for_status=yellow&timeout=5s"]
```

```text
curl -sk -u admin:fixture https://localhost:9200/   (a text fence is not argv scope)
```

A record that is not an EXECVE record, even though it names arguments:

```text
type=SYSCALL msg=audit(1700000000.000:3): arch=c000003e syscall=59 a0=7ffd a1=7ffe a2=7fff items=2 comm="curl"
```

Options that only look like secrets, and a cluster that carries no credentials:

```bash
some-tool --bypass true
gpg --passphrase-fd 0 -d f.gpg
gpg --passphrase-file f.txt -d f.gpg
some-tool --pass-through x
some-tool --passthrough x
gpg --passphrase < passphrase.txt
curl -sH 'Accept: application/json' https://api.example.test/
```

```dockerfile
FROM alpine:3.20
ARG NUCLEI_VERSION=latest
ENV CGO_ENABLED=0
ARG API_TOKEN
```

A quoted fence ends with the quote:

> ```bash
> echo quoted

In prose after the quote, curl -u admin:fixture is not a command line.

A closer may sit three columns deeper than its opener:

```bash
echo inside
   ```

In prose after that closer, curl -u admin:fixture is not a command line either.

A compose environment block in a yaml fence, list form and map form, and a dotenv fence:

```yaml
services:
  db:
    environment:
      - DB_URL=https://fixture-user:${DB_PASS}@db.example.test
  web:
    environment:
      DB_URL: https://fixture-user:${DB_PASS}@db.example.test
```

```dotenv
DB_URL=https://fixture-user:fixture-pass@db.example.test
```

## Round 2d

A hex object name is not a key fingerprint: SHA1:da39a3ee5e6b4b0d3255bfef95601890afd80709.

```bash
env BYPASS_PROXY=1 some-tool
curl -d "bypass=1" https://x.example.test
mysql -u root --password db
sh -c "mysql -e 'select 1;' --password db"
```

```cmd
net use Z: \\server\share * /user:alice
net use \\server\IPC$ "" /user:""
net use Z: /delete >nul 2>&1
```

## Round 3

A bare block head such as fe80:: or fd00::/8 names no network, fead:beef is a word,
and fe80:::1 is not an address.

```cmd
net user "Alice Smith" /add
net user "Alice Smith" * /add
```

```bash
curl -b cookies.txt https://api.example.test/
curl --cookie-jar jar.txt -b jar.txt https://api.example.test/
openssl enc -aes-256-cbc -pass env:ENC_PASS -in clear.txt
openssl rsa -passin file:key.pass -in key.pem
openssl pkcs12 -export -passout stdin -in c.pem
openssl req -new -key server.key -out server.csr
podman run --secret db-password alpine true
docker run --rm --secret source=db-password,target=db-password alpine true
docker build --secret id=npmrc,src=.npmrc .
docker build --build-arg DB_PASSWORD --build-arg VERSION=1.2 .
podman build --build-arg-file build.args .
```
