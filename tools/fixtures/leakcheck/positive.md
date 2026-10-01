# Positive fixture

Every value in this file is fake. Each flagged line carries an `expect:` marker
naming the rule that must fire, and the self-test fails on any other finding.

Host fixture-deny-host is on the denylist. <!-- expect: denylist -->
The prefix 172.16.0.x is on the denylist too. <!-- expect: denylist -->
MAC 02:42:ac:11:00:02 belongs to a real device. <!-- expect: mac-address -->
Address 10.99.0.7 is RFC 1918. <!-- expect: private-ipv4 -->
A label may touch the address: MAC:02:42:ac:11:00:02 <!-- expect: mac-address -->
macOS arp drops leading zeros: 2:42:ac:11:0:2 <!-- expect: mac-address -->
Cisco notation: 0242.ac11.0002 <!-- expect: mac-address -->
Linux names the interface after it: enx0242ac110002 <!-- expect: mac-address -->
Link-local fe80::42:acff:fe11:2 and unique-local fd12:3456:789a::10 <!-- expect: private-ipv6 -->
CGNAT 100.64.0.7 is a Tailscale address. <!-- expect: private-ipv4 -->
Link-local 169.254.10.20 names a host too. <!-- expect: private-ipv4 -->
Host key SHA256:FixtureFixtureFixtureFixtureFixtureFixture0 <!-- expect: ssh-fingerprint -->

```bash
curl -sk -u admin:fixture-not-a-secret https://localhost:9200/_cluster/health   # expect: argv-user
curl -sk --user "wazuh-wui:$FIXTURE_PASS" https://localhost:55000/security/user/authenticate   # expect: argv-user
curl -sku admin:fixture https://localhost:9200   # expect: argv-user
curl -sk -u admin:"fixture" https://localhost:9200   # expect: argv-user
curl -sk -H "Authorization: Bearer fixture-token" https://localhost:55000/agents   # expect: argv-header
curl -sk --oauth2-bearer fixture-token https://localhost:55000/agents   # expect: argv-header
curl -sk -d '{"user":"admin","password":"fixture"}' https://localhost:55000/security/user/authenticate   # expect: argv-body
docker compose exec -e INDEXER_PASSWORD=fixture wazuh.indexer true   # expect: argv-env
docker run --rm -e API_TOKEN="fixture" busybox true   # expect: argv-env
sudo /var/ossec/bin/agent-auth -m <MANAGER-IP> -P fixture-pass   # expect: argv-agent-auth
sudo WAZUH_REGISTRATION_PASSWORD=fixture apt-get install wazuh-agent   # expect: argv-secret-assign
sudo PASSWORD=fixture some-installer   # expect: argv-secret-assign
env API_KEY=fixture some-tool   # expect: argv-secret-assign
sshpass -p fixture ssh talon@<DELL-IP>   # expect: argv-sshpass
mysql -u root -pfixture wazuh   # expect: argv-mysql
mariadb-dump -u root -pfixture wazuh   # expect: argv-mysql
mysqlcheck -u root -pfixture wazuh   # expect: argv-mysql
docker login -u fixture-user -p fixture registry.example.test   # expect: argv-password-opt
bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p fixture   # expect: argv-password-opt
some-tool --password fixture   # expect: argv-password-opt
some-tool --api-key=fixture   # expect: argv-password-opt
/usr/share/wazuh-indexer/bin/wazuh-keystore -f indexer -k password -v fixture   # expect: argv-password-opt
git clone https://fixture-user:fixture-token@git.example.test/repo.git   # expect: argv-url-userinfo
```

Continuation lines map back to the physical line that holds the secret:

```bash
curl -sk \
  -u admin:fixture -w 'expect: argv-user' \
  https://localhost:9200/_cluster/health
```

```powershell
msiexec.exe /i wazuh-agent.msi /q `
  WAZUH_MANAGER="<MANAGER-IP>" WAZUH_REGISTRATION_PASSWORD="fixture"   # expect: argv-secret-assign
.\wazuh-agent.msi /q WAZUH_REGISTRATION_PASSWORD=fixture   # expect: argv-secret-assign
```

```cmd
net user fixture-user fixture-pass /add   # expect: argv-net-user
some-tool.exe ^
  --token fixture   # expect: argv-password-opt
```

A fence inside a blockquote is still a fence:

> ```sh
> curl -u admin:fixture https://localhost:9200   # expect: argv-user
> ```

Exec form splits one command across list items, and the scanner joins them:

```yaml
healthcheck:
  test: ["CMD", "curl", "-sk", "-u", "admin:fixture", "https://localhost:9200"]   # expect: argv-user
```

An auditd EXECVE record carries the argv the process saw. A text fence is not
argv scope, and the record is still read as one:

```text
type=EXECVE msg=audit(1700000000.000:1): argc=4 a0="curl" a1="-u" a2="admin:fixture" a3="https://localhost:9200"   # expect: argv-user
```

The JSON shape from the Wazuh decoder is the same record:

```json
{"data": {"audit": {"execve": {"a0": "curl", "a1": "-u", "a2": "admin:fixture"}}}}   # expect: argv-user
```

Hex-encoded arguments decode before the rules run:

```text
type=EXECVE msg=audit(1700000000.000:2): argc=3 a0="curl" a1="-u" a2=61646D696E3A66697874757265   # expect: argv-user
```

A marker that is not the marker does not silence anything:

```bash
curl -u admin:fixture https://localhost:9200   # leakcheck: allowlist   # expect: argv-user
```

```bash
echo "leakcheck: allow means nothing on a line that is not a comment"
curl -u admin:fixture https://localhost:9200   # expect: argv-user
```

Short-flag clusters, an attached value before -H, and the rest of the secret option names:

```bash
curl -skH "Authorization: Bearer fixture-token" https://localhost:55000/agents   # expect: argv-header
curl -XPATCH -H "Authorization: Bearer fixture-token" https://localhost:55000/agents   # expect: argv-header
gpg --batch --passphrase fixture -d f.gpg   # expect: argv-password-opt
some-tool --pwd fixture   # expect: argv-password-opt
some-tool --pass fixture   # expect: argv-password-opt
some-tool --api_key fixture   # expect: argv-password-opt
some-tool --credential fixture   # expect: argv-password-opt
some-tool --db-pass=fixture   # expect: argv-password-opt
some-tool --dbpassword fixture   # expect: argv-password-opt
```

A Dockerfile ENV or ARG bakes its value into the image history:

```dockerfile
ENV API_TOKEN=fixture   # expect: argv-secret-assign
ARG DB_PASSWORD=fixture   # expect: argv-secret-assign
```

A markdown sample is prose, and a command fence inside it is still read:

````markdown
In the sample's own prose, curl -u admin:fixture is not a command line.

```bash
curl -u admin:fixture https://localhost:9200   # expect: argv-user
```
````

A quote ends at the blank line, and so does an unclosed fence inside it:

> ```text
> quoted output, never closed inside the quote

```bash
curl -u admin:fixture https://localhost:9200   # expect: argv-user
```

A line indented four columns past its fence is content, not a closer:

```bash
echo start
    ```
curl -u admin:fixture https://localhost:9200   # expect: argv-user
```

A fence nested in a list item:

1. Check the indexer:

    ```bash
    curl -u admin:fixture https://localhost:9200   # expect: argv-user
    ```

The compose environment: exemption ends at the next key:

```yaml
services:
  helper:
    environment:
      - FIXTURE_URL=https://fixture-user:fixture-pass@db.example.test
    command: ["curl", "-u", "admin:fixture", "https://localhost:9200"]   # expect: argv-user
```

## Round 2d

Padded form SHA256:FixtureFixtureFixtureFixtureFixtureFixture0= <!-- expect: ssh-fingerprint -->
Legacy form MD5:0f:1e:2d:3c:4b:5a:69:78:87:96:a5:b4:c3:d2:e1:f0 <!-- expect: ssh-fingerprint -->
Long form SHA512:FixtureFixtureFixtureFixtureFixtureFixtureFixtureFixtureFixtureFixtureFixtureFixture0w <!-- expect: ssh-fingerprint -->
Short form SHA1:FixtureFixtureFixtureFixtur <!-- expect: ssh-fingerprint -->

```bash
redis-cli -u redis://:fixture-not-a-secret@cache.example.test:6379   # expect: argv-url-userinfo
sudo PGPASSWORD=fixture psql   # expect: argv-secret-assign
curl -d '{"userPassword":"fixture"}' https://x.example.test   # expect: argv-body
mysql -u root -p'a;b' db   # expect: argv-mysql
MYSQL_PWD=$(tool --token fixture) mysql db   # expect: argv-password-opt
echo it's; mysql -p db; tool --password fixture   # expect: argv-password-opt
```

```cmd
net use Z: \\fixture-srv\share fixture-pass /user:fixture-user   # expect: argv-net-user
net use \\fixture-srv\IPC$ /user:fixture-user fixture-pass   # expect: argv-net-user
```

```text
type=EXECVE msg=audit(1700000000.000:4): argc=3 a0="curl" a1="-u" a2=61646d696e3a66697874757265   # expect: argv-user
type=EXECVE msg=audit(1700000000.000:5): argc=3 a0="curl" a1="-u" a2=61646D696E3A66697874C3BC7265   # expect: argv-user
type=EXECVE msg=audit(1700000000.000:6): argc=3 a0="bash" a1="-c" a2=736574202D650A6375726C202D752061646D696E3A666978747572652068747470733A2F2F6C6F63616C686F73743A39323030   # expect: argv-user
type=EXECVE msg=audit(1700000000.000:7): argc=2 a0="ssh" a1=666978747572654031302E3235352E302E3920757074696D65   # expect: private-ipv4
type=EXECVE msg=audit(1700000000.000:8): argc=2 a0="sh" a1=70696E6720666978747572652D64656E792D686F7374   # expect: denylist
```

## Round 3

A prefix inside unique-local space names a network: fd12:3456::/48 <!-- expect: private-ipv6 -->
So does its network address alone: fd12:3456:: <!-- expect: private-ipv6 -->
A zone index does not hide the address: fe80::1%en0 <!-- expect: private-ipv6 -->
Neither does a bracketed port: [fe80::1]:22 <!-- expect: private-ipv6 -->

A continuation mark needs no space before it:

```powershell
some-tool -Label 'expect: argv-password-opt' --token`
  fixture
```

```cmd
some-tool.exe /label:"expect: argv-password-opt" --password^
  fixture
net user "Fixture User" fixture-pass /add   # expect: argv-net-user
```

```bash
curl --proxy-user fixture-user:fixture-pass https://x.example.test   # expect: argv-user
curl -U fixture-user:fixture-pass https://x.example.test   # expect: argv-user
curl --cookie session=fixture-pass https://x.example.test   # expect: argv-header
curl -sb "session=fixture-pass" https://x.example.test   # expect: argv-header
curl -H "X-Vault-Token: fixture-pass" https://x.example.test   # expect: argv-header
curl -H "Ocp-Apim-Subscription-Key: fixture-pass" https://x.example.test   # expect: argv-header
openssl enc -aes-256-cbc -pass pass:fixture-pass -in clear.txt   # expect: argv-password-opt
openssl pkcs12 -export -passout=pass:fixture-pass -in c.pem   # expect: argv-password-opt
openssl enc -aes-256-cbc -k fixture-pass -in clear.txt   # expect: argv-password-opt
some-tool --credentials fixture-pass   # expect: argv-password-opt
some-tool --tokens fixture-pass   # expect: argv-password-opt
sudo DB_PASSWORDS=fixture-pass some-tool   # expect: argv-secret-assign
docker run --rm alpine some-tool --secret fixture-pass   # expect: argv-password-opt
nerdctl run -e API_TOKEN=fixture alpine true   # expect: argv-env
docker build --build-arg DB_PASSWORD=fixture-pass .   # expect: argv-secret-assign
podman build --build-arg=API_TOKEN=fixture .   # expect: argv-secret-assign
```
