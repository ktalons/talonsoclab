# AppArmor profiles

One profile per long-running service in [`docker-compose.yml`](../docker-compose.yml). Each is
Docker's own `docker-default` profile under the service's name. The AppArmor label in a host
audit record then names the one service an exec came from, and the noise suppressions in
[`local_noise_baseline.xml`](../wazuh/custom-rules/local_noise_baseline.xml) pin that label
instead of the one every container shares
([`NOISE-BASELINE.md`](../../../phase-b-detection/NOISE-BASELINE.md)).

| Service | Profile |
|---|---|
| `wazuh.indexer` | `soc-recon-indexer` |
| `wazuh.manager` | `soc-recon-manager` |
| `wazuh.dashboard` | `soc-recon-dashboard` |
| `suricata` | `soc-recon-suricata` |

Nothing in a profile is tighter or looser than Docker's default. The only change is the name,
which appears three times: the profile line, and the two rules that let a container's own
processes signal and trace each other.

## Where the text comes from

Docker never writes `docker-default` to disk. The daemon renders it from a template when it
starts and loads the result into the kernel. `docker-default.reference` is that template
rendered for this box: `github.com/moby/profiles/apparmor` v0.2.2 (Apache-2.0), as vendored in
Docker 29.9.2, on a host where `/etc/apparmor.d` holds `abi/3.0`, `tunables/global` and
`abstractions/base` and the daemon runs unconfined.

```bash
bun tools/apparmor-profiles.ts           # profiles match the reference, compose names each one once
bun tools/apparmor-profiles.ts --write   # rebuild the four profiles from the reference
```

The check fails when a profile differs from the reference by more than its name, when the
reference differs from the digest pinned in the tool, when a service in the compose file has
no profile, shares one, or runs privileged, and when a file sits in this folder that no
service uses. It reads the one compose file and refuses what would bring settings in from
elsewhere (`extends`, `include`, an override file, a variable in `security_opt`), and any
`!` outside a comment line, since a YAML tag such as `!reset` changes what compose builds.

## After a docker-ce upgrade

The template changes between Docker releases. This one already differs from older ones: it
sets the ABI and denies `AF_ALG` and `AF_VSOCK` sockets. A copy made from an old template keeps
working and misses whatever the new default added, and nothing alerts on that. So the check is
by hand, after every `docker-ce` upgrade (runbook 00, section 5):

```bash
docker version --format '{{.Server.Version}}'     # on the box: the new version
# from a machine with gh: both source files at the old tag and at the new one
t=repos/moby/moby/contents/vendor/github.com/moby/profiles/apparmor
for f in template.go apparmor.go; do
  diff <(gh api "$t/$f?ref=docker-v29.9.2" -q .content | base64 -d) \
       <(gh api "$t/$f?ref=docker-v<new version>" -q .content | base64 -d)
done
```

Both files matter: `template.go` is the profile text, and `apparmor.go` picks the ABI line
and the includes that go into it. No output means neither moved and the copies stand (both are
identical at 29.9.3, checked 2026-11-14). Any output means: work out what the new pair renders
to on this host, change `docker-default.reference` to match, update `REFERENCE_SHA256` in
`tools/apparmor-profiles.ts`, run `bun tools/apparmor-profiles.ts --write`, install and load
the four files again, recreate the stack, and change the version named in this file.

The rendering also reads the host: whether `/etc/apparmor.d` holds `abi/3.0`,
`tunables/global` and `abstractions/base`, and what profile the daemon itself runs under. An
OS upgrade that removes one of those changes Docker's default without any Docker upgrade.

## Loading

A profile must be in the kernel before a container that names it starts. When it is not, the
start fails with `unable to apply apparmor profile` and the service stays down. So the load
comes before the first `docker compose up`, and again before a recreate whenever a profile in
this folder has changed.

```bash
# from deploy/soc-recon on the box
sudo install -m 0644 apparmor/soc-recon-* /etc/apparmor.d/
sudo apparmor_parser -r /etc/apparmor.d/soc-recon-*
sudo grep soc-recon /sys/kernel/security/apparmor/profiles   # four lines, each "(enforce)"
```

The copies in `/etc/apparmor.d` are root-owned, so a `git pull` alone never changes what the
kernel enforces. `apparmor.service` loads that folder at boot and is ordered before
`sysinit.target`, which Docker starts after. That ordering was read from the unit files, not
proved by a reboot.

After a recreate, each container should name its own profile and the kernel should agree:

```bash
docker inspect --format '{{.Name}} {{.AppArmorProfile}}' $(docker compose ps -q)
# the label the kernel holds for each container's first process, such as "soc-recon-indexer (enforce)"
for c in $(docker compose ps -q); do cat /proc/$(docker inspect --format '{{.State.Pid}}' $c)/attr/current; done
```

## Rules and containers move together

The suppression rules name these profiles, and the manager only reads its rules when its
container is created. So the labels and the rules change in one step: a bare
`docker compose up -d --force-recreate`, with no service named, which recreates all four
containers and gives the manager the new rules. Any half-way state is loud, not silent. A
service still under its old label, or a manager still on the old rules, means a healthcheck or
monitor shape stops matching its suppression and alerts as plain 80792 (thousands a day)
until the recreate is finished. Nothing is hidden in that state. Run the same command again.

To back out, revert the whole change set, the two tools and their tests included: the lint
refuses a rule that pins `docker-default`, and the profile check refuses a service with no
profile, so reverting only the rules and the compose lines leaves a tree that fails its own
checks. Then recreate the same way, check that every container is back on `docker-default`,
and only then:

```bash
sudo apparmor_parser -R /etc/apparmor.d/soc-recon-*
sudo rm /etc/apparmor.d/soc-recon-*
```
