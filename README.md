# Múcaro | Averiguao

Averiguao finds public infrastructure that belongs to, or serves, an organization but is missing from its inventory. You give it approved seeds (domains, IPv4 addresses or IPv4 prefixes) and an inventory snapshot. It follows a small, bounded set of passive observations outward from those seeds, attributes what it finds, and sorts every candidate into one of four review queues:

| Queue | Meaning |
| --- | --- |
| **Known** | Matches the inventory. |
| **New** | Not in the inventory and supported as the organization's own (approved domain, or RDAP registered to the organization). |
| **Unexplained** | Linked to the organization, but ownership and operation are unresolved (for example, an app hosted on a cloud provider). |
| **Third-party** | Serves an organizational name but is operated by someone else (the name's CNAME ends at an external provider). |

Every finding keeps the evidence path from its seed (`seed → certificate → hostname → DNS → address`), retrieval times, source validity periods where the source reports them, and the four attribution dimensions (ownership, operational control, hosting, service association) assessed separately. Averiguao never contacts the investigated hosts.

**Status:** Stage 1. Domain, IP and prefix seeds; Certificate Transparency, DNS, RDAP and Shodan InternetDB. ASN seeds, BGP and passive DNS history are planned, not built. The exact implemented behaviour is in [docs/RULES.md](docs/RULES.md); the longer-term design is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Try it without network

Python 3.10 or later, no third-party packages.

```sh
python3 averiguao.py --demo
```

Open the link it prints (`http://127.0.0.1:…/?token=…`). Demo mode uses a synthetic "Example Corp" world and a separate database. It shows every queue, plus the traps the scope rules have to resist: a shared certificate naming other customers, other tenants on a shared host, an expired certificate, a CDN and a SaaS status page.

## Run against real sources

```sh
python3 averiguao.py                 # web UI on 127.0.0.1:8767; open the printed link
```

The printed link carries a new access token each time the server starts. Without it, the page and the API refuse requests, so other users or programs on the same computer cannot read your findings or start runs.

1. **Inventory baseline.** Import a CSV of `value,label`. A value can be an IPv4 address, a CIDR, an exact hostname, or `*.example.com` for a whole domain tree. Each import is a new, immutable snapshot.
2. **New run.** Enter one seed per line, an approval reference (who authorized this scope) and the organization's registered names as RDAP shows them (for example `Example Corp, EXAMPLE-1`). Without organization names, address ownership can never be supported. Preview shows the normalized seeds and the estimated query count.
3. **Review.** Filter by queue, type or flag, and open a finding to see its evidence path and assessments. Exports are JSON (full provenance), CSV (one row per finding) and Markdown (analyst summary).

Runs are queued and run one at a time. Pause and resume take effect at batch boundaries. While a run is going, **Start run** becomes **Cancel run**: a cancelled run stops after its current batch, keeps and assesses what it found, and cannot be resumed. A restarted server resumes paused or interrupted runs from their last committed batch. **Reassess** recomputes queues against the current inventory without new queries.

Headless:

```sh
python3 averiguao.py run --config run.json --inventory inventory.csv --out reports/
```

`run.json` takes the same shape as the UI form:

```json
{"seeds": "example.com\n198.51.100.0/28", "approval_ref": "SEC-1234", "org_names": ["Example Corp"]}
```

## Boundaries and limits

- **Seeds:** prefixes larger than 4,096 addresses are rejected by default (the configurable ceiling is a /16). Any seed overlapping private, reserved or other special-purpose space is rejected, as are bare public suffixes such as `co.uk` or `github.io`.
- **Discovery:** stays inside the approved domains, at most two hops from a seed. Names on a shared certificate that fall outside the approved domains are counted, not followed, and so are other tenants' names on a shared host. Addresses next to an approved prefix are never queried. Public DNS answers pointing into private address space are flagged and never sent to any source.
- **Run limits:** hostnames, addresses, queries and time are each capped per run. When a run hits a cap it completes with a visible truncation notice, so the absence of a finding is never mistaken for the absence of infrastructure. Source failures are counted and shown too.
- **Sources and default rates:** crt.sh 0.5/s, Cloudflare DNS-over-HTTPS 10/s, rdap.org 1/s, InternetDB 5/s. Change them with `--rate SOURCE=N`. Connections are reused and each source's rate limit is shared across workers. `Retry-After` is honoured, and a source that asks for a long pause fails fast instead of blocking the run. Requests identify themselves with a User-Agent that links to this repository.

Shodan describes InternetDB as free for noncommercial use, including within a company, but not as the basis of a paid product. crt.sh is a community service with no capacity guarantee. Read each source's terms before heavy or commercial use.

## What the evidence means

Observations are what a source reported at retrieval time, not live tests. "No record" means the source had nothing, not that an address is unused or safe. A hostname under an approved domain supports ownership of the name, not control of the server it points to. An RDAP registration to a cloud provider means the provider owns the address, not that the organization does not operate the service. Averiguao keeps conflicting evidence visible instead of choosing a winner.

## What leaves your machine, and what stays

The tool sends only the name or address being looked up, plus a User-Agent naming Averiguao and this repository:

| Service | Receives |
| --- | --- |
| crt.sh | Approved domains |
| Cloudflare DNS-over-HTTPS | In-scope hostnames |
| rdap.org, and the regional registry it redirects to | Discovered addresses |
| Shodan InternetDB | Discovered addresses and every address of a prefix seed |

Each of these services, and anyone between you and them, can see which names and addresses you investigated and your public IP address.

Your inventory, organization names, approval references and findings are never sent anywhere. Addresses in private or reserved space are never sent either.

Everything stays in `.averiguao/` (ignored by Git), which is created owner-only, with the database files readable only by you. Headless reports are written owner-only too. The server listens only on 127.0.0.1. It requires the access token and rejects requests from other origins and hostnames. It has no third-party Python dependencies and never runs commands or loads code from what it downloads.

## Develop

```sh
python3 -m unittest discover -s tests -t .
NODE_PATH=$(npm root -g) node tests/e2e/test_ui.mjs     # optional, needs Playwright
```

| Suite | Covers |
| --- | --- |
| Unit tests | One per module. |
| `tests/acceptance/` | Checks the synthetic world against the Stage 1 acceptance criteria. |
| `tests/adversarial/` | Scope-escape and source-etiquette probes. |
| `tests/security/` | Local server and report-injection probes. |

No test touches the network.
