# Múcaro | Averiguao

Averiguao is a Python proof of concept for reviewing passive public observations about an approved IPv4 address or range. It queries Shodan InternetDB once per address, saves progress and positive observations in local SQLite, compares observed IPs with an optional inventory baseline, and presents the results in a browser. It does not scan or contact the investigated addresses.

## Run locally

Python 3.10 or later is required. No third-party Python packages or API token are required.

```sh
python3 oifd.py
```

Open [http://127.0.0.1:8767/](http://127.0.0.1:8767/) on the same computer. The server binds only to loopback. You can choose another port and tune the request pace:

```sh
python3 oifd.py --port 8768 --rate 50 --workers 8
```

The default is at most 50 requests per second across eight workers. This is an application setting, not a promised InternetDB allowance. HTTP 429 responses trigger a shared cooldown. Repeated source failures pause the job rather than marching through a large range as errors. The run can then be resumed. Avoid running multiple Averiguao server processes against the same data directory.

If the Python.org macOS build lacks its own trusted certificate bundle, Averiguao uses the Mac's `/etc/ssl/cert.pem` for verified HTTPS. It never disables certificate verification. On other systems, Python's configured trust store is used.

## Review a range

1. Optionally import a CSV of known public IPs or CIDRs using `IP_or_CIDR,label`. Saving a new baseline replaces the previous one and updates the classification of displayed results.
2. Enter one approved public IPv4 address or CIDR. **Preview range** shows the normalized range and exact number of addresses.
3. Select **Start lookup**. Every address in the selected range is checked, including addresses with no InternetDB record. A `/16` is 65,536 lookups and a `/8` is 16,777,216; large jobs can take substantial time. The job runs in batches of 256, and progress is committed after each batch.
4. Use **Pause** or **Resume** as needed. If the server is stopped, an interrupted job is marked paused when it starts again; resume from its last committed batch.
5. Inspect records and export CSV or JSON. Exports contain fetched positive or error records. The summary separately counts addresses for which InternetDB returned no record.

Data lives in `.oifd/oifd.sqlite3` and is ignored by Git. Back up that directory if you need the history. Averiguao does not send the inventory baseline to InternetDB; it sends only the individual addresses being queried. InternetDB and network intermediaries can see those queries and the requesting public IP.

## Interpret the evidence

InternetDB reports ports, hostnames, software identifiers, tags, and potential CVE identifiers. These are source observations, not a live test or vulnerability confirmation. Averiguao stores retrieval time, the source URL, and a hash of the source response. InternetDB does not provide a per-IP scan time through this endpoint, so Averiguao leaves that time unknown rather than substituting its retrieval time. Its database is updated weekly according to [Shodan's documentation](https://book.shodan.io/developer-apis/internetdb/).

“No record” means InternetDB returned no information for that address. It does not mean the address is unused or safe. A result on an approved range can be a tenant, vendor, or shared hosting service. The current app does not infer ownership or operational control.

Shodan states that the hosted InternetDB API requires no key and is free for noncommercial use, including use within a company, but not as the basis of a charged commercial product. See [Shodan's usage description](https://blog.shodan.io/introducing-the-internetdb-api/) before distributing or monetizing an integration.

## Verify

```sh
python3 -m unittest -v
```

The tests use simulated InternetDB responses. They verify range handling, inventory reconciliation, batch checkpoints, restart recovery, and rate-limit retry behavior without querying external addresses.
