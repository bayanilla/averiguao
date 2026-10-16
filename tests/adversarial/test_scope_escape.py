"""G1 adversarial probes: try to make discovery record candidates or query sources outside the approved boundary.

Tests whose docstring starts with "ISSUE" fail on purpose and document a confirmed problem. The rest are regression
guards for attacks that the code currently resists.
"""

from __future__ import annotations

import ipaddress
import unittest

from averiguao_core import attribution, scope
from averiguao_core.scope import ScopeError

from ._world import WorldCase, a, cert, idb, queried, rdap, world

NON_GLOBAL_PROBES = ("10.0.0.5", "127.0.0.1", "169.254.169.254", "192.168.1.1", "100.64.0.1", "0.0.0.0",
                     "224.0.0.1", "255.255.255.255")


class DnsAnswerAddresses(WorldCase):
    def test_dns_answers_in_non_global_space_are_not_recorded_or_sent_to_sources(self):
        """ISSUE (engine.py _Handler._dns, ~line 314): DNS answers are recorded and enriched without any check of
        the address range. An in-scope name that resolves to 10.0.0.5, 127.0.0.1 or 169.254.169.254 (cloud
        metadata) becomes an `ip` candidate and the engine sends that internal address to rdap.org and Shodan
        InternetDB. RULES.md section 1 rejects every non-global address as an IP seed; it is silent on DNS answers,
        but by the same reasoning (and common sense: it leaks internal addressing to third parties and produces
        meaningless 'new' findings like 127.0.0.1) a non-global answer should at most stay as CONTEXT on the DNS
        evidence: not recorded as a candidate, never queried."""
        w = world(dns={"example.com": a("example.com", list(NON_GLOBAL_PROBES) + ["198.51.100.9"])})
        store, run_id = self.run_world("example.com", w)
        asked = queried(w)
        leaked = sorted(q for (src, q) in asked if src in ("rdap", "internetdb") and q in NON_GLOBAL_PROBES)
        recorded = sorted(aid for aid in self.asset_ids(store, run_id)
                          if aid.startswith("ip:") and aid[3:] in NON_GLOBAL_PROBES)
        self.assertEqual(leaked, [], "non-global DNS answers were sent to rdap/internetdb")
        self.assertEqual(recorded, [], "non-global DNS answers were recorded as ip candidates")
        self.assertIn("ip:198.51.100.9", self.asset_ids(store, run_id))

    def test_ipv6_and_garbage_addresses_in_dns_data_are_ignored(self):
        w = world(dns={"example.com": a("example.com", ["2001:db8::1", "::ffff:198.51.100.7", "not-an-ip", "",
                                                        "198.51.100.300", "198.51.100.7/24"])})
        store, run_id = self.run_world("example.com", w)
        ips = {aid for aid in self.asset_ids(store, run_id) if aid.startswith("ip:")}
        self.assertEqual(ips, set())
        self.assertFalse({q for (s, q) in queried(w) if s in ("rdap", "internetdb")})


class RdapCache(WorldCase):
    def test_rdap_network_that_does_not_contain_the_query_is_not_reused(self):
        """ISSUE (engine.py execute ~line 410-418 with _cidrs_of; rdap.py map_rdap): the per-run RDAP cache trusts
        whatever `cidrs` an RDAP answer claims, without checking that they contain the queried address. An RDAP
        answer for 203.0.113.50 that claims 198.51.100.0/24 makes the engine skip the RDAP query for
        198.51.100.9 and attribution then reports 198.51.100.9's hosting/ownership from 203.0.113.50's registrant.
        RULES.md 2: 'an ip inside an already-fetched RDAP network reuses that evidence' - an ip is only inside the
        network the source actually answered for; networks that do not contain the query must be ignored (and
        the evidence kept only for the queried ip)."""
        w = world(rdap={"203.0.113.50": rdap("LIAR-NET", ["198.51.100.0/24"], org="Liar Hosting"),
                        "198.51.100.9": rdap("CORP-NET", ["198.51.100.0/24"], org="Corp")})
        store, run_id = self.run_world("203.0.113.50\n198.51.100.9", w, batch_size=1)
        self.assertIn(("rdap", "198.51.100.9"), queried(w),
                      "198.51.100.9 was never looked up: the cache reused a network 203.0.113.50's answer lied about")

    def test_rdap_whole_internet_network_does_not_suppress_every_later_lookup(self):
        """ISSUE (engine.py execute ~line 410-418): an RDAP answer whose network is 0.0.0.0/0 (or any huge block,
        e.g. an IANA/unallocated placeholder or a hostile/buggy RIR mirror) is cached and then 'covers' every
        later address of the run: no further RDAP query is made and every ip is attributed to that one record.
        RULES.md is silent on sanity bounds for the cache; common sense: never reuse an RDAP network larger than
        a plausible allocation (e.g. shorter than /8) or one that overlaps special-purpose space."""
        w = world(rdap={"203.0.113.50": rdap("EVERYTHING", ["0.0.0.0/0"], org="Everyone Inc"),
                        "198.51.100.9": rdap("CORP-NET", ["198.51.100.0/24"], org="Corp")})
        self.run_world("203.0.113.50\n198.51.100.9", w, batch_size=1)
        self.assertIn(("rdap", "198.51.100.9"), queried(w))

    def test_rdap_cache_reuse_inside_a_real_network_still_works(self):
        w = world(rdap={"198.51.100.9": rdap("CORP-NET", ["198.51.100.0/24"])})
        self.run_world("198.51.100.9\n198.51.100.10", w, batch_size=1)
        self.assertNotIn(("rdap", "198.51.100.10"), queried(w))


class CertificateNames(WorldCase):
    LOOKALIKES = [
        "example.com.evil.test", "evil-example.com", "notexample.com", "xn--exmple-cua.com", "examp1e.com",
        "www.example.com:443", "user@www.example.com", "www.example.com/admin", "www.example.com\x00.evil.test",
        "www.example.com evil.test", "*.*.example.com", "*example.com", "*.example.com.evil.test", "a..example.com",
        ".example.com", "example.com..", "exаmple.com", "www.example.com。evil.test",
        "x" * 64 + ".example.com", ("a." * 130) + "example.com", "", " ", None, 7, ["www.example.com"],
        {"n": "www.example.com"}, "_dmarc.example.com",
    ]

    def test_lookalike_and_malformed_ct_names_never_queried(self):
        w = world(ct={"example.com": {"certificates": [cert("1", self.LOOKALIKES + ["ok.example.com"])]}})
        store, run_id = self.run_world("example.com", w)
        for src, q in queried(w):
            self.assertTrue(q == "example.com" or q.endswith(".example.com") or src in ("rdap", "internetdb"),
                            f"{src} asked about {q!r}")
        hostnames = {aid for aid in self.asset_ids(store, run_id) if aid.startswith("hostname:")}
        for h in hostnames:
            self.assertTrue(h.endswith(".example.com"), h)
        self.assertIn("hostname:ok.example.com", hostnames)
        oos = store.run(run_id).get("out_of_scope") or {}
        self.assertGreater(sum(oos.values()), 0)

    def test_ct_name_equal_to_seed_or_wildcard_of_seed_adds_nothing(self):
        w = world(ct={"example.com": {"certificates": [cert("1", ["EXAMPLE.COM.", "*.example.com", "example.com"])]}})
        store, run_id = self.run_world("example.com", w)
        self.assertEqual({aid for aid in self.asset_ids(store, run_id) if aid.startswith("hostname:")}, set())
        self.assertEqual(w["dns"].queries(), ["example.com"])

    def test_ct_names_respect_max_depth_one_and_max_hostnames_one(self):
        names = [f"h{i}.example.com" for i in range(20)]
        w = world(ct={"example.com": {"certificates": [cert("1", names)]}},
                  dns={n: a(n, ["198.51.100.9"]) for n in names})
        store, run_id = self.run_world("example.com", w, limits={"max_depth": 1, "max_hostnames": 1})
        ids = self.asset_ids(store, run_id)
        self.assertEqual(len([i for i in ids if i.startswith("hostname:")]), 1)
        self.assertEqual([i for i in ids if i.startswith("ip:")], [])  # depth 2 never recorded at max_depth 1
        self.assertFalse({q for s, q in queried(w) if s in ("rdap", "internetdb")})
        self.assertLessEqual(len(w["dns"].queries()), 2)  # the seed and the single recorded hostname

    def test_overlapping_and_duplicate_seeds_query_each_name_once(self):
        w = world(ct={"example.com": {"certificates": [cert("1", ["sub.example.com", "a.sub.example.com"])]},
                      "sub.example.com": {"certificates": [cert("1", ["a.sub.example.com"])]}})
        self.run_world("example.com\nsub.example.com\nEXAMPLE.com.\nsub.example.com", w)
        for name, conn in w.items():
            qs = conn.queries()
            self.assertEqual(len(qs), len(set(qs)), f"{name} queried twice: {qs}")


class InternetDBHostnames(WorldCase):
    def test_in_scope_internetdb_hostnames_are_recorded_but_never_resolved(self):
        w = world(dns={"example.com": a("example.com", ["198.51.100.9"])},
                  internetdb={"198.51.100.9": idb(hostnames=["vpn.example.com", "other.test", "example.com.evil.test",
                                                             "*.example.com", "VPN.EXAMPLE.COM."])})
        store, run_id = self.run_world("example.com", w, limits={"max_depth": 1})
        ids = self.asset_ids(store, run_id)
        self.assertIn("hostname:vpn.example.com", ids)
        self.assertNotIn("hostname:other.test", ids)
        self.assertNotIn("hostname:example.com.evil.test", ids)
        self.assertEqual(w["dns"].queries(), ["example.com"])


class PrefixSeeds(WorldCase):
    def test_prefix_never_queries_neighbours_or_covering_networks(self):
        w = world(rdap_fallback=lambda q: rdap("CORP", ["198.51.100.0/24"]))
        self.run_world("198.51.100.16/30\n198.51.100.20/30", w)  # adjacent prefixes
        ips = {q for s, q in queried(w) if s in ("rdap", "internetdb")}
        net = ipaddress.ip_network("198.51.100.16/29")
        self.assertTrue(all(ipaddress.ip_address(q) in net for q in ips), ips)
        self.assertEqual(len(w["internetdb"].queries()), 8)

    def test_prefix_limits_and_special_ranges(self):
        cfg = lambda s, lim=None: scope.parse_run_config(  # noqa: E731
            {"seeds": s, "approval_ref": "T", "limits": lim or {}}, allow_documentation_ranges=False)
        for bad in ("8.8.0.0/15", "100.64.0.0/24", "192.0.0.0/29", "10.0.0.0/8", "0.0.0.0/0", "8.8.8.8/33",
                    "8.8.8.1/24", "2001:db8::/32", "08.8.8.0/24", "8.8.8.0/024", "8.8.8.8:53", "8.8.8.8\x00",
                    "169.254.169.254", "224.0.0.0/24", "192.88.99.0/24"):
            with self.assertRaises(ScopeError, msg=bad):
                cfg(bad)
        with self.assertRaises(ScopeError):
            cfg("8.8.8.0/24", {"max_prefix_addresses": 255})
        with self.assertRaises(ScopeError):
            cfg("8.8.0.0/16", {"max_prefix_addresses": 70000})
        self.assertEqual(cfg("8.8.8.8/32").seeds[0].type, "ip")


class SeedParsing(unittest.TestCase):
    def parse(self, text):
        return scope.parse_seeds(text, "T")

    def test_wildcards_and_garbage_seeds_rejected(self):
        for bad in ("*.example.com", "*example.com", "example.*", "com", "co.uk", "com.", "http://example.com",
                    "example.com/path", "user@example.com", "example.com:443", "exa mple.com", "-example.com",
                    "1.2.3.4.", "2130706433", "x" * 64 + ".com"):
            with self.assertRaises(ScopeError, msg=bad):
                self.parse(bad)

    def test_common_second_level_public_suffixes_rejected_as_seeds(self):
        """ISSUE (scope.py PUBLIC_SUFFIXES ~line 71): only a handful of second-level public suffixes are known,
        so 'com.ar', 'co.za', 'com.tr', 'co.kr', 'ac.jp' or 'github.io' are accepted as a domain seed. Every
        name under them is then 'in scope': crt.sh is queried for '%.co.za' and every certificate name of every
        South African company is EXPANDed and resolved (up to max_hostnames). RULES.md 1 documents only 'a small
        built-in list', so this is a gap in the rule as much as the code; common sense: the list should cover at
        least the widely used ccTLD second levels (or the run should warn), because one mistyped seed turns a
        bounded engagement into country-wide enumeration."""
        accepted = []
        for suffix in ("com.ar", "co.za", "com.tr", "co.kr", "ac.jp", "gov.br", "github.io"):
            try:
                self.parse(suffix)
                accepted.append(suffix)
            except ScopeError:
                pass
        self.assertEqual(accepted, [])

    def test_homoglyph_seed_normalizes_to_punycode_not_ascii(self):
        seeds = self.parse("exаmple.com")  # Cyrillic a
        self.assertTrue(seeds[0].value.startswith("xn--"))
        policy = scope.ScopePolicy(scope.RunConfig(seeds=seeds, org_names=()))
        self.assertIsNone(policy.in_scope_domain("www.example.com"))


class AttributionScopeSanity(unittest.TestCase):
    def test_org_match_is_whole_word(self):
        self.assertIsNone(attribution.org_matches(["Corp"], {"org_names": ["MegaCorporation"], "network_name": None,
                                                             "entity_handles": [], "handle": None}))


if __name__ == "__main__":
    unittest.main()
