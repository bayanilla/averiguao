"""Tests for averiguao_core.scope (RULES.md sections 1 and 2)."""

from __future__ import annotations

import hashlib
import ipaddress
import random
import unittest

from averiguao_core.contracts import HARD_MAX_PREFIX_ADDRESSES, Limits, RunConfig, ScopeDecision, Seed
from averiguao_core.scope import (
    DOCUMENTATION_NETWORKS,
    PUBLIC_SUFFIXES,
    SPECIAL_PURPOSE_NETWORKS,
    ScopeError,
    ScopePolicy,
    normalize_hostname,
    parse_inventory,
    parse_run_config,
    parse_seeds,
    run_config_from_dict,
)

REF = "TICKET-1"


def seeds(text: str, **kw):
    return parse_seeds(text, REF, **kw)


def one(text: str, **kw) -> Seed:
    result = seeds(text, **kw)
    assert len(result) == 1, result
    return result[0]


class SeedIPTests(unittest.TestCase):
    def assertRejected(self, text: str, fragment: str = "", **kw):
        with self.assertRaises(ScopeError) as cm:
            seeds(text, **kw)
        if fragment:
            self.assertIn(fragment, str(cm.exception))
        return str(cm.exception)

    def test_regression_slash_zero_and_one(self):
        # The old parser accepted these as 0.0.0.0/0 and 128.0.0.0/1.
        self.assertRejected("8.8.8.8/0")
        self.assertRejected("200.1.2.3/1")
        self.assertRejected("0.0.0.0/0", "0.0.0.0/8")
        self.assertRejected("128.0.0.0/1")
        self.assertRejected("0.0.0.0/1")

    def test_host_bits_rejected(self):
        msg = self.assertRejected("8.8.8.7/24", "host bits")
        self.assertIn("8.8.8.0/24", msg)
        self.assertRejected("198.51.100.7/24", "host bits", allow_documentation_ranges=True)

    def test_slash_32_becomes_ip(self):
        s = one("8.8.8.8/32")
        self.assertEqual((s.type, s.value), ("ip", "8.8.8.8"))

    def test_ip_and_prefix_canonical(self):
        self.assertEqual(one(" 8.8.8.8 ").value, "8.8.8.8")
        s = one("8.8.8.0/24")
        self.assertEqual((s.type, s.value), ("prefix", "8.8.8.0/24"))

    def test_overlap_via_wider_prefix(self):
        # 192.168.0.0/15 is "global" at both ends per is_global, but overlaps 192.168.0.0/16.
        self.assertRejected("192.168.0.0/15", "192.168.0.0/16", max_prefix_addresses=HARD_MAX_PREFIX_ADDRESSES)
        self.assertRejected("192.168.0.0/16", "192.168.0.0/16", max_prefix_addresses=HARD_MAX_PREFIX_ADDRESSES)
        self.assertRejected("100.64.0.0/16", "100.64.0.0/10", max_prefix_addresses=HARD_MAX_PREFIX_ADDRESSES)

    def test_special_addresses_rejected(self):
        for addr, block in [("10.1.2.3", "10.0.0.0/8"), ("127.0.0.1", "127.0.0.0/8"), ("100.64.0.1", "100.64"),
                            ("169.254.1.1", "169.254"), ("172.31.255.255", "172.16"), ("192.0.0.9", "192.0.0.0/24"),
                            ("192.88.99.1", "192.88.99"), ("198.19.0.1", "198.18"), ("224.0.0.1", "224"),
                            ("239.255.255.255", "224"), ("240.0.0.1", "240"), ("255.255.255.255", "255.255.255.255"),
                            ("0.0.0.0", "0.0.0.0/8"), ("192.0.2.1", "192.0.2.0/24"),
                            ("198.51.100.1", "198.51.100.0/24"), ("203.0.113.5", "203.0.113.0/24")]:
            with self.subTest(addr=addr):
                self.assertRejected(addr, block)

    def test_adjacent_global_ranges_accepted(self):
        for addr in ("9.255.255.255", "11.0.0.0", "100.63.255.255", "100.128.0.0", "172.15.255.255",
                     "172.32.0.0", "192.167.255.255", "192.169.0.0", "223.255.255.255", "1.1.1.1"):
            with self.subTest(addr=addr):
                self.assertEqual(one(addr).type, "ip")

    def test_documentation_ranges_allowed_when_flagged(self):
        s = one("198.51.100.0/24", allow_documentation_ranges=True)
        self.assertEqual(s.type, "prefix")
        self.assertEqual(one("203.0.113.7", allow_documentation_ranges=True).value, "203.0.113.7")
        self.assertEqual(one("192.0.2.0/25", allow_documentation_ranges=True).value, "192.0.2.0/25")
        # Still rejects other special blocks, including those adjacent to documentation ranges.
        self.assertRejected("192.0.0.0/22", "192.0.0.0/24", allow_documentation_ranges=True)
        self.assertRejected("198.50.0.0/15", "198.51.100.0/24")
        self.assertRejected("10.0.0.1", "10.0.0.0/8", allow_documentation_ranges=True)

    def test_ipv6_rejected(self):
        for text in ("2001:db8::1", "2606:4700::/32", "::ffff:8.8.8.8"):
            with self.subTest(text=text):
                self.assertRejected(text, "IPv6")

    def test_oversized_prefix(self):
        self.assertRejected("8.8.0.0/16", "limit is 4096")
        self.assertEqual(one("8.8.0.0/20").value, "8.8.0.0/20")
        self.assertEqual(one("8.8.0.0/16", max_prefix_addresses=65536).value, "8.8.0.0/16")
        self.assertRejected("8.0.0.0/15", max_prefix_addresses=65536)
        with self.assertRaises(ScopeError):
            seeds("8.8.8.8", max_prefix_addresses=HARD_MAX_PREFIX_ADDRESSES + 1)
        with self.assertRaises(ScopeError):
            seeds("8.8.8.8", max_prefix_addresses=0)

    def test_malformed_ip(self):
        for text in ("256.1.1.1", "1.2.3.4/33", "1.2.3.4/", "1.2.3.0/24/1", "01.2.3.4", "1.2.3.0/255.255.255.0",
                     "1.2.3"):
            with self.subTest(text=text):
                self.assertRejected(text)

    def test_line_numbers_in_errors(self):
        self.assertRejected("example.com\n\n# c\n10.0.0.1\n", "line 4")


class SeedDomainTests(unittest.TestCase):
    def test_normalization(self):
        s = one("Example.COM.")
        self.assertEqual((s.type, s.value, s.id, s.approval_ref, s.scope_version),
                         ("domain", "example.com", "seed:1", REF, "1"))

    def test_idna(self):
        self.assertEqual(one("Bücher.de").value, "xn--bcher-kva.de")
        self.assertEqual(one("xn--bcher-kva.de").value, "xn--bcher-kva.de")
        self.assertEqual(one("münchen.xn--p1ai").value, "xn--mnchen-3ya.xn--p1ai")

    def test_public_suffix_rejected(self):
        for text in ("co.uk", "CO.UK.", "com.au", "co.jp", "org.uk"):
            with self.subTest(text=text):
                with self.assertRaises(ScopeError) as cm:
                    seeds(text)
                self.assertIn("public suffix", str(cm.exception))
        for text in ("com", "test", "localhost", "example"):  # single label: invalid regardless
            with self.subTest(text=text), self.assertRaises(ScopeError):
                seeds(text)

    def test_suffix_like_seeds_allowed(self):
        self.assertEqual(one("example.com").value, "example.com")
        self.assertEqual(one("foo.test").value, "foo.test")
        self.assertEqual(one("example.co.uk").value, "example.co.uk")

    def test_invalid_domains(self):
        bad = ["*.example.com", "ex*ample.com", "-a.com", "a-.com", "a..com", ".com", "a_b.com", "a b.com",
               "a" * 64 + ".com", ".".join(["a" * 63] * 4) + ".com", "example.123", "example.c0m", "http://a.com",
               "a.com/x", "a.com..", "", "1.2.3.4.5"]
        for text in bad:
            with self.subTest(text=text):
                with self.assertRaises(ScopeError):
                    parse_seeds(text or "\n", REF)

    def test_length_boundaries(self):
        ok = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 57]) + ".com"  # 253 chars
        self.assertEqual(len(ok), 253)
        self.assertEqual(one(ok).value, ok)
        with self.assertRaises(ScopeError):
            seeds("a" + ok)

    def test_ordering_comments_and_dedup(self):
        result = seeds("# header\nexample.com\n\nEXAMPLE.com.\n8.8.8.8\n8.8.8.8/32\nexample.org\n")
        self.assertEqual([(s.id, s.type, s.value) for s in result],
                         [("seed:1", "domain", "example.com"), ("seed:2", "ip", "8.8.8.8"),
                          ("seed:3", "domain", "example.org")])

    def test_counts_and_approval(self):
        with self.assertRaises(ScopeError):
            seeds("# only a comment\n\n")
        with self.assertRaises(ScopeError):
            parse_seeds("example.com", "  ")
        with self.assertRaises(ScopeError):
            parse_seeds("example.com", "x" * 201)
        self.assertEqual(parse_seeds("example.com", "x" * 200)[0].approval_ref, "x" * 200)
        fifty = "\n".join(f"d{i}.example.com" for i in range(50))
        self.assertEqual(len(seeds(fifty)), 50)
        with self.assertRaises(ScopeError) as cm:
            seeds(fifty + "\nd50.example.com")
        self.assertIn("line 51", str(cm.exception))
        self.assertEqual(parse_seeds("example.com", REF, "v2")[0].scope_version, "v2")


class NormalizeHostnameTests(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(normalize_hostname("WWW.Example.COM."), "www.example.com")
        self.assertEqual(normalize_hostname("  a.b.example.com "), "a.b.example.com")
        self.assertEqual(normalize_hostname("bücher.example"), "xn--bcher-kva.example")

    def test_wildcards(self):
        self.assertEqual(normalize_hostname("*.Example.COM."), "*.example.com")
        self.assertEqual(normalize_hostname("*.bücher.de"), "*.xn--bcher-kva.de")
        for bad in ("*", "*.", "*.com", "a.*.example.com", "*a.example.com", "**.example.com", "*.*.example.com"):
            with self.subTest(bad=bad):
                self.assertIsNone(normalize_hostname(bad))

    def test_invalid(self):
        for bad in ("", ".", "localhost", "1.2.3.4", "a..b.com", "-x.com", "x-.com", "a_b.example.com",
                    "exa mple.com", None, 5, "a" * 64 + ".com"):
            with self.subTest(bad=bad):
                self.assertIsNone(normalize_hostname(bad))  # type: ignore[arg-type]


def make_config(text="example.com\nexample.org", max_depth=2):
    return RunConfig(seeds=seeds(text), org_names=("Example Inc",), limits=Limits(max_depth=max_depth))


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = ScopePolicy(make_config())

    def test_in_scope_domain(self):
        p = self.policy
        self.assertEqual(p.in_scope_domain("example.com"), "example.com")
        self.assertEqual(p.in_scope_domain("A.B.Example.COM."), "example.com")
        self.assertEqual(p.in_scope_domain("x.example.org"), "example.org")
        for name in ("example.com.evil.test", "notexample.com", "example.com-x.test", "xexample.com",
                     "example.co", "com", "example.net", "*.example.com", "", "1.2.3.4", "example.com.evil"):
            with self.subTest(name=name):
                self.assertIsNone(p.in_scope_domain(name))

    def test_most_specific_seed(self):
        p = ScopePolicy(make_config("example.com\nsub.example.com"))
        self.assertEqual(p.in_scope_domain("a.sub.example.com"), "sub.example.com")
        self.assertEqual(p.in_scope_domain("a.example.com"), "example.com")

    def test_decide_table(self):
        p = self.policy
        D = ScopeDecision
        cases = [
            ("certificate_mentions_hostname", "www.example.com", 1, D.EXPAND, "in_scope"),
            ("certificate_mentions_hostname", "www.example.com", 2, D.EXPAND, "in_scope"),
            ("certificate_mentions_hostname", "www.example.com", 3, D.DENY, "depth_limit"),
            ("certificate_mentions_hostname", "www.example.net", 1, D.DENY, "ct_name_outside_approved_domains"),
            ("certificate_mentions_hostname", "example.com.evil.test", 1, D.DENY,
             "ct_name_outside_approved_domains"),
            ("certificate_mentions_hostname", "*.example.com", 1, D.DENY, "ct_name_outside_approved_domains"),
            ("certificate_mentions_hostname", "bad_name.example.com", 1, D.DENY,
             "ct_name_outside_approved_domains"),
            ("hostname_resolves_to_ip", "8.8.8.8", 1, D.RECORD, "in_scope"),
            ("hostname_resolves_to_ip", "8.8.8.8", 2, D.RECORD, "in_scope"),
            ("hostname_resolves_to_ip", "8.8.8.8", 3, D.DENY, "depth_limit"),
            ("ip_reports_hostname", "api.example.org", 2, D.RECORD, "in_scope"),
            ("ip_reports_hostname", "api.example.org", 3, D.DENY, "depth_limit"),
            ("ip_reports_hostname", "other-tenant.net", 2, D.CONTEXT, "hostname_outside_approved_domains"),
            ("ip_reports_hostname", "other-tenant.net", 9, D.CONTEXT, "hostname_outside_approved_domains"),
            ("prefix_contains_ip", "8.8.8.1", 1, D.RECORD, "prefix_member"),
            ("rdap_enrichment", "8.8.8.8", 1, D.CONTEXT, "enrichment_only"),
            ("rdap_enrichment", "8.8.8.8", 99, D.CONTEXT, "enrichment_only"),
            ("cname_target", "cdn.provider.net", 1, D.CONTEXT, "cname_context"),
        ]
        for pred, obj, depth, decision, reason in cases:
            with self.subTest(pred=pred, obj=obj, depth=depth):
                d = p.decide(pred, obj, depth)
                self.assertEqual((d.decision, d.reason), (decision, reason))

    def test_depth_follows_limit(self):
        p = ScopePolicy(make_config(max_depth=1))
        self.assertEqual(p.decide("certificate_mentions_hostname", "a.example.com", 1).decision,
                         ScopeDecision.EXPAND)
        self.assertEqual(p.decide("hostname_resolves_to_ip", "8.8.8.8", 2).reason, "depth_limit")

    def test_unknown_predicate(self):
        with self.assertRaises(ValueError):
            self.policy.decide("seed_is", "x", 0)

    def test_prefix_addresses(self):
        p = ScopePolicy(RunConfig(seeds=seeds("8.8.8.0/30\nexample.com"), org_names=()))
        self.assertEqual(p.prefix_addresses(p.config.seeds[0]), ["8.8.8.0", "8.8.8.1", "8.8.8.2", "8.8.8.3"])
        self.assertEqual(len(p.prefix_addresses(one("8.8.0.0/20"))), 4096)
        with self.assertRaises(ValueError):
            p.prefix_addresses(p.config.seeds[1])


class RunConfigTests(unittest.TestCase):
    def body(self, **kw):
        b = {"seeds": "example.com\n8.8.8.0/24", "approval_ref": REF}
        b.update(kw)
        return b

    def test_defaults(self):
        cfg = parse_run_config(self.body())
        self.assertEqual(cfg.limits, Limits())
        self.assertEqual(cfg.org_names, ())
        self.assertEqual(cfg.label, "")
        self.assertTrue(cfg.match_rules.prefix_containment)
        self.assertFalse(cfg.match_rules.domain_hierarchy)
        self.assertEqual(cfg.seeds[0].scope_version, "1")

    def test_org_names(self):
        cfg = parse_run_config(self.body(org_names=" Example Inc , example inc,EXAMPLE-NET ,, "))
        self.assertEqual(cfg.org_names, ("Example Inc", "EXAMPLE-NET"))
        cfg = parse_run_config(self.body(org_names=["Acme", "ACME", " Acme Corp "]))
        self.assertEqual(cfg.org_names, ("Acme", "Acme Corp"))
        for bad in (["A"], ["x" * 101], [f"org{i}" for i in range(21)], 5, [1]):
            with self.subTest(bad=bad), self.assertRaises(ScopeError):
                parse_run_config(self.body(org_names=bad))

    def test_limits(self):
        cfg = parse_run_config(self.body(limits={"max_depth": 3, "max_prefix_addresses": 65536,
                                                 "max_queries": 200000, "max_seconds": 86400},
                                         seeds="8.8.0.0/16"))
        self.assertEqual(cfg.limits.max_depth, 3)
        self.assertEqual(cfg.seeds[0].value, "8.8.0.0/16")
        bad = [{"max_depth": 0}, {"max_depth": 4}, {"max_seconds": 86401}, {"max_queries": 200001},
               {"max_prefix_addresses": 65537}, {"max_hostnames": 0}, {"max_addresses": -1},
               {"max_depth": True}, {"max_depth": "2"}, {"max_depth": 2.0}, {"bogus": 1}, "x"]
        for limits in bad:
            with self.subTest(limits=limits), self.assertRaises(ScopeError):
                parse_run_config(self.body(limits=limits))
        # Raised prefix limit is applied to seeds; default rejects a /16.
        with self.assertRaises(ScopeError):
            parse_run_config(self.body(seeds="8.8.0.0/16"))

    def test_match_rules(self):
        cfg = parse_run_config(self.body(match_rules={"prefix_containment": False, "domain_hierarchy": True}))
        self.assertEqual((cfg.match_rules.prefix_containment, cfg.match_rules.domain_hierarchy), (False, True))
        for bad in ({"exact": False}, {"other": True}, {"domain_hierarchy": "yes"}):
            with self.subTest(bad=bad), self.assertRaises(ScopeError):
                parse_run_config(self.body(match_rules=bad))

    def test_required_fields(self):
        for body in ({"seeds": "example.com"}, {"seeds": "", "approval_ref": REF},
                     {"approval_ref": REF}, {"seeds": 5, "approval_ref": REF}, [], self.body(label=5),
                     self.body(label="x" * 201)):
            with self.subTest(body=body), self.assertRaises(ScopeError):
                parse_run_config(body)  # type: ignore[arg-type]

    def test_documentation_flag(self):
        with self.assertRaises(ScopeError):
            parse_run_config(self.body(seeds="198.51.100.0/24"))
        cfg = parse_run_config(self.body(seeds="198.51.100.0/24"), allow_documentation_ranges=True)
        self.assertEqual(cfg.seeds[0].value, "198.51.100.0/24")

    def test_round_trip(self):
        cfg = parse_run_config(self.body(org_names="Example Inc,Other", label="Q4 run", scope_version="v3",
                                         limits={"max_depth": 1, "max_hostnames": 10},
                                         match_rules={"domain_hierarchy": True}))
        data = cfg.to_dict()
        back = run_config_from_dict(data)
        self.assertEqual(back, cfg)
        self.assertIsInstance(back.seeds, tuple)
        self.assertIsInstance(back.org_names, tuple)
        self.assertEqual(back.to_dict(), data)
        import json
        self.assertEqual(run_config_from_dict(json.loads(json.dumps(data))), cfg)


class InventoryTests(unittest.TestCase):
    def test_kinds_and_normalization(self):
        snap = parse_inventory("value,label\n10.0.0.1,core\n192.168.0.0/16,lan\nWWW.Example.com.,web\n"
                               "*.Example.ORG,tree\n8.8.8.8/32,dns\n", label=" baseline ")
        self.assertEqual([(e.id, e.kind, e.value, e.label) for e in snap.entries], [
            ("inv:1", "ip", "10.0.0.1", "core"),
            ("inv:2", "cidr", "192.168.0.0/16", "lan"),
            ("inv:3", "hostname", "www.example.com", "web"),
            ("inv:4", "domain_tree", "example.org", "tree"),
            ("inv:5", "cidr", "8.8.8.8/32", "dns"),
        ])
        self.assertEqual(snap.label, "baseline")
        self.assertEqual(snap.as_of, snap.imported_at)

    def test_header_variants(self):
        for header in ("value", "IP", "ip_or_cidr", "cidr", "Network", "asset", " value "):
            with self.subTest(header=header):
                snap = parse_inventory(f"{header},label\n8.8.8.8,x\n")
                self.assertEqual(len(snap.entries), 1)
        self.assertEqual(len(parse_inventory("8.8.8.8,x\n1.1.1.1,y\n").entries), 2)
        with self.assertRaises(ScopeError):  # header-like word on a later row is just a bad value
            parse_inventory("8.8.8.8,x\nvalue,label\n")

    def test_header_after_blank_lines_and_bom(self):
        snap = parse_inventory("﻿\n\nip,label\n8.8.8.8\n")
        self.assertEqual([(e.value, e.label) for e in snap.entries], [("8.8.8.8", "")])

    def test_quoting_and_label_whitespace(self):
        snap = parse_inventory('"8.8.8.8","Google, public\nDNS"\n"example.com",\n')
        self.assertEqual(snap.entries[0].label, "Google, public DNS")
        self.assertEqual(snap.entries[1].label, "")

    def test_duplicates_keep_first(self):
        snap = parse_inventory("8.8.8.8,first\n8.8.8.8,second\nexample.com,h\n*.example.com,t\nEXAMPLE.com.,dup\n")
        self.assertEqual([(e.id, e.kind, e.value, e.label) for e in snap.entries], [
            ("inv:1", "ip", "8.8.8.8", "first"),
            ("inv:2", "hostname", "example.com", "h"),
            ("inv:3", "domain_tree", "example.com", "t"),
        ])

    def test_bad_rows_name_lines(self):
        cases = {
            "value,label\n8.8.8.8,a\n8.8.8.7/24,b\n": "line 3",
            "8.8.8.8,a\n\n2001:db8::1,b\n": "line 3",
            "8.8.8.8,a,extra\n": "line 1",
            'a.com,"multi\nline"\nbad_host!,x\n': "line 3",
            "*.com,x\n": "line 1",
            "a.*.example.com,x\n": "line 1",
            "999.1.1.1,x\n": "line 1",
            ",label only\n": "line 1",
        }
        for text, fragment in cases.items():
            with self.subTest(text=text):
                with self.assertRaises(ScopeError) as cm:
                    parse_inventory(text)
                self.assertIn(fragment, str(cm.exception))

    def test_trailing_empty_columns_and_comments(self):
        snap = parse_inventory("8.8.8.8,a,,\n# comment,x\n")
        self.assertEqual(len(snap.entries), 1)

    def test_row_limit(self):
        rows = "\n".join(f"10.{i // 256 % 256}.{i % 256}.1,x" for i in range(10_000))
        self.assertEqual(len(parse_inventory(rows).entries), 10_000)
        self.assertEqual(len(parse_inventory(rows + "\n10.0.0.1,dup\n").entries), 10_000)
        with self.assertRaises(ScopeError) as cm:
            parse_inventory(rows + "\n11.0.0.1,extra\n")
        self.assertIn("line 10001", str(cm.exception))

    def test_empty(self):
        snap = parse_inventory("", label="empty baseline")
        self.assertEqual(snap.entries, ())
        self.assertEqual(snap.id, "snap:" + hashlib.sha256(b"").hexdigest()[:16])

    def test_snapshot_id(self):
        a = parse_inventory("8.8.8.8,x\nexample.com,y\n", label="a")
        b = parse_inventory("value,label\n 8.8.8.8 , x \nEXAMPLE.COM.,y\n", label="b", as_of="2026-01-01")
        c = parse_inventory("8.8.8.8,x\nexample.com,z\n")
        self.assertEqual(a.id, b.id)
        self.assertNotEqual(a.id, c.id)
        expected = hashlib.sha256(b"ip,8.8.8.8,x\nhostname,example.com,y\n").hexdigest()[:16]
        self.assertEqual(a.id, f"snap:{expected}")

    def test_as_of(self):
        self.assertEqual(parse_inventory("", as_of="2026-10-01T12:00:00Z").as_of, "2026-10-01T12:00:00+00:00")
        self.assertEqual(parse_inventory("", as_of="2026-10-01T12:00:00+02:00").as_of,
                         "2026-10-01T10:00:00+00:00")
        self.assertEqual(parse_inventory("", as_of="2026-10-01").as_of, "2026-10-01T00:00:00+00:00")
        self.assertEqual(parse_inventory("", as_of="2026-10-01T12:00:00.123456").as_of,
                         "2026-10-01T12:00:00+00:00")
        for bad in ("yesterday", "2026-13-01", "10/01/2026"):
            with self.subTest(bad=bad), self.assertRaises(ScopeError):
                parse_inventory("", as_of=bad)


class SpecialPurposeCoverageTests(unittest.TestCase):
    def test_covers_ipaddress_private_networks(self):
        consts = getattr(ipaddress, "_IPv4Constants", None)
        private = list(getattr(consts, "_private_networks", [])) + [ipaddress.IPv4Network("100.64.0.0/10"),
                                                                      ipaddress.IPv4Network("224.0.0.0/4")]
        blocks = [b for b, _ in SPECIAL_PURPOSE_NETWORKS]
        for net in private:
            with self.subTest(net=str(net)):
                self.assertTrue(any(net.subnet_of(b) for b in blocks))

    def test_public_suffix_list(self):
        for s in ("com", "co.uk", "test", "example", "localhost"):
            self.assertIn(s, PUBLIC_SUFFIXES)

    def test_second_level_and_private_suffixes_rejected_as_seeds(self):
        rejected = ("com.ar", "co.za", "com.tr", "co.kr", "ac.jp", "gov.br", "or.jp", "ne.jp", "go.kr", "co.id",
                    "com.ng", "edu.pk", "gob.mx", "net.in", "org.ua", "mil.br", "co.nz", "com.vn",
                    "github.io", "gitlab.io", "herokuapp.com", "azurewebsites.net", "cloudfront.net",
                    "amazonaws.com", "appspot.com", "firebaseapp.com", "web.app", "pages.dev", "workers.dev",
                    "netlify.app", "vercel.app", "blogspot.com", "wordpress.com", "s3.amazonaws.com",
                    "cloudapp.net", "trafficmanager.net", "azureedge.net", "fastly.net", "myshopify.com")
        for text in rejected:
            with self.subTest(text=text):
                with self.assertRaises(ScopeError) as cm:
                    parse_seeds(text.upper() + ".", REF)
                self.assertIn("public suffix", str(cm.exception))
        for text in ("example.com.ar", "acme.co.za", "acme.github.io", "shop.myshopify.com", "acme.co.kr",
                     "google.com", "bbc.co.uk", "or.de", "go.com"):
            with self.subTest(text=text):
                self.assertEqual(parse_seeds(text, REF)[0].value, text)

    def test_private_suffix_inventory_tree_rejected(self):
        with self.assertRaises(ScopeError):
            parse_inventory("*.github.io,x\n")
        self.assertEqual(parse_inventory("*.acme.github.io,x\n").entries[0].value, "acme.github.io")

    def test_is_special_purpose(self):
        from averiguao_core.scope import is_special_purpose
        for ip in ("10.0.0.1", "192.168.1.1", "100.64.0.1", "127.0.0.1", "224.0.0.5", "255.255.255.255",
                   "192.0.0.8", "0.0.0.0", "11.0.0.0/7", "192.168.0.0/15", "2001:db8::1", "bogus", ""):
            with self.subTest(ip=ip):
                self.assertTrue(is_special_purpose(ip))
        for ip in ("8.8.8.8", "1.1.1.1", "8.8.8.0/24", "100.128.0.1"):
            with self.subTest(ip=ip):
                self.assertFalse(is_special_purpose(ip))
        for ip in ("198.51.100.7", "203.0.113.0/24", "192.0.2.1"):
            with self.subTest(ip=ip):
                self.assertTrue(is_special_purpose(ip))
                self.assertFalse(is_special_purpose(ip, allow_documentation_ranges=True))
        self.assertTrue(is_special_purpose("10.0.0.1", allow_documentation_ranges=True))


class PropertyTests(unittest.TestCase):
    def test_random_cidrs(self):
        rng = random.Random(20261016)
        blocks = [b for b, _ in SPECIAL_PURPOSE_NETWORKS]
        non_doc = [b for b in blocks if b not in DOCUMENTATION_NETWORKS]
        accepted = rejected = 0
        for _ in range(2000):
            plen = rng.randint(0, 32)
            addr = ipaddress.IPv4Address(rng.getrandbits(32))
            if rng.random() < 0.7:  # mostly valid network addresses so many get past the host-bit check
                addr = ipaddress.IPv4Network((addr, plen), strict=False).network_address
            text = f"{addr}/{plen}"
            limit = rng.choice([256, 4096, HARD_MAX_PREFIX_ADDRESSES])
            doc = rng.random() < 0.2
            try:
                result = parse_seeds(text, REF, max_prefix_addresses=limit, allow_documentation_ranges=doc)
            except ScopeError:
                rejected += 1
                continue
            accepted += 1
            (seed,) = result
            net = ipaddress.IPv4Network(seed.value)
            self.assertEqual(net, ipaddress.IPv4Network(text))
            self.assertLessEqual(net.num_addresses, limit)
            self.assertLessEqual(net.num_addresses, HARD_MAX_PREFIX_ADDRESSES)
            for b in (non_doc if doc else blocks):
                self.assertFalse(net.overlaps(b), f"{text} overlaps {b}")
            self.assertEqual(seed.type, "ip" if net.prefixlen == 32 else "prefix")
        self.assertGreater(accepted, 100)
        self.assertGreater(rejected, 100)


if __name__ == "__main__":
    unittest.main()
