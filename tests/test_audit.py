"""Audit-engine tests: BFS load order, binding, versions, weak symbols."""
import unittest

from elfaudit.audit import run_audit
from elfbuilder import ElfBuilder


def lib(name, soname=None, needed=(), symbols=()):
    b = ElfBuilder(soname=soname or name)
    for n in needed:
        b.need(n)
    for kw in symbols:
        b.symbol(**kw)
    return b.build()


def refs(verdict, symbol):
    return [r for r in verdict["references"] if r["symbol"] == symbol]


class LoadOrder(unittest.TestCase):
    def test_bfs_first_discovery_dedups_ring(self):
        # target -> [libb, libc]; libb -> [libd]; libc -> [libd];
        # libd -> [libb] (ring back).  BFS: libb, libc, libd.
        target = lib("fc.so", needed=("libb.so", "libc.so"))
        libb = lib("libb.so", needed=("libd.so",))
        libc = lib("libc.so", needed=("libd.so",))
        libd = lib("libd.so", needed=("libb.so",))
        verdict = run_audit("fc.so", target,
                            [("libb.so", libb), ("libc.so", libc),
                             ("libd.so", libd)])
        self.assertEqual(verdict["status"], "passed")
        self.assertEqual(verdict["load_order"],
                         ["fc.so", "libb.so", "libc.so", "libd.so"])

    def test_missing_dependency_rejected(self):
        target = lib("fc.so", needed=("liba.so",))
        verdict = run_audit("fc.so", target, [])
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["error"]["field"], "DT_NEEDED")
        self.assertIn("liba.so", verdict["error"]["message"])

    def test_duplicate_object_names_rejected(self):
        target = lib("fc.so", needed=("liba.so",))
        liba = lib("liba.so")
        verdict = run_audit("fc.so", target,
                            [("liba.so", liba), ("liba.so", liba)])
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["error"]["field"], "request")
        self.assertIn("duplicate", verdict["error"]["message"])

    def test_target_name_clash_rejected(self):
        target = lib("liba.so", needed=())
        verdict = run_audit("liba.so", target, [("liba.so", target)])
        self.assertEqual(verdict["status"], "rejected")

    def test_malformed_dependency_rejected_with_object_name(self):
        target = lib("fc.so", needed=("liba.so",))
        verdict = run_audit("fc.so", target, [("liba.so", b"\x7fELFgarbage")])
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["error"]["object"], "liba.so")


class Binding(unittest.TestCase):
    def test_unversioned_shadowing_picks_earlier_loaded(self):
        target = lib("fc.so", needed=("liba.so", "libb.so"),
                     symbols=(dict(name="log_emit", defined=False),))
        liba = lib("liba.so", symbols=(dict(name="log_emit", value=0x1111),))
        libb = lib("libb.so", symbols=(dict(name="log_emit", value=0x2222),))
        verdict = run_audit("fc.so", target,
                            [("liba.so", liba), ("libb.so", libb)])
        self.assertEqual(verdict["status"], "passed")
        (ref,) = refs(verdict, "log_emit")
        self.assertEqual(ref["status"], "bound")
        self.assertEqual(ref["resolution"]["object"], "liba.so")
        self.assertEqual(ref["resolution"]["symbol_index"], 1)
        self.assertEqual(ref["resolution"]["version_basis"],
                         {"kind": "unversioned"})

    def test_version_shadowing_picks_earlier_compatible(self):
        # libb impersonates liba via SONAME; both define nav_update@FC_2.0.
        target = lib("fc.so", needed=("liba.so", "libb.so"),
                     symbols=(dict(name="nav_update", defined=False,
                                   version="FC_2.0", version_file="liba.so"),))
        liba = lib("liba.so",
                   symbols=(dict(name="nav_update", version="FC_2.0"),))
        libb = lib("libb.so", soname="liba.so",
                   symbols=(dict(name="nav_update", version="FC_2.0"),))
        verdict = run_audit("fc.so", target,
                            [("liba.so", liba), ("libb.so", libb)])
        self.assertEqual(verdict["status"], "passed")
        (ref,) = refs(verdict, "nav_update")
        self.assertEqual(ref["requirement"],
                         {"version": "FC_2.0", "file": "liba.so"})
        self.assertEqual(ref["resolution"]["object"], "liba.so")
        self.assertEqual(ref["resolution"]["version_basis"],
                         {"kind": "verdef", "version": "FC_2.0", "index": 2})

    def test_version_shadowing_reversed_load_order(self):
        target = lib("fc.so", needed=("libb.so", "liba.so"),
                     symbols=(dict(name="nav_update", defined=False,
                                   version="FC_2.0", version_file="liba.so"),))
        liba = lib("liba.so",
                   symbols=(dict(name="nav_update", version="FC_2.0"),))
        libb = lib("libb.so", soname="liba.so",
                   symbols=(dict(name="nav_update", version="FC_2.0"),))
        verdict = run_audit("fc.so", target,
                            [("liba.so", liba), ("libb.so", libb)])
        (ref,) = refs(verdict, "nav_update")
        self.assertEqual(ref["resolution"]["object"], "libb.so")

    def test_version_mismatch_fails_strong_reference(self):
        target = lib("fc.so", needed=("liba.so",),
                     symbols=(dict(name="nav_update", defined=False,
                                   version="FC_9.9", version_file="liba.so"),))
        liba = lib("liba.so",
                   symbols=(dict(name="nav_update", version="FC_2.0"),))
        verdict = run_audit("fc.so", target, [("liba.so", liba)])
        self.assertEqual(verdict["status"], "failed")
        first = verdict["first_unresolved"]
        self.assertEqual(first["symbol"], "nav_update")
        self.assertIn("FC_9.9", first["reason"])

    def test_hidden_definition_not_visible(self):
        target = lib("fc.so", needed=("liba.so",),
                     symbols=(dict(name="alpha", defined=False),))
        liba = lib("liba.so",
                   symbols=(dict(name="alpha", visibility=2),))  # STV_HIDDEN
        verdict = run_audit("fc.so", target, [("liba.so", liba)])
        self.assertEqual(verdict["status"], "failed")
        self.assertIn("no visible definition",
                      verdict["first_unresolved"]["reason"])

    def test_weak_definition_satisfies_strong_reference(self):
        target = lib("fc.so", needed=("liba.so",),
                     symbols=(dict(name="alpha", defined=False),))
        liba = lib("liba.so", symbols=(dict(name="alpha", bind="WEAK"),))
        verdict = run_audit("fc.so", target, [("liba.so", liba)])
        self.assertEqual(verdict["status"], "passed")
        self.assertEqual(refs(verdict, "alpha")[0]["status"], "bound")

    def test_earlier_wrong_version_is_skipped(self):
        # liba loads first but only provides FC_1.0; libb provides the
        # required FC_2.0 and must win despite loading later.
        target = lib("fc.so", needed=("liba.so", "libb.so"),
                     symbols=(dict(name="nav_update", defined=False,
                                   version="FC_2.0", version_file="liba.so"),))
        liba = lib("liba.so",
                   symbols=(dict(name="nav_update", version="FC_1.0"),))
        libb = lib("libb.so", soname="liba.so",
                   symbols=(dict(name="nav_update", version="FC_2.0"),))
        verdict = run_audit("fc.so", target,
                            [("liba.so", liba), ("libb.so", libb)])
        self.assertEqual(verdict["status"], "passed")
        (ref,) = refs(verdict, "nav_update")
        self.assertEqual(ref["resolution"]["object"], "libb.so")
        self.assertEqual(ref["resolution"]["version_basis"]["version"], "FC_2.0")

    def test_hidden_version_skipped_for_later_default(self):
        # liba's only definition is a hidden (non-default) version; the
        # unversioned reference must bind to libb's default definition.
        target = lib("fc.so", needed=("liba.so", "libb.so"),
                     symbols=(dict(name="alpha", defined=False),))
        liba = lib("liba.so",
                   symbols=(dict(name="alpha", version="V1",
                                 hidden_version=True),))
        libb = lib("libb.so", symbols=(dict(name="alpha"),))
        verdict = run_audit("fc.so", target,
                            [("liba.so", liba), ("libb.so", libb)])
        self.assertEqual(verdict["status"], "passed")
        (ref,) = refs(verdict, "alpha")
        self.assertEqual(ref["resolution"]["object"], "libb.so")


class WeakSymbols(unittest.TestCase):
    def test_weak_unbound_is_not_fatal(self):
        target = lib("fc.so", needed=("liba.so",),
                     symbols=(dict(name="required_op", defined=False),
                              dict(name="optional_trace", defined=False,
                                   bind="WEAK")))
        liba = lib("liba.so", symbols=(dict(name="required_op"),))
        verdict = run_audit("fc.so", target, [("liba.so", liba)])
        self.assertEqual(verdict["status"], "passed")
        self.assertIsNone(verdict["first_unresolved"])
        (weak,) = refs(verdict, "optional_trace")
        self.assertEqual(weak["status"], "unbound")
        self.assertEqual(weak["bind"], "WEAK")
        self.assertIn("no visible definition", weak["reason"])
        (strong,) = refs(verdict, "required_op")
        self.assertEqual(strong["status"], "bound")
        self.assertEqual(strong["resolution"]["object"], "liba.so")

    def test_strong_unbound_fails_with_first_reason(self):
        target = lib("fc.so", needed=("liba.so",),
                     symbols=(dict(name="missing_op", defined=False),))
        liba = lib("liba.so")
        verdict = run_audit("fc.so", target, [("liba.so", liba)])
        self.assertEqual(verdict["status"], "failed")
        first = verdict["first_unresolved"]
        self.assertEqual(first["symbol"], "missing_op")
        self.assertEqual(first["object"], "fc.so")
        self.assertEqual(first["symbol_index"], 1)
        self.assertIn("no visible definition", first["reason"])

    def test_first_unresolved_follows_load_order(self):
        # Two unbound strong refs in different objects: the one in the
        # earlier-loaded object is reported first.
        target = lib("fc.so", needed=("liba.so",),
                     symbols=(dict(name="zzz_missing", defined=False),))
        liba = lib("liba.so", symbols=(dict(name="aaa_missing", defined=False),))
        verdict = run_audit("fc.so", target, [("liba.so", liba)])
        self.assertEqual(verdict["status"], "failed")
        self.assertEqual(verdict["first_unresolved"]["symbol"], "zzz_missing")


if __name__ == "__main__":
    unittest.main()
