"""Regression tests for the cbk914/VulnCenter vulncenter.py remediation.

Run with:  python test_vulncenter.py
(or:       python -m unittest test_vulncenter -v)

Each test that targets a specific defect asserts on the ORIGINAL behaviour so
that it fails on the unpatched file and passes on the patched one.
"""
import importlib.util
import inspect
import os
import sys
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(HERE, "vulncenter.py")


def load_module():
    """Import vulncenter.py as a module, without running its CLI entrypoint."""
    spec = importlib.util.spec_from_file_location("vulncenter_under_test", TARGET)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeResponse(object):
    def __init__(self, content=b"real,data\n", status=200):
        self.content = content
        self.status = status

    def raise_for_status(self):
        if self.status >= 400:
            import requests
            raise requests.HTTPError("{} Server Error".format(self.status), response=self)


class TestModuleImportsCleanly(unittest.TestCase):
    """DEFECT: module-level code referenced `r` before binding it (NameError)."""

    def test_import_does_not_raise(self):
        # On the unpatched file this blows up either with
        #   NameError: name 'r' is not defined
        # or, because the downloads run first, with
        #   gzip.BadGzipFile: Not a gzipped file (b'<!')
        mod = load_module()
        self.assertTrue(hasattr(mod, "download_database"))

    def test_no_unbound_name_r_at_module_level(self):
        """The precise defect: `r` used at module scope but never bound there."""
        import ast
        with open(TARGET, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), TARGET)

        # Walk everything at module scope, descending into nested blocks
        # (if/for/while/try) but NOT into function or class bodies.
        bound = set()
        used = set()

        def visit(node):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef,
                                      ast.Lambda, ast.ClassDef)):
                    # Skip the body, but still count default args / decorators
                    # as module-scope references.
                    for d in getattr(child, "decorator_list", []):
                        visit(d)
                    for default in list(getattr(child, "defaults", []) or []):
                        visit(default)
                    continue
                if isinstance(child, ast.Name):
                    if isinstance(child.ctx, ast.Store):
                        bound.add(child.id)
                    else:
                        used.add(child.id)
                visit(child)

        visit(tree)

        unbound = used - bound
        self.assertNotIn("r", unbound,
                         "name 'r' is referenced at module scope but never bound -> NameError at import")

    def test_main_is_guarded(self):
        mod = load_module()
        self.assertTrue(hasattr(mod, "main"),
                        "expected side effects to move into main()")
        src = self._read()
        self.assertIn('if __name__ == "__main__":', src)

    @staticmethod
    def _read():
        with open(TARGET, encoding="utf-8") as fh:
            return fh.read()


class TestArityBugs(unittest.TestCase):
    """DEFECT: search_database() called with 3 args against a 2-arg signature."""

    def test_search_database_accepts_three_args(self):
        mod = load_module()
        # (redis_client, vulnerability_type, args.search)
        sig = inspect.signature(mod.search_database)
        self.assertEqual(len(sig.parameters), 3,
                         "search_database must take (r, vulnerability_type, search_string)")

    def test_update_database_accepts_four_args(self):
        mod = load_module()
        # call sites pass (redis_client, "cve", url, filename)
        sig = inspect.signature(mod.update_database)
        self.assertEqual(len(sig.parameters), 4,
                         "update_database must take (r, vulnerability_type, url, filename)")


class TestNetworkHardening(unittest.TestCase):
    """DEFECT: requests.get(url) had no timeout and no raise_for_status()."""

    def setUp(self):
        self.mod = load_module()
        self.calls = []

        self.real_get = self.mod.requests.get

        def fake_get(url, **kwargs):
            self.calls.append((url, kwargs))
            return FakeResponse()

        self.mod.requests.get = fake_get

    def tearDown(self):
        self.mod.requests.get = self.real_get

    def test_timeout_is_passed(self):
        import tempfile
        tmp = tempfile.mkdtemp()
        target = os.path.join(tmp, "out.bin")
        self.mod.download_database("https://example.invalid/x.csv", target)
        _url, kwargs = self.calls[0]
        self.assertIn("timeout", kwargs,
                      "requests.get() called without timeout -> can hang forever")
        self.assertGreater(kwargs["timeout"], 0)

    def test_html_response_is_rejected(self):
        import tempfile
        tmp = tempfile.mkdtemp()
        target = os.path.join(tmp, "exploitdb-FE.csv")
        # A GitLab /-/blob/ page: exactly what the old URLs returned.
        self.mod.requests.get = lambda url, **kw: FakeResponse(b"<!DOCTYPE html><html>...")
        with self.assertRaises(Exception) as ctx:
            self.mod.download_database("https://gitlab.com/x/-/blob/main/f.csv", target)
        self.assertNotIn("DOCTYPE", str(ctx.exception))
        self.assertFalse(os.path.exists(target),
                         "HTML error page was written to disk as a database")

    def test_http_error_is_raised(self):
        import tempfile
        tmp = tempfile.mkdtemp()
        target = os.path.join(tmp, "out.bin")
        self.mod.requests.get = lambda url, **kw: FakeResponse(b"nope", status=500)
        with self.assertRaises(Exception):
            self.mod.download_database("https://example.invalid/x", target)
        self.assertFalse(os.path.exists(target))


class TestGitlabUrlsAreRaw(unittest.TestCase):
    """DEFECT: three download_database() calls used GitLab /-/blob/ HTML pages."""

    def test_no_blob_urls_in_download_table(self):
        mod = load_module()
        urls = [u for _t, u, _f in mod.DATABASES]
        for url in urls:
            self.assertNotIn("/-/blob/", url,
                             "{} is an HTML web page, not a raw file".format(url))

    def test_exploitdb_urls_are_raw(self):
        mod = load_module()
        exploit = [u for _t, u, _f in mod.DATABASES
                   if "exploit-database" in u]
        self.assertEqual(len(exploit), 3)
        for url in exploit:
            self.assertIn("/-/raw/", url)

    def test_no_inline_download_calls_remain(self):
        with open(TARGET, encoding="utf-8") as fh:
            src = fh.read()
        # All downloads must go through the DATABASES table, not module scope.
        self.assertNotIn('download_database("https://gitlab.com', src)


class TestSearchDatabaseHandlesMissingField(unittest.TestCase):
    def test_missing_description_is_skipped(self):
        mod = load_module()

        class FakeRedis(object):
            def scan_iter(self, pattern):
                return iter(["vulnerability:1", "vulnerability:2"])

            def hget(self, key, field):
                return None if key == "vulnerability:1" else b"bluekeep rdp"

            def hgetall(self, key):
                return {key: b"data"}

        results = mod.search_database(FakeRedis(), "cve", "rdp")
        self.assertEqual(len(results), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)