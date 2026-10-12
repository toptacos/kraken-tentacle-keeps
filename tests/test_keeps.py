#!/usr/bin/env python3
"""keeps contract tests. Every case runs offline against a temp KRAKEN_HOME.

No live vendor calls. The suite runs twice per CI job, once per cipher
backend, because the store format must not depend on which one sealed it.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

BACKENDS = ["cryptography", "vendored-aesgcm"]


def invoke(action, payload=None, env=None, backend=None, raw=None):
    run = os.environ.copy()
    run["KRAKEN_OFFLINE"] = "1"
    if backend:
        run["KRAKEN_KEEPS_BACKEND"] = backend
    if env:
        run.update(env)
    body = (
        raw
        if raw is not None
        else json.dumps(
            {"v": 1, "id": None, "action": action, "payload": payload or {}}
        )
    )
    proc = subprocess.run(
        ["sh", str(ROOT / "handler.sh")],
        input=body,
        text=True,
        capture_output=True,
        env=run,
        check=False,
    )
    lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("{")]
    if not lines:
        raise AssertionError(
            f"no JSON on stdout: rc={proc.returncode} err={proc.stderr[:400]}"
        )
    return json.loads(lines[-1])


class Base:
    """Shared helpers. Deliberately NOT a TestCase.

    pytest collects every ``unittest.TestCase`` subclass regardless of its
    name, so the abstract body must stay a plain mixin. Otherwise the
    unparameterized base runs once with ``backend=None`` and every assertion
    about the cipher engine is wrong.
    """

    backend = None

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.env = {"KRAKEN_HOME": self.home}
        self.store = Path(self.home) / ".kraken" / "data" / "keeps"

    def call(self, action, payload=None, **kw):
        kw.setdefault("env", self.env)
        kw.setdefault("backend", self.backend)
        return invoke(action, payload, **kw)

    def put(self, name, value, **kw):
        return self.call("put", {"name": name, "value": value}, **kw)

    def leak_free(self, needle, *paths):
        for p in paths:
            self.assertNotIn(needle.encode(), p.read_bytes())


class KeepsContract(Base):
    """Behaviour that must hold for every cipher backend.

    Bound to a concrete TestCase per backend at the bottom of this module.
    """

    def test_ping(self):
        r = self.call("ping")
        self.assertTrue(r["ok"])
        self.assertEqual(r["result"]["arm"], "keeps")
        self.assertEqual(r["result"]["cipher"], "AES-256-GCM")
        self.assertEqual(r["result"]["engine"], self.backend)
        self.assertEqual(r["result"]["fetches"], 0)

    def test_empty_stdin_pings(self):
        self.assertTrue(invoke("", raw="", env=self.env, backend=self.backend)["ok"])

    def test_unknown_action(self):
        self.assertEqual(self.call("scrape")["error"]["code"], "unknown_action")

    def test_bad_stdin_is_one_error_object(self):
        r = invoke("", raw="{not json", env=self.env, backend=self.backend)
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"]["code"], "bad_request")

    def test_put_get_roundtrip(self):
        self.assertTrue(self.put("openai", "sk-test-123")["ok"])
        r = self.call("get", {"name": "openai", "reveal": True})
        self.assertEqual(r["result"]["value"], "sk-test-123")
        self.assertTrue(r["result"]["revealed"])

    def test_get_masks_by_default(self):
        self.put("openai", "sk-test-123")
        r = self.call("get", {"name": "openai"})
        self.assertEqual(r["result"]["value"], "•" * 4)
        self.assertFalse(r["result"]["revealed"])
        self.assertNotIn("sk-test-123", json.dumps(r))

    def test_list_never_carries_values(self):
        self.put("openai", "sk-test-123")
        self.put("github.token", "ghp-abc")
        r = self.call("list")
        self.assertEqual(r["result"]["count"], 2)
        self.assertEqual(
            [e["name"] for e in r["result"]["entries"]], ["github.token", "openai"]
        )
        blob = json.dumps(r)
        self.assertNotIn("sk-test-123", blob)
        self.assertNotIn("ghp-abc", blob)
        self.assertNotIn("nonce_sealed", blob)

    def test_has_reports_existence_only(self):
        self.put("openai", "x")
        self.assertTrue(self.call("has", {"name": "openai"})["result"]["exists"])
        self.assertFalse(self.call("has", {"name": "nope"})["result"]["exists"])

    def test_at_rest_is_sealed(self):
        self.put("openai", "sk-test-123")
        self.leak_free(
            "sk-test-123", self.store / "store.json", self.store / "master.key"
        )
        self.assertEqual((self.store / "store.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.store / "master.key").stat().st_mode & 0o777, 0o600)

    def test_two_backends_share_the_store_format(self):
        """A store sealed by one backend opens under the other."""
        self.put("openai", "sk-test-123", backend="cryptography")
        other = "vendored-aesgcm" if self.backend == "cryptography" else "cryptography"
        r = self.call("get", {"name": "openai", "reveal": True}, backend=other)
        self.assertEqual(r["result"]["value"], "sk-test-123")

    def test_tampered_ciphertext_is_refused(self):
        self.put("openai", "sk-test-123")
        p = self.store / "store.json"
        doc = json.loads(p.read_text())
        sealed = doc["entries"]["openai"]["nonce_sealed"]
        doc["entries"]["openai"]["nonce_sealed"] = (
            "B" if sealed[0] != "B" else "C"
        ) + sealed[1:]
        p.write_text(json.dumps(doc))
        r = self.call("get", {"name": "openai", "reveal": True})
        self.assertEqual(r["error"]["code"], "undecryptable")

    def test_entry_name_is_bound_into_the_ciphertext(self):
        """Swapping a sealed blob between slots must not decrypt."""
        self.put("alpha", "secret-a")
        self.put("beta", "secret-b")
        p = self.store / "store.json"
        doc = json.loads(p.read_text())
        doc["entries"]["alpha"]["nonce_sealed"] = doc["entries"]["beta"]["nonce_sealed"]
        p.write_text(json.dumps(doc))
        r = self.call("get", {"name": "alpha", "reveal": True})
        self.assertEqual(r["error"]["code"], "undecryptable")

    def test_rotate_rekeys_and_preserves_values(self):
        self.put("openai", "sk-test-123")
        before = self.call("where")["result"]["kid"]
        r = self.call("rotate")
        self.assertTrue(r["result"]["new_key"])
        self.assertNotEqual(self.call("where")["result"]["kid"], before)
        after = self.call("get", {"name": "openai", "reveal": True})
        self.assertEqual(after["result"]["value"], "sk-test-123")
        self.assertEqual(after["result"]["rotations"], 1)

    def test_rotate_keeps_store_readable_on_failure(self):
        self.put("openai", "sk-test-123")
        self.put("stripe", "sk_live_9")
        p = self.store / "store.json"
        doc = json.loads(p.read_text())
        doc["entries"]["stripe"]["nonce_sealed"] = (
            "AAAA" + doc["entries"]["stripe"]["nonce_sealed"][4:]
        )
        p.write_text(json.dumps(doc))
        self.assertEqual(self.call("rotate")["error"]["code"], "undecryptable")
        self.assertEqual(
            self.call("get", {"name": "openai", "reveal": True})["result"]["value"],
            "sk-test-123",
        )

    def test_export_stays_sealed_and_import_needs_the_key(self):
        self.put("openai", "sk-test-123")
        out = Path(self.home) / "bundle.json"
        r = self.call("export", {"path": str(out)})
        self.assertTrue(r["result"]["sealed"])
        self.leak_free("sk-test-123", out)
        fresh = tempfile.mkdtemp()
        bad = self.call("import", {"path": str(out)}, env={"KRAKEN_HOME": fresh})
        self.assertEqual(bad["error"]["code"], "key_mismatch")

    def test_export_with_key_imports_into_a_fresh_home(self):
        self.put("openai", "sk-test-123")
        self.put("stripe", "sk_live_9")
        out = Path(self.home) / "bundle.json"
        self.call("export", {"path": str(out), "include_key": True})
        self.leak_free("sk-test-123", out)
        fresh = tempfile.mkdtemp()
        env = {"KRAKEN_HOME": fresh}
        guarded = self.call("import", {"path": str(out)}, env=env)
        self.assertEqual(guarded["error"]["code"], "key_in_bundle")
        r = self.call("import", {"path": str(out), "adopt_key": True}, env=env)
        self.assertEqual(r["result"]["imported"], 2)
        got = self.call("get", {"name": "openai", "reveal": True}, env=env)
        self.assertEqual(got["result"]["value"], "sk-test-123")

    def test_export_inline_imports(self):
        self.put("openai", "sk-test-123")
        data = self.call("export", {"inline": True, "include_key": True})["result"][
            "data"
        ]
        fresh = tempfile.mkdtemp()
        env = {"KRAKEN_HOME": fresh}
        self.assertEqual(
            self.call("import", {"bundle": data, "adopt_key": True}, env=env)["result"][
                "imported"
            ],
            1,
        )
        self.assertEqual(
            self.call("get", {"name": "openai", "reveal": True}, env=env)["result"][
                "value"
            ],
            "sk-test-123",
        )

    def test_remove_and_clear(self):
        self.put("openai", "sk-test-123")
        self.assertTrue(self.call("remove", {"name": "openai"})["result"]["removed"])
        self.assertEqual(
            self.call("remove", {"name": "openai"})["error"]["code"], "not_found"
        )
        self.put("a", "1")
        self.put("b", "2")
        r = self.call("clear", {"forget_key": True})
        self.assertEqual(r["result"]["cleared"], 2)
        self.assertTrue(r["result"]["key_forgotten"])
        self.assertFalse((self.store / "master.key").exists())

    def test_where_never_prints_the_key(self):
        self.put("openai", "sk-test-123")
        r = self.call("where")
        self.assertIn("kid", r["result"])
        self.assertNotIn("sk-test-123", json.dumps(r))
        key = (self.store / "master.key").read_text().strip()
        self.assertNotIn(key, json.dumps(r))

    def test_finish_redacts_credential_keys(self):
        r = self.call(
            "finish",
            {
                "raw": {"arm": "keeps", "note": "hi"},
                "patch": {
                    "client_secret": "shh",
                    "nested": {"password": "pw", "ok": 1},
                },
            },
        )
        self.assertTrue(r["result"]["finished"])
        blob = json.dumps(r)
        self.assertNotIn("shh", blob)
        self.assertNotIn("pw", blob)
        self.assertIn("ok", blob)

    def test_get_missing_is_not_found(self):
        self.assertEqual(
            self.call("get", {"name": "absent"})["error"]["code"], "not_found"
        )

    def test_put_overwrites_and_keeps_created(self):
        self.put("openai", "one")
        first = self.call("list")["result"]["entries"][0]["created"]
        self.put("openai", "two")
        self.assertEqual(
            self.call("get", {"name": "openai", "reveal": True})["result"]["value"],
            "two",
        )
        self.assertEqual(self.call("list")["result"]["entries"][0]["created"], first)

    def test_file_and_base64_values(self):
        src = Path(self.home) / "secret.txt"
        src.write_text("from-a-file", encoding="utf-8")
        self.assertTrue(self.call("put", {"name": "file", "file": str(src)})["ok"])
        self.assertEqual(
            self.call("get", {"name": "file", "reveal": True})["result"]["value"],
            "from-a-file",
        )
        self.assertTrue(
            self.call("put", {"name": "b64", "base64": "ZnJvbS1iNjQ="})["ok"]
        )
        self.assertEqual(
            self.call("get", {"name": "b64", "reveal": True})["result"]["value"],
            "from-b64",
        )

    def test_put_needs_a_value(self):
        self.assertEqual(self.call("put", {"name": "x"})["error"]["code"], "refused")

    def test_empty_value_refused(self):
        self.assertEqual(
            self.call("put", {"name": "x", "value": ""})["error"]["code"], "refused"
        )

    def test_oversize_value_refused(self):
        self.assertEqual(
            self.call("put", {"name": "x", "value": "a" * (256 * 1024 + 1)})["error"][
                "code"
            ],
            "refused",
        )

    def test_illegal_names_refused(self):
        for bad in ("../escape", "a/b/../../c", ".hidden", "", "with space", "a" * 200):
            r = self.call("put", {"name": bad, "value": "x"})
            self.assertFalse(r["ok"], f"name {bad!r} should be refused")
            self.assertEqual(r["error"]["code"], "refused", f"name {bad!r}")

    def test_dotted_namespaces_allowed(self):
        for good in ("openai", "github.token", "prod/stripe-key", "a-b_c.1"):
            self.assertTrue(
                self.put(good, "x")["ok"], f"name {good!r} should be allowed"
            )

    def test_path_jail_refuses_license_and_catalog_dirs(self):
        for bad in (
            "/tmp/keys",
            str(Path(self.home) / ".kraken" / "keys"),
            "/tmp/licenses.json",
            "/tmp/kraken_catalog",
            "/tmp/topta.co",
        ):
            r = self.call("ping", {"dir": bad})
            self.assertFalse(r["ok"], f"dir {bad!r} should be jailed")
            self.assertEqual(r["error"]["code"], "refused")

    def test_explicit_dir_is_honoured(self):
        alt = Path(self.home) / "elsewhere"
        self.call(
            "put",
            {"name": "openai", "value": "x"},
        )
        r = self.call(
            "put",
            {"name": "k", "value": "y"},
            env={**self.env, "KRAKEN_KEEPS_DIR": str(alt)},
        )
        self.assertTrue(r["ok"])
        self.assertTrue((alt / ".kraken" / "data" / "keeps" / "store.json").exists())

    def test_project_scope(self):
        proj = Path(self.home) / "proj"
        (proj / ".kraken").mkdir(parents=True)
        r = subprocess.run(
            ["sh", str(ROOT / "handler.sh")],
            input=json.dumps(
                {"v": 1, "action": "ping", "payload": {"scope": "project"}}
            ),
            text=True,
            capture_output=True,
            env={
                **os.environ,
                "KRAKEN_OFFLINE": "1",
                "KRAKEN_KEEPS_BACKEND": self.backend,
            },
            cwd=str(proj),
            check=False,
        )
        body = json.loads(
            [ln for ln in r.stdout.splitlines() if ln.startswith("{")][-1]
        )
        self.assertEqual(body["result"]["scope"], "project")
        self.assertIn(str(proj), body["result"]["dir"])

    def test_offline_flag_reported(self):
        self.assertTrue(self.call("ping")["result"]["offline"])

    def test_corrupt_store_degrades_instead_of_crashing(self):
        self.put("openai", "sk-test-123")
        (self.store / "store.json").write_text("{ this is not json", encoding="utf-8")
        r = self.call("list")
        self.assertTrue(r["ok"])
        self.assertEqual(r["result"]["count"], 0)

    def test_get_before_any_put_is_not_found(self):
        self.assertEqual(self.call("get", {"name": "x"})["error"]["code"], "not_found")

    def test_response_is_envelope_v1(self):
        for action in ("ping", "where", "list", "has", "bogus"):
            r = self.call(action, {"name": "x"})
            self.assertEqual(r["v"], 1)
            self.assertIn("ok", r)
            if r["ok"]:
                self.assertIn("result", r)
            else:
                self.assertEqual(set(r["error"]), {"code", "message"})


class TestVendored(Base, unittest.TestCase):
    backend = "vendored-aesgcm"

    def test_engine_is_vendored(self):
        self.assertEqual(self.call("ping")["result"]["engine"], "vendored-aesgcm")

    def test_roundtrip(self):
        self.put("openai", "sk-test-123")
        self.assertEqual(
            self.call("get", {"name": "openai", "reveal": True})["result"]["value"],
            "sk-test-123",
        )

    def test_binary_value(self):
        import base64 as b64

        raw = bytes(range(256))
        self.assertTrue(
            self.call("put", {"name": "bin", "base64": b64.b64encode(raw).decode()})[
                "ok"
            ]
        )
        asked = self.call("get", {"name": "bin", "reveal": True})
        self.assertEqual(asked["error"]["code"], "not_text")
        got = self.call("get", {"name": "bin", "reveal": True, "encoding": "base64"})
        self.assertEqual(b64.b64decode(got["result"]["value"]), raw)
        self.assertEqual(got["result"]["size"], 256)

    def test_aesgcm_known_vector(self):
        """FIPS-197 / SP 800-38D sanity, independent of any library."""
        import aesgcm

        self.assertEqual(
            aesgcm.encrypt(bytes(16), bytes(12), bytes(16)).hex(),
            "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf",
        )
        w, nr = aesgcm._expand(
            bytes.fromhex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            )
        )
        self.assertEqual(
            aesgcm._encrypt_block(
                bytes.fromhex("00112233445566778899aabbccddeeff"), w, nr
            ).hex(),
            "8ea2b7ca516745bfeafc49904b496089",
        )

    def test_aesgcm_tamper_and_aad(self):
        import aesgcm

        k, n = os.urandom(32), os.urandom(12)
        sealed = aesgcm.encrypt(k, n, b"v", b"openai")
        with self.assertRaises(ValueError):
            aesgcm.decrypt(k, n, sealed[:-1] + bytes([sealed[-1] ^ 1]), b"openai")
        with self.assertRaises(ValueError):
            aesgcm.decrypt(k, n, sealed, b"stripe")

    def test_aesgcm_long_iv(self):
        import aesgcm

        for ivlen in (8, 16, 20, 60, 64, 128):
            k, n, pt, aad = os.urandom(32), os.urandom(ivlen), os.urandom(70), b"aad"
            self.assertEqual(
                aesgcm.decrypt(k, n, aesgcm.encrypt(k, n, pt, aad), aad), pt
            )


def _backend_class(backend: str) -> type:
    """Build one concrete TestCase for a cipher backend."""
    label = "".join(part.capitalize() for part in backend.replace("-", "_").split("_"))
    return type(
        f"TestKeeps{label}", (KeepsContract, unittest.TestCase), {"backend": backend}
    )


# Bound at module scope so pytest collects one full contract run per backend.
# (The `load_tests` protocol only works under `unittest`, and this suite is
# run by pytest in CI as well as directly.)
TestKeepsCryptography = _backend_class("cryptography")
TestKeepsVendoredAesgcm = _backend_class("vendored-aesgcm")


def load_tests(loader, tests, pattern):
    """`unittest` entry point. pytest collects the classes above instead."""
    return tests


if __name__ == "__main__":
    unittest.main()
