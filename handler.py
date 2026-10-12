#!/usr/bin/env python3
"""keeps — encrypted local secret store. AES-256-GCM at rest, no daemon.

Envelope v1 on stdin/stdout. Core never imports this file.

Contract notes that the rest of the reef depends on:
  * `list` returns names and metadata only. A keep name is not its value.
  * `get` masks the value unless payload.reveal is true.
  * The entry name is bound in as AES-GCM additional data, so a sealed
    entry cannot be silently renamed or swapped between slots.
  * The store refuses to live in keys/, next to licenses.json, or in a
    catalog dump. License keys are not this store.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import platform
import re
import secrets
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import aesgcm  # noqa: E402

VERSION = "0.1.0"
PROTOCOL = 1
NONCE = 12
MAX_VALUE = 256 * 1024
MAX_NAME = 128

# Matches the sibling arms: license material and catalog dumps are not stores.
FORBIDDEN = ("/keys", "keys/", "licenses.json", "kraken_catalog", "topta.co")

# Reflected in every echo so a value never rides out in a hook envelope.
REDACT_KEYS = (
    "token",
    "secret",
    "password",
    "passwd",
    "client_secret",
    "api_key",
    "apikey",
)
MASK = "•" * 4

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-/]*$")


class Locked(Exception):
    pass


class Refused(Exception):
    pass


def _now() -> str:
    return (
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )


def ok(ident, result):
    return {"v": PROTOCOL, "id": ident, "ok": True, "result": result}


def err(ident, code, message):
    return {
        "v": PROTOCOL,
        "id": ident,
        "ok": False,
        "error": {"code": code, "message": message},
    }


def redact(obj):
    """Mask values whose key looks like a credential. Applied to every echo."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if any(s in str(k).lower() for s in REDACT_KEYS):
                out[k] = MASK
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def _check_dir(path: Path) -> Path:
    text = str(path.resolve()).replace("\\", "/").lower()
    for part in FORBIDDEN:
        if part in text:
            raise Refused(f"forbidden store path {part!r}")
    return path


def resolve(payload: dict | None = None) -> tuple[Path, str]:
    payload = payload or {}
    explicit = payload.get("dir") or os.environ.get("KRAKEN_KEEPS_DIR")
    if explicit:
        p = Path(os.path.expandvars(str(explicit)))
        if p.name == "keeps" and p.parent.name == "data":
            return _check_dir(p), "dir"
        if p.name == ".kraken":
            return _check_dir(p / "data" / "keeps"), "dir"
        return _check_dir(p / ".kraken" / "data" / "keeps"), "dir"
    scope = (
        payload.get("scope") or os.environ.get("KRAKEN_KEEPS_SCOPE") or "home"
    ).lower()
    if scope == "project":
        cur = Path.cwd()
        while True:
            cand = cur / ".kraken"
            if cand.is_dir():
                return _check_dir(cand / "data" / "keeps"), "project"
            if cur.parent == cur:
                break
            cur = cur.parent
        scope = "home"
    if scope == "system":
        return _check_dir(
            Path(os.environ.get("KRAKEN_SYSTEM") or "/etc/kraken") / "data" / "keeps"
        ), "system"
    root = os.environ.get("KRAKEN_HOME") or str(Path.home())
    return _check_dir(Path(root) / ".kraken" / "data" / "keeps"), "home"


def store_path(payload: dict | None = None) -> Path:
    d, _ = resolve(payload)
    return d / "store.json"


def key_path(payload: dict | None = None) -> Path:
    d, _ = resolve(payload)
    return d / "master.key"


def check_name(raw) -> str:
    name = str(raw or "").strip()
    if not name:
        raise Refused("empty name")
    if len(name) > MAX_NAME:
        raise Refused("name too long")
    if not NAME_RE.match(name) or ".." in name:
        raise Refused("illegal name")
    return name


def load(payload: dict | None = None) -> dict:
    p = store_path(payload)
    if not p.exists():
        return {"v": 1, "created": _now(), "entries": {}}
    try:
        st = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"v": 1, "corrupt": True, "created": _now(), "entries": {}}
    st.setdefault("entries", {})
    return st


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".keeps-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def save(st: dict, payload: dict | None = None) -> None:
    st["updated"] = _now()
    _atomic_write(store_path(payload), json.dumps(st, indent=2).encode("utf-8"))


def _backend() -> str:
    # KRAKEN_KEEPS_BACKEND pins the cipher so CI can exercise the vendored
    # fallback on hosts that do have the wheel. The on-disk format is
    # identical either way.
    forced = os.environ.get("KRAKEN_KEEPS_BACKEND", "").strip().lower()
    if forced in ("vendored", "vendored-aesgcm", "python", "pure"):
        return "vendored-aesgcm"
    if forced in ("cryptography", "openssl", "wheel"):
        return "cryptography"
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401

        return "cryptography"
    except Exception:
        return "vendored-aesgcm"


def _seal(key: bytes, name: str, plain: bytes) -> str:
    nonce = secrets.token_bytes(NONCE)
    if _backend() == "cryptography":
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        blob = AESGCM(key).encrypt(nonce, plain, name.encode("utf-8"))
    else:
        blob = aesgcm.encrypt(key, nonce, plain, name.encode("utf-8"))
    return base64.b64encode(nonce + blob).decode("ascii")


def _open(key: bytes, name: str, sealed_b64: str) -> bytes:
    raw = base64.b64decode(sealed_b64.encode("ascii"), validate=True)
    nonce, blob = raw[:NONCE], raw[NONCE:]
    if _backend() == "cryptography":
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        return AESGCM(key).decrypt(nonce, blob, name.encode("utf-8"))
    return aesgcm.decrypt(key, nonce, blob, name.encode("utf-8"))


def kid(key: bytes) -> str:
    return hashlib.sha256(b"kraken-keeps-kid\x00" + key).hexdigest()[:16]


def _derive(passphrase: str, salt: bytes) -> bytes:
    try:
        return hashlib.scrypt(
            passphrase.encode("utf-8"), salt=salt, n=1 << 14, r=8, p=1, dklen=32
        )
    except (ValueError, AttributeError):
        return hashlib.pbkdf2_hmac(
            "sha256", passphrase.encode("utf-8"), salt, 600_000, dklen=32
        )


def key_of(payload: dict | None = None, create: bool = False) -> bytes:
    """Resolve the master key: explicit passphrase, else the local key file."""
    payload = payload or {}
    passphrase = payload.get("passphrase")
    if passphrase:
        st = load(payload)
        meta = st.get("kdf") or {}
        salt = (
            binascii.unhexlify(meta["salt"])
            if meta.get("salt")
            else secrets.token_bytes(16)
        )
        return _derive(str(passphrase), salt)
    kp = key_path(payload)
    if kp.exists():
        text = kp.read_text(encoding="utf-8").strip()
        try:
            return binascii.unhexlify(text)
        except (binascii.Error, ValueError):
            raise Locked("master key is not valid hex")
    if create:
        key = secrets.token_bytes(32)
        _atomic_write(kp, binascii.hexlify(key), 0o600)
        return key
    raise Locked("no master key yet — put something first, or pass a passphrase")


def _value_bytes(payload: dict) -> bytes:
    if "value" in payload and payload["value"] is not None:
        raw = str(payload["value"]).encode("utf-8")
    elif payload.get("file"):
        raw = Path(str(payload["file"])).read_bytes()
    elif payload.get("base64"):
        try:
            raw = base64.b64decode(
                str(payload["base64"]).encode("ascii"), validate=True
            )
        except (binascii.Error, ValueError):
            raise Refused("bad base64")
    else:
        raise Refused("no value, file, or base64 in payload")
    if not raw:
        raise Refused("empty value")
    if len(raw) > MAX_VALUE:
        raise Refused("value exceeds 256 KiB")
    return raw


def meta_of(entry: dict) -> dict:
    return {
        "name": entry["name"],
        "size": entry.get("size"),
        "created": entry.get("created"),
        "updated": entry.get("updated"),
        "rotations": entry.get("rotations", 0),
    }


def dispatch(req: dict) -> dict:
    action = req.get("action") or "ping"
    payload = req.get("payload") or {}
    ident = req.get("id")
    dest, scope = resolve(payload)
    st = load(payload)

    if action == "ping":
        kp = key_path(payload)
        return ok(
            ident,
            {
                "arm": "keeps",
                "version": VERSION,
                "protocol": PROTOCOL,
                "platform": f"{sys.platform}-{platform.machine()}",
                "engine": _backend(),
                "cipher": "AES-256-GCM",
                "scope": scope,
                "dir": str(dest),
                "entries": len(st.get("entries") or {}),
                "sealed": kp.exists(),
                "offline": os.environ.get("KRAKEN_OFFLINE") == "1",
                "fetches": 0,
            },
        )
    if action == "where":
        kp = key_path(payload)
        sealed = kp.exists()
        result = {
            "arm": "keeps",
            "scope": scope,
            "dir": str(dest),
            "store": str(store_path(payload)),
            "key_file": str(kp),
            "sealed": sealed,
            "entries": len(st.get("entries") or {}),
            "hint": "license keys in ~/.kraken/keys are licenses, not this store",
        }
        if sealed:
            try:
                result["kid"] = kid(
                    binascii.unhexlify(kp.read_text(encoding="utf-8").strip())
                )
            except (binascii.Error, ValueError, OSError):
                result["kid"] = "unreadable"
        return ok(ident, result)
    if action == "list":
        entries = [meta_of(e) for e in (st.get("entries") or {}).values()]
        entries.sort(key=lambda e: e["name"])
        return ok(
            ident,
            {
                "arm": "keeps",
                "entries": entries,
                "count": len(entries),
                "values": "never",
            },
        )
    if action == "has":
        try:
            name = check_name(payload.get("name"))
        except Refused as e:
            return err(ident, "bad_name", str(e))
        entry = (st.get("entries") or {}).get(name)
        if not entry:
            return ok(ident, {"name": name, "exists": False})
        return ok(ident, dict(meta_of(entry), exists=True))
    if action == "put":
        try:
            name = check_name(payload.get("name"))
            raw = _value_bytes(payload)
            key = key_of(payload, create=True)
        except Refused as e:
            return err(ident, "refused", str(e))
        except Locked as e:
            return err(ident, "locked", str(e))
        entries = st.setdefault("entries", {})
        prev = entries.get(name) or {}
        stamp = _now()
        entries[name] = {
            "name": name,
            "nonce_sealed": _seal(key, name, raw),
            "size": len(raw),
            "created": prev.get("created", stamp),
            "updated": stamp,
            "rotations": prev.get("rotations", 0),
        }
        save(st, payload)
        return ok(
            ident,
            {
                "arm": "keeps",
                "name": name,
                "size": len(raw),
                "sealed": True,
                "count": len(entries),
                "updated": stamp,
                "revealed": False,
            },
        )
    if action == "get":
        try:
            name = check_name(payload.get("name"))
        except Refused as e:
            return err(ident, "bad_name", str(e))
        entry = (st.get("entries") or {}).get(name)
        if not entry:
            return err(ident, "not_found", "no such keep")
        try:
            key = key_of(payload)
        except Locked as e:
            return err(ident, "locked", str(e))
        try:
            raw = _open(key, name, entry["nonce_sealed"])
        except Exception:
            return err(ident, "undecryptable", "wrong key or tampered store")
        if payload.get("reveal") is True:
            # Small files are allowed, so offer a byte-exact path for
            # anything that is not valid UTF-8 text.
            if str(payload.get("encoding") or "").lower() == "base64":
                return ok(
                    ident,
                    dict(
                        meta_of(entry),
                        value=base64.b64encode(raw).decode("ascii"),
                        encoding="base64",
                        revealed=True,
                    ),
                )
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                return err(
                    ident,
                    "not_text",
                    "value is not UTF-8; re-read with payload.encoding=base64",
                )
            return ok(
                ident,
                dict(meta_of(entry), value=text, encoding="utf-8", revealed=True),
            )
        return ok(
            ident,
            dict(
                meta_of(entry),
                value=MASK,
                revealed=False,
                hint="pass payload.reveal=true to print the value",
            ),
        )
    if action == "remove":
        try:
            name = check_name(payload.get("name"))
        except Refused as e:
            return err(ident, "bad_name", str(e))
        entries = st.setdefault("entries", {})
        if name not in entries:
            return err(ident, "not_found", "no such keep")
        del entries[name]
        save(st, payload)
        return ok(ident, {"removed": True, "name": name, "count": len(entries)})
    if action == "rotate":
        try:
            key = key_of(payload, create=True)
        except Locked as e:
            return err(ident, "locked", str(e))
        entries = st.get("entries") or {}
        # Read every entry before writing anything, so a failure part way
        # through leaves the existing store readable.
        plain: dict[str, bytes] = {}
        for name, entry in entries.items():
            try:
                plain[name] = _open(key, name, entry["nonce_sealed"])
            except Exception:
                return err(
                    ident, "undecryptable", f"cannot read {name!r} before rotate"
                )
        new_key = (
            secrets.token_bytes(32) if payload.get("new_key") is not False else key
        )
        for name, entry in entries.items():
            entry["nonce_sealed"] = _seal(new_key, name, plain[name])
            entry["rotations"] = entry.get("rotations", 0) + 1
            entry["updated"] = _now()
        save(st, payload)
        if new_key != key:
            _atomic_write(key_path(payload), binascii.hexlify(new_key), 0o600)
        return ok(
            ident,
            {
                "arm": "keeps",
                "rotated": len(entries),
                "new_key": new_key != key,
                "kid": kid(new_key),
                "count": len(entries),
            },
        )
    if action == "export":
        include_key = payload.get("include_key") is True
        entries = st.get("entries") or {}
        if not entries:
            return err(ident, "empty", "nothing to export")
        bundle = {"v": 1, "arm": "keeps", "created": _now(), "entries": entries}
        if include_key:
            try:
                bundle["master_key"] = binascii.hexlify(key_of(payload)).decode("ascii")
            except Locked as e:
                return err(ident, "locked", str(e))
        if payload.get("inline"):
            raw = base64.b64encode(json.dumps(bundle).encode("utf-8")).decode("ascii")
            return ok(
                ident,
                {
                    "format": "json+b64",
                    "inline": True,
                    "data": raw,
                    "count": len(entries),
                    "key_included": include_key,
                },
            )
        out = Path(str(payload.get("path") or (dest / "export.json")))
        _atomic_write(out, json.dumps(bundle, indent=2).encode("utf-8"), 0o600)
        return ok(
            ident,
            {
                "path": str(out),
                "format": "json",
                "count": len(entries),
                "sealed": not include_key,
                "key_included": include_key,
                "hint": "wax signs the export; keeps leaves it sealed",
            },
        )
    if action == "import":
        raw = payload.get("bundle")
        if not raw:
            src = payload.get("path") or payload.get("file")
            if not src:
                return err(ident, "no_bundle", "pass payload.bundle, .path, or .file")
            raw = Path(str(src)).read_text(encoding="utf-8")
        if not isinstance(raw, str):
            return err(ident, "bad_bundle", "bundle must be a JSON string")
        if not raw.lstrip().startswith("{"):
            # export --inline hands back base64; accept either shape.
            try:
                raw = base64.b64decode(
                    raw.strip().encode("ascii"), validate=True
                ).decode("utf-8")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                return err(ident, "bad_bundle", "not a keeps bundle")
        try:
            bundle = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return err(ident, "bad_bundle", "not a keeps bundle")
        incoming = bundle.get("entries") or {}
        if not incoming:
            return err(ident, "empty", "bundle has no entries")
        try:
            key = key_of(payload, create=True)
        except Locked as e:
            return err(ident, "locked", str(e))
        if bundle.get("master_key"):
            if payload.get("adopt_key") is not True:
                return err(
                    ident,
                    "key_in_bundle",
                    "bundle carries a key; pass adopt_key=true to re-key",
                )
            try:
                bkey = binascii.unhexlify(str(bundle["master_key"]))
            except (binascii.Error, ValueError):
                return err(ident, "bad_bundle", "bundle master_key is not hex")
            _atomic_write(key_path(payload), binascii.hexlify(bkey), 0o600)
            key = bkey
        entries = st.setdefault("entries", {})
        added = 0
        for name, entry in incoming.items():
            try:
                check_name(name)
                raw_val = _open(key, name, entry["nonce_sealed"])
            except (Refused, KeyError) as e:
                return err(ident, "refused", f"skipping {name!r}: {e}")
            except Exception:
                return err(ident, "key_mismatch", "bundle was sealed with another key")
            if payload.get("overwrite") is not True and name in entries:
                continue
            stamp = _now()
            entries[name] = {
                "name": name,
                "nonce_sealed": _seal(key, name, raw_val),
                "size": entry.get("size", len(raw_val)),
                "created": entry.get("created", stamp),
                "updated": stamp,
                "rotations": entry.get("rotations", 0),
            }
            added += 1
        save(st, payload)
        return ok(
            ident,
            {
                "arm": "keeps",
                "imported": added,
                "skipped": len(incoming) - added,
                "count": len(entries),
            },
        )
    if action == "clear":
        entries = st.setdefault("entries", {})
        dropped = len(entries)
        entries.clear()
        save(st, payload)
        forgot = False
        if payload.get("forget_key") is True:
            kp = key_path(payload)
            if kp.exists():
                try:
                    size = kp.stat().st_size
                    with open(kp, "r+b") as fh:
                        fh.write(b"\x00" * size)
                        fh.flush()
                        os.fsync(fh.fileno())
                except OSError:
                    pass
                kp.unlink(missing_ok=True)
                forgot = True
        return ok(
            ident,
            {
                "cleared": dropped,
                "key_forgotten": forgot,
                "sealed": key_path(payload).exists(),
            },
        )
    if action == "finish":
        out = dict(payload.get("raw") or {"arm": "keeps"})
        out.update(payload.get("patch") or {})
        out = redact(out)
        out["finished"] = True
        return ok(ident, out)
    return err(ident, "unknown_action", f"unknown action {action}")


def main() -> int:
    raw = sys.stdin.read()
    try:
        req = json.loads(raw) if raw.strip() else {"action": "ping", "payload": {}}
        if not isinstance(req, dict):
            raise ValueError("request must be an object")
        body = dispatch(req)
    except Refused as e:
        body = err(None, "refused", str(e))
    except Locked as e:
        body = err(None, "locked", str(e))
    except json.JSONDecodeError:
        body = err(None, "bad_request", "stdin was not one JSON object")
    except Exception as e:
        body = err(None, "internal", f"{type(e).__name__}: {e}")
    json.dump(body, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
