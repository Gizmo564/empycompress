#!/usr/bin/env python3
"""
empy v3.4 — Empyrean Secure Compression
======================================
AES-256-GCM encryption + zlib compression + X25519 peer layer.
Copyright Volvi 2026. All rights reserved.

Usage:
  python empy.py                      Launch GUI (browser interface)
  python empy.py --gui                Launch GUI (browser interface)
  python empy.py encrypt <file>       Encrypt from CLI
  python empy.py decrypt <file.empy>  Decrypt from CLI
  python empy.py --help               Full CLI help
"""

# ── Bootstrap: ensure 'cryptography' is installed before anything else ───────
import sys, subprocess

def _ensure_deps():
    required = {"cryptography": "cryptography"}
    missing  = []
    for pkg, pip_name in required.items():
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pip_name)
    if not missing:
        return
    print(f"  [empy] Missing dependencies: {', '.join(missing)}")
    print(f"  [empy] Installing via pip...")
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet"] + missing,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        print(f"  [empy] ✅  Installed: {', '.join(missing)}")
        # Reload site packages so imports below work without restart
        import importlib, site
        importlib.invalidate_caches()
    except subprocess.CalledProcessError:
        print(f"  [empy] ❌  Could not auto-install. Run manually:")
        print(f"              pip install {' '.join(missing)}")
        sys.exit(1)

if not getattr(sys, 'frozen', False):  # skip when compiled by Nuitka/PyInstaller
    _ensure_deps()
# ─────────────────────────────────────────────────────────────────────────────

import os, json, zlib, struct, hashlib, getpass, argparse, datetime, secrets, io
from pathlib import Path

# Force UTF-8 output on Windows (default is cp1252 which breaks Unicode art)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidTag

# ─────────────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────────────
MAGIC        = b"EMPY"
VERSION_V1   = 1     # standard encrypted file
VERSION_V2   = 2     # peer-sealed (double-encrypted) file
PROG_VERSION = "3.5.1"

SALT_LEN     = 32
NONCE_LEN    = 12
KEY_LEN      = 32
PBKDF2_ITER  = 600_000
MIN_PWD_LEN  = 8

# ─────────────────────────────────────────────────────
#  Crypto helpers
# ─────────────────────────────────────────────────────

def _pbkdf2(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN,
                     salt=salt, iterations=PBKDF2_ITER)
    return kdf.derive(password.encode("utf-8"))


def _hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN,
                salt=salt, info=info).derive(ikm)


def _aes_enc(key: bytes, nonce: bytes, data: bytes, aad: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, data, aad)


def _aes_dec(key: bytes, nonce: bytes, data: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, data, aad)
    except InvalidTag:
        raise ValueError("Decryption failed — wrong password/key or file is corrupted.")


def _meta_nonce(nonce: bytes) -> bytes:
    """Derive a distinct nonce for the metadata block by hashing the data nonce."""
    return hashlib.sha256(nonce + b"empy-meta-nonce").digest()[:NONCE_LEN]


def _compress(data: bytes) -> bytes:
    comp = zlib.compress(data, level=9)
    # Don't compress if it makes the data larger (e.g. JPEGs, ZIPs)
    return comp if len(comp) < len(data) else data


def _decompress(data: bytes, original_size: int) -> bytes:
    try:
        dec = zlib.decompress(data)
        if len(dec) == original_size:
            return dec
    except zlib.error:
        pass
    # Stored uncompressed (already-compressed input)
    return data


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _fingerprint(pub_bytes: bytes) -> str:
    return hashlib.sha256(pub_bytes).hexdigest()


# ─────────────────────────────────────────────────────
#  V1 format: standard single-password encryption
# ─────────────────────────────────────────────────────
#
# Layout:
#   MAGIC      4 B
#   VERSION    1 B  (= 1)
#   SALT      32 B  (PBKDF2 salt)
#   NONCE     12 B  (AES-GCM nonce for payload)
#   META_LEN   4 B  (uint32 BE)
#   ENC_META   var  (AES-GCM encrypted JSON metadata)
#   ENC_DATA   var  (AES-GCM encrypted + zlib-compressed file data)
#

def _v1_encode(raw: bytes, filename: str, password: str) -> tuple[bytes, dict]:
    """Encode raw file bytes into a V1 .empy blob."""
    salt  = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key   = _pbkdf2(password, salt)

    comp  = _compress(raw)
    meta  = {
        "filename"       : filename,
        "original_size"  : len(raw),
        "compressed_size": len(comp),
        "sha256"         : hashlib.sha256(raw).hexdigest(),
        "created_at"     : _now_iso(),
        "format_version" : VERSION_V1,
    }
    enc_meta = _aes_enc(key, _meta_nonce(nonce), json.dumps(meta).encode(), b"empy-meta")
    enc_data = _aes_enc(key, nonce, comp, b"empy-data")

    return (MAGIC + bytes([VERSION_V1]) + salt + nonce
            + struct.pack(">I", len(enc_meta)) + enc_meta + enc_data), meta


def _v1_decode(blob: bytes, password: str) -> tuple[bytes, dict]:
    """Decode a V1 .empy blob. Returns (raw_bytes, metadata)."""
    buf = memoryview(blob)
    pos = 0

    magic = bytes(buf[pos:pos+4]); pos += 4
    if magic != MAGIC:
        raise ValueError("Not a valid .empy file (bad magic bytes).")

    ver = buf[pos]; pos += 1
    if ver != VERSION_V1:
        raise ValueError(f"Expected V1 inner blob, got version {ver}.")

    salt  = bytes(buf[pos:pos+SALT_LEN]);  pos += SALT_LEN
    nonce = bytes(buf[pos:pos+NONCE_LEN]); pos += NONCE_LEN
    ml    = struct.unpack_from(">I", buf, pos)[0]; pos += 4
    enc_meta = bytes(buf[pos:pos+ml]);     pos += ml
    enc_data = bytes(buf[pos:])

    key      = _pbkdf2(password, salt)
    meta     = json.loads(_aes_dec(key, _meta_nonce(nonce), enc_meta, b"empy-meta"))
    comp     = _aes_dec(key, nonce, enc_data, b"empy-data")
    raw      = _decompress(comp, meta["original_size"])

    actual = hashlib.sha256(raw).hexdigest()
    if actual != meta["sha256"]:
        raise ValueError(f"Integrity check FAILED — file may be tampered with!\n"
                         f"  Expected : {meta['sha256']}\n  Got      : {actual}")
    return raw, meta


# ─────────────────────────────────────────────────────
#  V2 format: peer-sealed (X25519 ECDH + peer password + V1 inner)
# ─────────────────────────────────────────────────────
#
# Layout:
#   MAGIC             4 B
#   VERSION           1 B  (= 2)
#   PEER_SALT        32 B  (PBKDF2 salt for peer password)
#   PEER_NONCE       12 B  (AES-GCM nonce for peer layer)
#   EPHEMERAL_PUB    32 B  (sender's ephemeral X25519 public key)
#   RECIP_FP_HEX     64 B  (hex SHA-256 of recipient's raw public key)
#   PEER_META_LEN     4 B
#   ENC_PEER_META    var   (AES-GCM encrypted JSON peer metadata)
#   INNER_LEN         4 B
#   ENC_INNER        var   (peer-key encrypted V1 blob)
#
# Peer key derivation:
#   ecdh_shared = X25519(ephemeral_priv, recipient_pub)
#   pwd_component = PBKDF2(peer_password, peer_salt)
#   peer_key = HKDF(ikm=ecdh_shared, salt=pwd_component, info=b"empy-peer-v2")
#
# This means decryption requires BOTH the recipient's private key AND the peer password.
#

RECIP_FP_LEN = 64   # hex SHA-256 = 64 ASCII chars


def _peer_key(ecdh_shared: bytes, peer_password: str, peer_salt: bytes) -> bytes:
    pwd_component = _pbkdf2(peer_password, peer_salt)
    return _hkdf(ecdh_shared, salt=pwd_component, info=b"empy-peer-v2")


def _v2_encode(inner_blob: bytes, recipient_pub_bytes: bytes,
               sender_name: str, recipient_name: str, peer_password: str) -> bytes:
    """Wrap an inner V1 blob in a V2 peer-sealed envelope."""
    peer_salt  = os.urandom(SALT_LEN)
    peer_nonce = os.urandom(NONCE_LEN)

    # Ephemeral keypair for forward secrecy
    eph_priv = X25519PrivateKey.generate()
    eph_pub  = eph_priv.public_key()
    eph_pub_bytes = eph_pub.public_bytes(serialization.Encoding.Raw,
                                          serialization.PublicFormat.Raw)

    recip_pub = X25519PublicKey.from_public_bytes(recipient_pub_bytes)
    ecdh_shared = eph_priv.exchange(recip_pub)
    pkey = _peer_key(ecdh_shared, peer_password, peer_salt)

    recip_fp = _fingerprint(recipient_pub_bytes)

    peer_meta = {
        "sender"      : sender_name,
        "recipient"   : recipient_name,
        "recip_fp"    : recip_fp,
        "sealed_at"   : _now_iso(),
    }
    enc_peer_meta = _aes_enc(pkey, _meta_nonce(peer_nonce),
                             json.dumps(peer_meta).encode(), b"empy-peer-meta")
    enc_inner     = _aes_enc(pkey, peer_nonce, inner_blob, b"empy-peer-data")

    fp_bytes = recip_fp.encode("ascii")   # 64 bytes

    return (MAGIC + bytes([VERSION_V2])
            + peer_salt + peer_nonce
            + eph_pub_bytes
            + fp_bytes
            + struct.pack(">I", len(enc_peer_meta)) + enc_peer_meta
            + struct.pack(">I", len(enc_inner))     + enc_inner)


def _v2_decode(blob: bytes, my_priv_bytes: bytes, peer_password: str) -> tuple[bytes, dict]:
    """Unseal a V2 blob. Returns (inner_blob, peer_meta)."""
    buf = memoryview(blob)
    pos = 0

    magic = bytes(buf[pos:pos+4]); pos += 4
    if magic != MAGIC:
        raise ValueError("Not a valid .empy file (bad magic bytes).")

    ver = buf[pos]; pos += 1
    if ver != VERSION_V2:
        raise ValueError(f"Expected a peer-sealed V2 file, got version {ver}. "
                         "Use 'decrypt' for standard files.")

    peer_salt     = bytes(buf[pos:pos+SALT_LEN]);    pos += SALT_LEN
    peer_nonce    = bytes(buf[pos:pos+NONCE_LEN]);   pos += NONCE_LEN
    eph_pub_bytes = bytes(buf[pos:pos+32]);           pos += 32
    recip_fp_enc  = bytes(buf[pos:pos+RECIP_FP_LEN]).decode("ascii"); pos += RECIP_FP_LEN
    pml           = struct.unpack_from(">I", buf, pos)[0]; pos += 4
    enc_peer_meta = bytes(buf[pos:pos+pml]);          pos += pml
    inl           = struct.unpack_from(">I", buf, pos)[0]; pos += 4
    enc_inner     = bytes(buf[pos:pos+inl])

    my_priv    = X25519PrivateKey.from_private_bytes(my_priv_bytes)
    my_pub     = my_priv.public_key()
    my_pub_bytes = my_pub.public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw)
    my_fp = _fingerprint(my_pub_bytes)

    if my_fp != recip_fp_enc:
        raise ValueError(
            f"This file was not sealed for this keypair.\n"
            f"  File recipient fingerprint : {recip_fp_enc[:16]}...\n"
            f"  Your key fingerprint       : {my_fp[:16]}...")

    eph_pub     = X25519PublicKey.from_public_bytes(eph_pub_bytes)
    ecdh_shared = my_priv.exchange(eph_pub)
    pkey        = _peer_key(ecdh_shared, peer_password, peer_salt)

    peer_meta  = json.loads(_aes_dec(pkey, _meta_nonce(peer_nonce), enc_peer_meta, b"empy-peer-meta"))
    inner_blob = _aes_dec(pkey, peer_nonce, enc_inner, b"empy-peer-data")

    return inner_blob, peer_meta


# ─────────────────────────────────────────────────────
#  Keypair management
# ─────────────────────────────────────────────────────

def _load_pubkey(path: str) -> tuple[bytes, str]:
    """Return (raw_32_byte_pubkey, name)."""
    data = json.loads(Path(path).read_text())
    return bytes.fromhex(data["public_key"]), data["name"]


def _load_privkey(path: str, password: str) -> tuple[bytes, str]:
    """Return (raw_32_byte_privkey, name). Decrypts with password."""
    data  = json.loads(Path(path).read_text())
    salt  = bytes.fromhex(data["key_salt"])
    nonce = bytes.fromhex(data["key_nonce"])
    enc   = bytes.fromhex(data["private_key_enc"])
    key   = _pbkdf2(password, salt)
    raw   = _aes_dec(key, nonce, enc, b"empy-privkey")
    return raw, data["name"]


def cmd_keygen(args):
    name    = args.name
    out_dir = Path(args.outdir or ".")
    out_dir.mkdir(parents=True, exist_ok=True)

    pub_path  = out_dir / f"{name}.empy.pub"
    priv_path = out_dir / f"{name}.empy.key"

    for p in (pub_path, priv_path):
        if p.exists() and not args.force:
            raise ValueError(f"File already exists: {p}  (use --force to overwrite)")

    print(f"  Generating X25519 keypair for '{name}'...")
    key_password = args.key_password or _pwd(
        "  Key protection password : ", confirm=True,
        label="key protection password")

    priv = X25519PrivateKey.generate()
    pub  = priv.public_key()
    priv_bytes = priv.private_bytes(serialization.Encoding.Raw,
                                    serialization.PrivateFormat.Raw,
                                    serialization.NoEncryption())
    pub_bytes  = pub.public_bytes(serialization.Encoding.Raw,
                                   serialization.PublicFormat.Raw)

    # Encrypt private key with key_password
    ksalt  = os.urandom(SALT_LEN)
    knonce = os.urandom(NONCE_LEN)
    kkey   = _pbkdf2(key_password, ksalt)
    enc_priv = _aes_enc(kkey, knonce, priv_bytes, b"empy-privkey")

    fp = _fingerprint(pub_bytes)

    pub_data = {
        "name"       : name,
        "public_key" : pub_bytes.hex(),
        "fingerprint": fp,
        "created_at" : _now_iso(),
    }
    priv_data = {
        "name"           : name,
        "public_key"     : pub_bytes.hex(),
        "fingerprint"    : fp,
        "private_key_enc": enc_priv.hex(),
        "key_salt"       : ksalt.hex(),
        "key_nonce"      : knonce.hex(),
        "created_at"     : _now_iso(),
    }

    pub_path.write_text(json.dumps(pub_data, indent=2))
    priv_path.write_text(json.dumps(priv_data, indent=2))
    priv_path.chmod(0o600)   # owner read-only

    print()
    print(f"  ✅  Keypair generated for '{name}'")
    print(f"  🔑  Public key  → {pub_path}  (share freely)")
    print(f"  🔒  Private key → {priv_path}  (keep secret, mode 0600)")
    print(f"  🆔  Fingerprint : {fp[:32]}...")
    print()
    print("  Share the .empy.pub file with peers who want to send you sealed files.")


# ─────────────────────────────────────────────────────
#  High-level commands
# ─────────────────────────────────────────────────────

def cmd_encrypt(args):
    inp = Path(args.input)
    if not inp.exists():
        raise FileNotFoundError(f"Input file not found: {inp}")

    default_out = inp.parent / (inp.name + ".empy")
    out = Path(args.output) if args.output else default_out

    if out.exists() and not args.force:
        raise ValueError(f"Output already exists: {out}  (use --force to overwrite)")

    password = args.password or _pwd("  Set password    : ", confirm=True)
    if args.password:
        _validate_pwd(args.password)

    print(f"  Reading '{inp.name}'...")
    raw  = inp.read_bytes()
    orig = len(raw)

    print("  Compressing & encrypting...")
    blob, meta = _v1_encode(raw, inp.name, password)
    out.write_bytes(blob)

    esz   = out.stat().st_size
    csize = meta["compressed_size"]
    cp    = (1 - csize / orig) * 100 if orig else 0.0

    print(f"\n  ✅  Encrypted  → {out}")
    print(f"  📄  Original   : {_h(orig)}")
    if orig and csize < orig:
        print(f"  🗜   Compressed : {_h(csize)}  ({cp:.1f}% reduction)")
    else:
        print(f"  🗜   Compressed : stored uncompressed (already compressed input)")
    print(f"  🔐  Output     : {_h(esz)}")
    print(f"  🔑  SHA-256    : {meta['sha256'][:16]}...")


def cmd_decrypt(args):
    inp    = Path(args.input)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    password = args.password or _pwd("  Enter password  : ")
    if args.password:
        _validate_pwd(args.password)

    blob = inp.read_bytes()
    if len(blob) < 5:
        raise ValueError("File is too small to be a valid .empy file.")

    ver = blob[4]
    if ver == VERSION_V2:
        raise ValueError(
            "This is a peer-sealed file. Use 'open' to decrypt it.\n"
            "  empy open <file.empy> --key <your.empy.key>")

    print("  Deriving key & decrypting...")
    raw, meta = _v1_decode(blob, password)

    out_file = outdir / meta["filename"]
    if out_file.exists() and not args.force:
        raise ValueError(f"Output already exists: {out_file}  (use --force to overwrite)")
    out_file.write_bytes(raw)

    print(f"\n  ✅  Decrypted  → {out_file}")
    print(f"  📄  File       : {meta['filename']}")
    print(f"  📦  Size       : {_h(len(raw))}")
    print(f"  🔑  SHA-256    : {meta['sha256'][:16]}...  ✔ verified")
    print(f"  📅  Created    : {meta['created_at']}")


def cmd_seal(args):
    inp = Path(args.input)
    if not inp.exists():
        raise FileNotFoundError(f"Input file not found: {inp}")

    recip_pub_bytes, recip_name = _load_pubkey(args.to)

    default_out = inp.parent / (inp.name + ".empy")
    out = Path(args.output) if args.output else default_out

    if out.exists() and not args.force:
        raise ValueError(f"Output already exists: {out}  (use --force to overwrite)")

    print(f"  Sealing for recipient '{recip_name}'...")

    base_password = args.base_password or _pwd(
        "  Base password (inner layer) : ", confirm=True,
        label="base password")
    peer_password = args.peer_password or _pwd(
        "  Peer password (outer layer) : ", confirm=True,
        label="peer password")

    _, sender_name = _load_privkey(args.key, args.key_password or _pwd(
        "  Key protection password     : ", label="key protection password"))

    print("  Compressing & encrypting inner layer...")
    raw  = inp.read_bytes()
    inner_blob, meta = _v1_encode(raw, inp.name, base_password)

    print("  Applying peer encryption layer...")
    v2_blob = _v2_encode(inner_blob, recip_pub_bytes, sender_name, recip_name, peer_password)
    out.write_bytes(v2_blob)

    esz = out.stat().st_size
    fp  = _fingerprint(recip_pub_bytes)

    print(f"\n  ✅  Sealed     → {out}")
    print(f"  👤  Sender     : {sender_name}")
    print(f"  👥  Recipient  : {recip_name}")
    print(f"  🆔  Recip. FP  : {fp[:32]}...")
    print(f"  🔐  Output     : {_h(esz)}")
    print(f"  🔑  SHA-256    : {meta['sha256'][:16]}...")
    print()
    print("  Two passwords required to open this file:")
    print("   1. Peer password  — shared between sender & recipient out-of-band")
    print("   2. Base password  — used to unlock the inner encrypted payload")


def cmd_open(args):
    inp    = Path(args.input)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    blob = inp.read_bytes()
    if len(blob) < 5:
        raise ValueError("File is too small to be a valid .empy file.")

    ver = blob[4]
    if ver == VERSION_V1:
        raise ValueError(
            "This is a standard encrypted file — use 'decrypt' instead.\n"
            "  empy decrypt <file.empy>")

    key_password  = args.key_password  or _pwd("  Key protection password : ",
                                                label="key protection password")
    peer_password = args.peer_password or _pwd("  Peer password           : ")
    base_password = args.base_password or _pwd("  Base password           : ")

    priv_bytes, my_name = _load_privkey(args.key, key_password)

    print("  Unsealing peer layer...")
    inner_blob, peer_meta = _v2_decode(blob, priv_bytes, peer_password)

    print("  Decrypting inner layer...")
    raw, meta = _v1_decode(inner_blob, base_password)

    out_file = outdir / meta["filename"]
    if out_file.exists() and not args.force:
        raise ValueError(f"Output already exists: {out_file}  (use --force to overwrite)")
    out_file.write_bytes(raw)

    print(f"\n  ✅  Opened     → {out_file}")
    print(f"  👤  Sender     : {peer_meta.get('sender', 'unknown')}")
    print(f"  👥  Recipient  : {peer_meta.get('recipient', 'unknown')}  (you: {my_name})")
    print(f"  📅  Sealed at  : {peer_meta.get('sealed_at', 'unknown')}")
    print(f"  📄  File       : {meta['filename']}")
    print(f"  📦  Size       : {_h(len(raw))}")
    print(f"  🔑  SHA-256    : {meta['sha256'][:16]}...  ✔ verified")


def cmd_info(args):
    inp  = Path(args.input)
    blob = inp.read_bytes()
    if len(blob) < 5:
        raise ValueError("File is too small to be a valid .empy file.")

    ver = blob[4]
    pkg = inp.stat().st_size

    if ver == VERSION_V1:
        # Need password to read encrypted metadata
        password = args.password or _pwd("  Enter password  : ")
        print("  Deriving key...")
        _, meta = _v1_decode(blob, password)

        print(f"\n  ┌───────────────────────────────────────────────────────┐")
        print(f"  │              .empy File Information  (V1)             │")
        print(f"  └───────────────────────────────────────────────────────┘")
        print(f"  Package    : {inp.name}  ({_h(pkg)})")
        print(f"  Version    : {VERSION_V1}  (standard)")
        print(f"  Filename   : {meta['filename']}")
        print(f"  Original   : {_h(meta['original_size'])}")
        print(f"  Compressed : {_h(meta['compressed_size'])}")
        print(f"  SHA-256    : {meta['sha256']}")
        print(f"  Created    : {meta['created_at']}")
        print(f"  Encryption : AES-256-GCM")
        print(f"  KDF        : PBKDF2-HMAC-SHA256  ({PBKDF2_ITER:,} iterations)")

    elif ver == VERSION_V2:
        print(f"\n  ┌───────────────────────────────────────────────────────┐")
        print(f"  │           .empy File Information  (V2 Sealed)         │")
        print(f"  └───────────────────────────────────────────────────────┘")
        # Read the recipient fingerprint without decrypting
        pos = 4 + 1 + SALT_LEN + NONCE_LEN + 32   # skip: MAGIC(4) VER(1) PEER_SALT(32) PEER_NONCE(12) EPH_PUB(32)
        recip_fp = blob[pos:pos+RECIP_FP_LEN].decode("ascii")
        print(f"  Package    : {inp.name}  ({_h(pkg)})")
        print(f"  Version    : {VERSION_V2}  (peer-sealed, double-encrypted)")
        print(f"  Recip. FP  : {recip_fp[:32]}...")
        print(f"  Encryption : X25519-ECDH + AES-256-GCM  (outer)")
        print(f"               AES-256-GCM  (inner)")
        print(f"  KDF        : PBKDF2-HMAC-SHA256 + HKDF-SHA256")
        print(f"  Note       : Use 'open' with your private key to decrypt.")

        if args.password or args.key:
            pass   # Could further decrypt if keys provided, left as future extension

    else:
        raise ValueError(f"Unknown .empy format version: {ver}")

    print()


# ─────────────────────────────────────────────────────
#  Utilities
# ─────────────────────────────────────────────────────

def _h(n: float) -> str:
    n = float(n)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def _validate_pwd(password: str, label: str = "password") -> str:
    if len(password) < MIN_PWD_LEN:
        raise ValueError(
            f"The {label} must be at least {MIN_PWD_LEN} characters long.")
    return password


def _pwd(prompt: str, confirm: bool = False, label: str = "password") -> str:
    p = getpass.getpass(f"  {prompt}")
    if len(p) < MIN_PWD_LEN:
        raise ValueError(
            f"The {label} must be at least {MIN_PWD_LEN} characters long.")
    if confirm:
        p2 = getpass.getpass(f"  Confirm {label} : ")
        if p != p2:
            raise ValueError(f"The {label}s do not match.")
    return p


# ─────────────────────────────────────────────────────
#  In-memory key helpers (used by GUI)
# ─────────────────────────────────────────────────────

def _pubkey_from_str(json_str: str) -> tuple[bytes, str]:
    """Load a public key from JSON string content."""
    data = json.loads(json_str)
    return bytes.fromhex(data["public_key"]), data["name"]


def _privkey_from_str(json_str: str, password: str) -> tuple[bytes, str]:
    """Load and decrypt a private key from JSON string content."""
    data  = json.loads(json_str)
    salt  = bytes.fromhex(data["key_salt"])
    nonce = bytes.fromhex(data["key_nonce"])
    enc   = bytes.fromhex(data["private_key_enc"])
    key   = _pbkdf2(password, salt)
    raw   = _aes_dec(key, nonce, enc, b"empy-privkey")
    return raw, data["name"]


# ─────────────────────────────────────────────────────
#  GUI — embedded single-page app
# ─────────────────────────────────────────────────────

_GUI_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>empy</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,300;0,400;0,500;0,700;1,300&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#06060e;--surface:#0d0d1c;--surface2:#13132b;
  --border:rgba(0,255,136,.12);--border-hi:rgba(0,255,136,.4);
  --accent:#00ff88;--adim:rgba(0,255,136,.12);
  --blue:#4488ff;--bdim:rgba(68,136,255,.12);
  --txt:#c8d4f0;--muted:#424866;--err:#ff4466;--warn:#ffaa00;
  --r:4px;--font:'JetBrains Mono',monospace
}
html,body{height:100%;background:var(--bg);color:var(--txt);font-family:var(--font);font-size:13px;overflow:hidden}
body::after{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.025) 2px,rgba(0,0,0,.025) 4px);pointer-events:none;z-index:999}
.app{display:grid;grid-template-columns:190px 1fr;grid-template-rows:46px 1fr 26px;height:100vh}

/* title bar */
.tb{grid-column:1/-1;background:var(--surface);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 18px;gap:14px;user-select:none}
.logo{color:var(--accent);font-size:15px;font-weight:700;letter-spacing:5px;text-shadow:0 0 20px rgba(0,255,136,.5)}
.logo-sub{color:var(--muted);font-size:10px;font-weight:300;letter-spacing:.5px}
.tb-right{margin-left:auto;color:var(--accent);font-size:10px;letter-spacing:1px}
.tb-right span{animation:blink 1.8s step-end infinite}
@keyframes blink{50%{opacity:0}}

/* sidebar */
.sb{background:var(--surface);border-right:1px solid var(--border);padding:10px 0;display:flex;flex-direction:column;gap:1px;overflow-y:auto}
.ni{display:flex;align-items:center;gap:9px;padding:9px 15px;cursor:pointer;color:var(--muted);font-size:11px;letter-spacing:1.5px;border-left:2px solid transparent;transition:all .14s;user-select:none}
.ni:hover{color:var(--txt);background:var(--adim)}
.ni.on{color:var(--accent);border-left-color:var(--accent);background:var(--adim)}
.ni-icon{font-size:13px;width:17px;text-align:center}
.ndiv{height:1px;background:var(--border);margin:7px 14px}

/* main */
.main{overflow-y:auto;padding:22px;display:flex;flex-direction:column;gap:18px;scrollbar-width:thin;scrollbar-color:var(--border) transparent}
.panel{display:none;flex-direction:column;gap:16px}
.panel.on{display:flex}

.pt{font-size:10px;font-weight:700;color:var(--muted);letter-spacing:3px;padding-bottom:11px;border-bottom:1px solid var(--border)}
.pt em{color:var(--accent);font-style:normal}

/* drop zone */
.dz{border:1px dashed rgba(0,255,136,.2);border-radius:var(--r);padding:28px;text-align:center;cursor:pointer;transition:all .18s;background:var(--surface);position:relative}
.dz:hover,.dz.over{border-color:var(--accent);background:var(--adim)}
.dz.has{border-style:solid;border-color:rgba(0,255,136,.35);background:rgba(0,255,136,.04)}
.dz-icon{font-size:22px;margin-bottom:7px;opacity:.45}
.dz-txt{color:var(--muted);font-size:11px;line-height:1.5}
.dz-name{color:var(--accent);font-size:12px;font-weight:500}
.dz-sz{color:var(--muted);font-size:10px;margin-top:2px}
input[type=file]{display:none}

/* fields */
.field{display:flex;flex-direction:column;gap:5px}
.fl{font-size:10px;font-weight:700;letter-spacing:2px;color:var(--muted)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.pw{position:relative}
.pw .inp{padding-right:38px}
.eye{position:absolute;right:9px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--muted);cursor:pointer;font-size:13px;padding:0;transition:color .14s}
.eye:hover{color:var(--accent)}
.inp{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:8px 11px;color:var(--txt);font-family:var(--font);font-size:13px;outline:none;width:100%;transition:border-color .14s,box-shadow .14s}
.inp:focus{border-color:rgba(0,255,136,.45);box-shadow:0 0 0 2px rgba(0,255,136,.07)}
.inp::placeholder{color:var(--muted)}

/* buttons */
.btn{background:none;border:1px solid var(--border-hi);border-radius:var(--r);padding:10px 18px;color:var(--accent);font-family:var(--font);font-size:11px;font-weight:700;letter-spacing:2px;cursor:pointer;transition:all .14s;display:flex;align-items:center;justify-content:center;gap:8px;width:100%}
.btn:hover{background:var(--adim);box-shadow:0 0 18px rgba(0,255,136,.18)}
.btn:active{transform:scale(.98)}
.btn:disabled{opacity:.3;pointer-events:none}
.btn.blue{border-color:rgba(68,136,255,.5);color:var(--blue)}
.btn.blue:hover{background:var(--bdim);box-shadow:0 0 18px rgba(68,136,255,.18)}

/* console */
.con{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:13px;min-height:76px;font-size:11px;line-height:1.65;white-space:pre-wrap;word-break:break-all}
.ok{color:var(--accent)}.er{color:var(--err)}.dm{color:var(--muted)}.nfo{color:var(--blue)}

/* download link */
.dl{display:inline-flex;align-items:center;gap:7px;margin-top:6px;background:rgba(0,255,136,.07);border:1px solid rgba(0,255,136,.28);border-radius:var(--r);padding:7px 13px;color:var(--accent);cursor:pointer;font-family:var(--font);font-size:11px;font-weight:500;text-decoration:none;transition:all .14s}
.dl:hover{background:rgba(0,255,136,.14)}
.dl.b{background:rgba(68,136,255,.07);border-color:rgba(68,136,255,.3);color:var(--blue)}
.dl.b:hover{background:rgba(68,136,255,.14)}

/* spinner */
.spin{display:inline-block;width:11px;height:11px;border:2px solid rgba(0,255,136,.2);border-top-color:var(--accent);border-radius:50%;animation:rot .65s linear infinite;vertical-align:middle;margin-left:6px}
@keyframes rot{to{transform:rotate(360deg)}}

/* status bar */
.stbar{grid-column:1/-1;background:var(--surface);border-top:1px solid var(--border);padding:0 15px;display:flex;align-items:center;gap:12px;font-size:10px;color:var(--muted)}
.dot{width:5px;height:5px;border-radius:50%;background:var(--accent);box-shadow:0 0 7px var(--accent);flex-shrink:0}

::-webkit-scrollbar{width:3px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}

@media(max-width:660px){
  .app{grid-template-columns:1fr}
  .sb{flex-direction:row;overflow-x:auto;border-right:none;border-bottom:1px solid var(--border);padding:0}
  .ni{border-left:none;border-bottom:2px solid transparent;flex-direction:column;gap:2px;font-size:9px;padding:8px 11px;min-width:52px;white-space:nowrap}
  .ni.on{border-bottom-color:var(--accent);border-left-color:transparent}
  .ndiv{display:none}
  .grid2{grid-template-columns:1fr}
}
</style>
</head>
<body>
<div class="app">

<!-- TITLE BAR -->
<div class="tb">
  <div class="logo">EMPY</div>
  <div class="logo-sub">Empyrean Secure Compression &nbsp;·&nbsp; v__VERSION__ &nbsp;·&nbsp; Copyright Volvi 2026</div>
  <div class="tb-right">&#x25CF; SECURE<span>_</span></div>
</div>

<!-- SIDEBAR -->
<nav class="sb">
  <div class="ni on" data-p="encrypt"><span class="ni-icon">&#x1F510;</span>ENCRYPT</div>
  <div class="ni"    data-p="decrypt"><span class="ni-icon">&#x1F513;</span>DECRYPT</div>
  <div class="ndiv"></div>
  <div class="ni"    data-p="keygen"><span class="ni-icon">&#x1F5DD;</span>KEYGEN</div>
  <div class="ni"    data-p="seal"><span class="ni-icon">&#x1F4E8;</span>SEAL</div>
  <div class="ni"    data-p="open"><span class="ni-icon">&#x1F4EC;</span>OPEN</div>
  <div class="ndiv"></div>
  <div class="ni"    data-p="info"><span class="ni-icon">&#x1F50D;</span>INFO</div>
</nav>

<!-- MAIN -->
<main class="main">

<!-- ENCRYPT -->
<div class="panel on" id="p-encrypt">
  <div class="pt"><em>ENCRYPT</em> &nbsp;&#xB7;&nbsp; STANDARD PASSWORD ENCRYPTION</div>
  <div class="dz" id="dz-encrypt" onclick="pick('encrypt')">
    <input type="file" id="fi-encrypt" onchange="fromInput('encrypt',this)">
    <div class="dz-icon">&#x1F4C2;</div>
    <div class="dz-txt" id="dt-encrypt">Drop any file here, or click to select</div>
  </div>
  <div class="field"><div class="fl">PASSWORD <span style="color:#ff446680">*</span></div>
    <div class="pw"><input class="inp" type="password" id="e-pw" placeholder="minimum 8 characters">
    <button class="eye" onclick="tog('e-pw',this)">&#x25C9;</button></div></div>
  <div class="field"><div class="fl">CONFIRM PASSWORD</div>
    <div class="pw"><input class="inp" type="password" id="e-pw2" placeholder="confirm password">
    <button class="eye" onclick="tog('e-pw2',this)">&#x25C9;</button></div></div>
  <button class="btn" onclick="doEncrypt()">&#x1F510; &nbsp;ENCRYPT FILE</button>
  <div class="con" id="con-encrypt"><span class="dm">Ready &mdash; select a file and set a password.</span></div>
</div>

<!-- DECRYPT -->
<div class="panel" id="p-decrypt">
  <div class="pt"><em>DECRYPT</em> &nbsp;&#xB7;&nbsp; STANDARD FILE DECRYPTION</div>
  <div class="dz" id="dz-decrypt" onclick="pick('decrypt')">
    <input type="file" id="fi-decrypt" accept=".empy" onchange="fromInput('decrypt',this)">
    <div class="dz-icon">&#x1F512;</div>
    <div class="dz-txt" id="dt-decrypt">Drop a .empy file here, or click to select</div>
  </div>
  <div class="field"><div class="fl">PASSWORD</div>
    <div class="pw"><input class="inp" type="password" id="d-pw" placeholder="enter your password">
    <button class="eye" onclick="tog('d-pw',this)">&#x25C9;</button></div></div>
  <button class="btn" onclick="doDecrypt()">&#x1F513; &nbsp;DECRYPT FILE</button>
  <div class="con" id="con-decrypt"><span class="dm">Ready &mdash; select a .empy file and enter the password.</span></div>
</div>

<!-- KEYGEN -->
<div class="panel" id="p-keygen">
  <div class="pt"><em>KEYGEN</em> &nbsp;&#xB7;&nbsp; GENERATE X25519 KEYPAIR</div>
  <div class="field"><div class="fl">YOUR NAME / ALIAS</div>
    <input class="inp" type="text" id="kg-name" placeholder="e.g.  alice"></div>
  <div class="field"><div class="fl">KEY PROTECTION PASSWORD</div>
    <div class="pw"><input class="inp" type="password" id="kg-pw" placeholder="protects your private key file">
    <button class="eye" onclick="tog('kg-pw',this)">&#x25C9;</button></div></div>
  <div class="field"><div class="fl">CONFIRM PASSWORD</div>
    <div class="pw"><input class="inp" type="password" id="kg-pw2" placeholder="confirm">
    <button class="eye" onclick="tog('kg-pw2',this)">&#x25C9;</button></div></div>
  <button class="btn" onclick="doKeygen()">&#x1F5DD; &nbsp;GENERATE KEYPAIR</button>
  <div class="con" id="con-keygen"><span class="dm">Generates a .empy.pub (share freely) and .empy.key (keep secret).</span></div>
</div>

<!-- SEAL -->
<div class="panel" id="p-seal">
  <div class="pt"><em>SEAL</em> &nbsp;&#xB7;&nbsp; PEER-ENCRYPT FOR A SPECIFIC RECIPIENT</div>
  <div class="dz" id="dz-seal" onclick="pick('seal')">
    <input type="file" id="fi-seal" onchange="fromInput('seal',this)">
    <div class="dz-icon">&#x1F4C4;</div>
    <div class="dz-txt" id="dt-seal">Drop the file to seal</div>
  </div>
  <div class="grid2">
    <div class="field"><div class="fl">RECIPIENT PUBLIC KEY (.empy.pub)</div>
      <div class="dz" style="padding:14px" id="dz-spub" onclick="pick('spub')">
        <input type="file" id="fi-spub" onchange="fromInput('spub',this)">
        <div class="dz-txt" id="dt-spub">Drop recipient .empy.pub</div>
      </div></div>
    <div class="field"><div class="fl">YOUR PRIVATE KEY (.empy.key)</div>
      <div class="dz" style="padding:14px" id="dz-skey" onclick="pick('skey')">
        <input type="file" id="fi-skey" onchange="fromInput('skey',this)">
        <div class="dz-txt" id="dt-skey">Drop your .empy.key</div>
      </div></div>
  </div>
  <div class="field"><div class="fl">KEY PROTECTION PASSWORD</div>
    <div class="pw"><input class="inp" type="password" id="s-kpw" placeholder="unlocks your .empy.key">
    <button class="eye" onclick="tog('s-kpw',this)">&#x25C9;</button></div></div>
  <div class="grid2">
    <div class="field"><div class="fl">PEER PASSWORD (outer layer)</div>
      <div class="pw"><input class="inp" type="password" id="s-ppw" placeholder="share with recipient">
      <button class="eye" onclick="tog('s-ppw',this)">&#x25C9;</button></div></div>
    <div class="field"><div class="fl">BASE PASSWORD (inner layer)</div>
      <div class="pw"><input class="inp" type="password" id="s-bpw" placeholder="share with recipient">
      <button class="eye" onclick="tog('s-bpw',this)">&#x25C9;</button></div></div>
  </div>
  <button class="btn" onclick="doSeal()">&#x1F4E8; &nbsp;SEAL FILE</button>
  <div class="con" id="con-seal"><span class="dm">Double-layer: X25519-ECDH outer + AES-256-GCM inner. Needs 3 secrets to open.</span></div>
</div>

<!-- OPEN -->
<div class="panel" id="p-open">
  <div class="pt"><em>OPEN</em> &nbsp;&#xB7;&nbsp; PEER-DECRYPT A SEALED FILE</div>
  <div class="dz" id="dz-open" onclick="pick('open')">
    <input type="file" id="fi-open" accept=".empy" onchange="fromInput('open',this)">
    <div class="dz-icon">&#x1F4EC;</div>
    <div class="dz-txt" id="dt-open">Drop the sealed .empy file</div>
  </div>
  <div class="field"><div class="fl">YOUR PRIVATE KEY (.empy.key)</div>
    <div class="dz" style="padding:14px" id="dz-okey" onclick="pick('okey')">
      <input type="file" id="fi-okey" onchange="fromInput('okey',this)">
      <div class="dz-txt" id="dt-okey">Drop your .empy.key</div>
    </div></div>
  <div class="field"><div class="fl">KEY PROTECTION PASSWORD</div>
    <div class="pw"><input class="inp" type="password" id="o-kpw" placeholder="unlocks your .empy.key">
    <button class="eye" onclick="tog('o-kpw',this)">&#x25C9;</button></div></div>
  <div class="grid2">
    <div class="field"><div class="fl">PEER PASSWORD (outer layer)</div>
      <div class="pw"><input class="inp" type="password" id="o-ppw" placeholder="from sender">
      <button class="eye" onclick="tog('o-ppw',this)">&#x25C9;</button></div></div>
    <div class="field"><div class="fl">BASE PASSWORD (inner layer)</div>
      <div class="pw"><input class="inp" type="password" id="o-bpw" placeholder="from sender">
      <button class="eye" onclick="tog('o-bpw',this)">&#x25C9;</button></div></div>
  </div>
  <button class="btn blue" onclick="doOpen()">&#x1F4EC; &nbsp;OPEN FILE</button>
  <div class="con" id="con-open"><span class="dm">Requires your private key + key password + peer password + base password.</span></div>
</div>

<!-- INFO -->
<div class="panel" id="p-info">
  <div class="pt"><em>INFO</em> &nbsp;&#xB7;&nbsp; INSPECT FILE METADATA</div>
  <div class="dz" id="dz-info" onclick="pick('info')">
    <input type="file" id="fi-info" accept=".empy" onchange="fromInput('info',this)">
    <div class="dz-icon">&#x1F50D;</div>
    <div class="dz-txt" id="dt-info">Drop a .empy file to inspect</div>
  </div>
  <div class="field"><div class="fl">PASSWORD <span style="color:var(--muted)">(required for V1 files)</span></div>
    <div class="pw"><input class="inp" type="password" id="i-pw" placeholder="enter password to read metadata">
    <button class="eye" onclick="tog('i-pw',this)">&#x25C9;</button></div></div>
  <button class="btn" onclick="doInfo()">&#x1F50D; &nbsp;INSPECT FILE</button>
  <div class="con" id="con-info"><span class="dm">V2 peer-sealed files show type info without a password.</span></div>
</div>

</main>

<!-- STATUS BAR -->
<div class="stbar">
  <div class="dot"></div>
  <span>LOCAL &nbsp;&bull;&nbsp; 127.0.0.1</span>
  <span style="color:var(--border-hi)">&middot;</span>
  <span id="stxt">Waiting for input</span>
</div>
</div>

<script>
// ── file state ─────────────────────────────────────────────────
const S = {};

// ── navigation ─────────────────────────────────────────────────
document.querySelectorAll('.ni').forEach(el => {
  el.addEventListener('click', () => {
    document.querySelectorAll('.ni').forEach(n => n.classList.remove('on'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('on'));
    el.classList.add('on');
    document.getElementById('p-' + el.dataset.p).classList.add('on');
  });
});

// ── drag & drop ────────────────────────────────────────────────
['encrypt','decrypt','seal','open','info','spub','skey','okey'].forEach(k => {
  const el = document.getElementById('dz-' + k);
  if (!el) return;
  el.addEventListener('dragover', e => { e.preventDefault(); el.classList.add('over'); });
  el.addEventListener('dragleave', () => el.classList.remove('over'));
  el.addEventListener('drop', e => {
    e.preventDefault(); el.classList.remove('over');
    if (e.dataTransfer.files[0]) load(k, e.dataTransfer.files[0]);
  });
});

function pick(k) { document.getElementById('fi-' + k).click(); }
function fromInput(k, inp) { if (inp.files[0]) load(k, inp.files[0]); }

function load(k, file) {
  const r = new FileReader();
  r.onload = e => {
    const arr = new Uint8Array(e.target.result);
    const b64 = btoa(arr.reduce((s,b) => s + String.fromCharCode(b), ''));
    S[k] = { name: file.name, size: file.size, b64 };
    const td = document.getElementById('dt-' + k);
    const dz = document.getElementById('dz-' + k);
    if (td) td.innerHTML = `<div class="dz-name">${x(file.name)}</div><div class="dz-sz">${sz(file.size)}</div>`;
    if (dz) dz.classList.add('has');
    st('Loaded: ' + file.name);
  };
  r.readAsArrayBuffer(file);
}

// ── helpers ────────────────────────────────────────────────────
function x(s){ return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function sz(n){ if(n<1024) return n+' B'; if(n<1048576) return (n/1024).toFixed(1)+' KB'; if(n<1073741824) return (n/1048576).toFixed(1)+' MB'; return (n/1073741824).toFixed(1)+' GB'; }
function st(m){ document.getElementById('stxt').textContent = m; }

function tog(id, btn) {
  const el = document.getElementById(id);
  el.type = el.type === 'password' ? 'text' : 'password';
  btn.textContent = el.type === 'password' ? '\u25C9' : '\u25CE';
}

function clr(id, lines) {
  const el = document.getElementById('con-' + id);
  el.innerHTML = lines.map(([c,t]) => `<span class="${c}">${x(String(t))}</span>`).join('\n');
}
function app(id, c, t) {
  const el = document.getElementById('con-' + id);
  el.innerHTML += `<span class="${c}">${x(String(t))}</span>\n`;
  el.scrollTop = el.scrollHeight;
}
function spin(id) {
  clr(id, [['dm','Processing...']]);
  document.getElementById('con-'+id).innerHTML += '<span class="spin"></span>';
}

function dlLink(name, b64, blue) {
  const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const url = URL.createObjectURL(new Blob([bytes]));
  const a = document.createElement('a');
  a.href = url; a.download = name;
  a.className = 'dl' + (blue ? ' b' : '');
  a.innerHTML = '&#x2B07; DOWNLOAD &nbsp;' + x(name);
  return a;
}

function txtB64(str) {
  const bytes = new TextEncoder().encode(str);
  return btoa(bytes.reduce((s,b) => s + String.fromCharCode(b), ''));
}

async function api(action, payload) {
  const r = await fetch('/api', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({action, ...payload})
  });
  const d = await r.json();
  if (d.error) throw new Error(d.error);
  return d;
}

// ── ENCRYPT ───────────────────────────────────────────────────
async function doEncrypt() {
  const f = S.encrypt, pw = document.getElementById('e-pw').value, pw2 = document.getElementById('e-pw2').value;
  if (!f) return clr('encrypt',[['er','ERROR: No file selected.']]);
  if (pw.length < 8) return clr('encrypt',[['er','ERROR: Password must be at least 8 characters.']]);
  if (pw !== pw2) return clr('encrypt',[['er','ERROR: Passwords do not match.']]);
  try {
    spin('encrypt');
    const r = await api('encrypt', {file_data:f.b64, filename:f.name, password:pw});
    const el = document.getElementById('con-encrypt'); el.innerHTML = '';
    app('encrypt','ok','&#x2713;  Encrypted successfully');
    app('encrypt','dm','Original  : ' + sz(r.meta.original_size));
    app('encrypt','dm','Output    : ' + r.filename);
    app('encrypt','dm','SHA-256   : ' + r.meta.sha256.slice(0,16) + '...');
    el.appendChild(dlLink(r.filename, r.file_data, false));
    st('Encrypted: ' + r.filename);
  } catch(e){ clr('encrypt',[['er','ERROR: '+e.message]]); st('Error'); }
}

// ── DECRYPT ───────────────────────────────────────────────────
async function doDecrypt() {
  const f = S.decrypt, pw = document.getElementById('d-pw').value;
  if (!f) return clr('decrypt',[['er','ERROR: No file selected.']]);
  if (!pw) return clr('decrypt',[['er','ERROR: Enter a password.']]);
  try {
    spin('decrypt');
    const r = await api('decrypt', {file_data:f.b64, password:pw});
    const el = document.getElementById('con-decrypt'); el.innerHTML = '';
    app('decrypt','ok','&#x2713;  Decrypted successfully');
    app('decrypt','dm','File      : ' + r.meta.filename);
    app('decrypt','dm','Size      : ' + sz(r.meta.original_size));
    app('decrypt','dm','SHA-256   : ' + r.meta.sha256.slice(0,16) + '...  \u2714 verified');
    app('decrypt','dm','Created   : ' + r.meta.created_at);
    el.appendChild(dlLink(r.filename, r.file_data, false));
    st('Decrypted: ' + r.filename);
  } catch(e){ clr('decrypt',[['er','ERROR: '+e.message]]); st('Error'); }
}

// ── KEYGEN ────────────────────────────────────────────────────
async function doKeygen() {
  const name = document.getElementById('kg-name').value.trim();
  const pw = document.getElementById('kg-pw').value, pw2 = document.getElementById('kg-pw2').value;
  if (!name) return clr('keygen',[['er','ERROR: Enter a name/alias.']]);
  if (pw.length < 8) return clr('keygen',[['er','ERROR: Password must be at least 8 characters.']]);
  if (pw !== pw2) return clr('keygen',[['er','ERROR: Passwords do not match.']]);
  try {
    spin('keygen');
    const r = await api('keygen', {name, key_password:pw});
    const el = document.getElementById('con-keygen'); el.innerHTML = '';
    app('keygen','ok',"&#x2713;  Keypair generated for '" + name + "'");
    app('keygen','dm','Fingerprint: ' + r.fingerprint.slice(0,32) + '...');
    app('keygen','nfo','Share .empy.pub freely. Keep .empy.key private.');
    el.appendChild(document.createTextNode('\n'));
    el.appendChild(dlLink(r.pub_filename, txtB64(r.pub_data), false));
    el.appendChild(document.createTextNode('\n'));
    el.appendChild(dlLink(r.key_filename, txtB64(r.key_data), true));
    st('Keypair generated: ' + name);
  } catch(e){ clr('keygen',[['er','ERROR: '+e.message]]); st('Error'); }
}

// ── SEAL ──────────────────────────────────────────────────────
async function doSeal() {
  const f=S.seal, pub=S.spub, key=S.skey;
  const kpw=document.getElementById('s-kpw').value;
  const ppw=document.getElementById('s-ppw').value;
  const bpw=document.getElementById('s-bpw').value;
  if (!f)   return clr('seal',[['er','ERROR: No file selected.']]);
  if (!pub) return clr('seal',[['er','ERROR: No recipient public key loaded.']]);
  if (!key) return clr('seal',[['er','ERROR: No sender private key loaded.']]);
  if (kpw.length<8) return clr('seal',[['er','ERROR: Key password must be at least 8 characters.']]);
  if (ppw.length<8) return clr('seal',[['er','ERROR: Peer password must be at least 8 characters.']]);
  if (bpw.length<8) return clr('seal',[['er','ERROR: Base password must be at least 8 characters.']]);
  try {
    spin('seal');
    const r = await api('seal', {
      file_data:f.b64, filename:f.name,
      pub_key_b64:pub.b64, priv_key_b64:key.b64,
      key_password:kpw, peer_password:ppw, base_password:bpw
    });
    const el = document.getElementById('con-seal'); el.innerHTML = '';
    app('seal','ok','&#x2713;  File sealed successfully');
    app('seal','dm','Recipient : ' + (r.recipient || ''));
    app('seal','dm','SHA-256   : ' + r.meta.sha256.slice(0,16) + '...');
    el.appendChild(dlLink(r.filename, r.file_data, false));
    st('Sealed: ' + r.filename);
  } catch(e){ clr('seal',[['er','ERROR: '+e.message]]); st('Error'); }
}

// ── OPEN ──────────────────────────────────────────────────────
async function doOpen() {
  const f=S.open, key=S.okey;
  const kpw=document.getElementById('o-kpw').value;
  const ppw=document.getElementById('o-ppw').value;
  const bpw=document.getElementById('o-bpw').value;
  if (!f)   return clr('open',[['er','ERROR: No file selected.']]);
  if (!key) return clr('open',[['er','ERROR: No private key loaded.']]);
  if (!kpw) return clr('open',[['er','ERROR: Enter key protection password.']]);
  if (!ppw) return clr('open',[['er','ERROR: Enter peer password.']]);
  if (!bpw) return clr('open',[['er','ERROR: Enter base password.']]);
  try {
    spin('open');
    const r = await api('open', {
      file_data:f.b64, priv_key_b64:key.b64,
      key_password:kpw, peer_password:ppw, base_password:bpw
    });
    const el = document.getElementById('con-open'); el.innerHTML = '';
    app('open','ok','&#x2713;  File opened successfully');
    app('open','dm','Sender    : ' + (r.peer_meta.sender||'unknown'));
    app('open','dm','File      : ' + r.meta.filename);
    app('open','dm','Size      : ' + sz(r.meta.original_size));
    app('open','dm','SHA-256   : ' + r.meta.sha256.slice(0,16) + '...  \u2714 verified');
    el.appendChild(dlLink(r.filename, r.file_data, false));
    st('Opened: ' + r.filename);
  } catch(e){ clr('open',[['er','ERROR: '+e.message]]); st('Error'); }
}

// ── INFO ──────────────────────────────────────────────────────
async function doInfo() {
  const f=S.info, pw=document.getElementById('i-pw').value;
  if (!f) return clr('info',[['er','ERROR: No file selected.']]);
  try {
    spin('info');
    const r = await api('info', {file_data:f.b64, password:pw});
    const el = document.getElementById('con-info'); el.innerHTML = '';
    if (r.version === 1) {
      app('info','ok','&#x2713;  V1 &mdash; Standard Encrypted File');
      app('info','dm','Filename   : ' + r.meta.filename);
      app('info','dm','Original   : ' + sz(r.meta.original_size));
      app('info','dm','Compressed : ' + sz(r.meta.compressed_size));
      app('info','dm','SHA-256    : ' + r.meta.sha256);
      app('info','dm','Created    : ' + r.meta.created_at);
      app('info','dm','Encryption : AES-256-GCM + PBKDF2-SHA256');
    } else {
      app('info','ok','&#x2713;  V2 &mdash; Peer-Sealed File (double-encrypted)');
      app('info','dm','Recip. FP  : ' + r.recip_fp.slice(0,32) + '...');
      app('info','nfo','Use OPEN tab to decrypt with your private key.');
    }
    st('Inspected: ' + f.name);
  } catch(e){ clr('info',[['er','ERROR: '+e.message]]); st('Error'); }
}
</script>
</body>
</html>"""


_GUI_HTML = _GUI_HTML.replace("__VERSION__", PROG_VERSION)


# ─────────────────────────────────────────────────────
#  GUI command — local HTTP server + browser
# ─────────────────────────────────────────────────────

def cmd_gui(args):
    import base64 as _b64
    import threading
    import webbrowser
    from http.server import HTTPServer, BaseHTTPRequestHandler

    port = getattr(args, "port", None) or 7749

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *_): pass  # suppress access logs

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                body = _GUI_HTML.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_error(404)

        def do_POST(self):
            if self.path != "/api":
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length", 0))
            raw    = self.rfile.read(length)
            try:
                result = self._handle(json.loads(raw))
                resp   = json.dumps(result).encode("utf-8")
                self.send_response(200)
            except Exception as exc:
                resp = json.dumps({"error": str(exc)}).encode("utf-8")
                self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

        # ── dispatch ────────────────────────────────────────
        def _handle(self, d):
            action = d.get("action")

            if action == "encrypt":
                raw  = _b64.b64decode(d["file_data"])
                _validate_pwd(d["password"])
                blob, meta = _v1_encode(raw, d["filename"], d["password"])
                return {
                    "ok": True,
                    "filename": d["filename"] + ".empy",
                    "file_data": _b64.b64encode(blob).decode(),
                    "meta": meta,
                }

            if action == "decrypt":
                raw, meta = _v1_decode(_b64.b64decode(d["file_data"]), d["password"])
                return {
                    "ok": True,
                    "filename": meta["filename"],
                    "file_data": _b64.b64encode(raw).decode(),
                    "meta": meta,
                }

            if action == "keygen":
                name = d["name"].strip()
                if not name:
                    raise ValueError("Name cannot be empty.")
                kpwd = d["key_password"]
                _validate_pwd(kpwd, "key protection password")

                priv = X25519PrivateKey.generate()
                pub  = priv.public_key()
                pb   = priv.private_bytes(serialization.Encoding.Raw,
                                          serialization.PrivateFormat.Raw,
                                          serialization.NoEncryption())
                ub   = pub.public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw)
                ksalt  = os.urandom(SALT_LEN)
                knonce = os.urandom(NONCE_LEN)
                kkey   = _pbkdf2(kpwd, ksalt)
                enc_pb = _aes_enc(kkey, knonce, pb, b"empy-privkey")
                fp     = _fingerprint(ub)

                pub_data = json.dumps({
                    "name": name, "public_key": ub.hex(),
                    "fingerprint": fp, "created_at": _now_iso(),
                }, indent=2)
                priv_data = json.dumps({
                    "name": name, "public_key": ub.hex(),
                    "fingerprint": fp, "private_key_enc": enc_pb.hex(),
                    "key_salt": ksalt.hex(), "key_nonce": knonce.hex(),
                    "created_at": _now_iso(),
                }, indent=2)
                return {
                    "ok": True, "fingerprint": fp,
                    "pub_filename": f"{name}.empy.pub", "pub_data": pub_data,
                    "key_filename": f"{name}.empy.key", "key_data": priv_data,
                }

            if action == "seal":
                raw = _b64.b64decode(d["file_data"])
                pub_json  = _b64.b64decode(d["pub_key_b64"]).decode("utf-8")
                priv_json = _b64.b64decode(d["priv_key_b64"]).decode("utf-8")
                recip_pub, recip_name = _pubkey_from_str(pub_json)
                _,         sender_name = _privkey_from_str(priv_json, d["key_password"])
                for label, val in [
                    ("key protection password", d["key_password"]),
                    ("peer password",            d["peer_password"]),
                    ("base password",            d["base_password"]),
                ]:
                    _validate_pwd(val, label)
                inner_blob, meta = _v1_encode(raw, d["filename"], d["base_password"])
                v2_blob = _v2_encode(inner_blob, recip_pub, sender_name,
                                     recip_name, d["peer_password"])
                return {
                    "ok": True,
                    "filename": d["filename"] + ".empy",
                    "file_data": _b64.b64encode(v2_blob).decode(),
                    "meta": meta,
                    "recipient": recip_name,
                }

            if action == "open":
                priv_json = _b64.b64decode(d["priv_key_b64"]).decode("utf-8")
                priv_bytes, _ = _privkey_from_str(priv_json, d["key_password"])
                inner_blob, peer_meta = _v2_decode(
                    _b64.b64decode(d["file_data"]), priv_bytes, d["peer_password"])
                raw, meta = _v1_decode(inner_blob, d["base_password"])
                return {
                    "ok": True,
                    "filename": meta["filename"],
                    "file_data": _b64.b64encode(raw).decode(),
                    "meta": meta, "peer_meta": peer_meta,
                }

            if action == "info":
                blob = _b64.b64decode(d["file_data"])
                if len(blob) < 5:
                    raise ValueError("File too small to be a valid .empy file.")
                ver = blob[4]
                if ver == VERSION_V1:
                    pwd = d.get("password", "")
                    if not pwd:
                        raise ValueError("A password is required to read V1 file metadata.")
                    _, meta = _v1_decode(blob, pwd)
                    return {"ok": True, "version": 1, "meta": meta}
                if ver == VERSION_V2:
                    pos = 4 + 1 + SALT_LEN + NONCE_LEN + 32
                    recip_fp = blob[pos:pos + RECIP_FP_LEN].decode("ascii")
                    return {"ok": True, "version": 2, "recip_fp": recip_fp}
                raise ValueError(f"Unknown .empy version: {ver}")

            raise ValueError(f"Unknown action: {action!r}")

    # Find a free port, starting from the requested one
    start_port = port
    for _candidate in range(start_port, start_port + 16):
        try:
            server = HTTPServer(("127.0.0.1", _candidate), _Handler)
            port = _candidate
            break
        except OSError:
            continue
    else:
        raise ValueError(
            f"Ports {start_port}–{start_port + 15} are all in use. "
            f"Try: empy gui --port <other_port>")

    url = f"http://127.0.0.1:{port}"
    if port != start_port:
        print(f"  ⚠   Port {start_port} was busy — using {port} instead.")

    print(f"  🌐  GUI running at {url}")
    print(f"  ℹ   Opening browser automatically ...")
    print(f"  ⚠   Press Ctrl+C to stop the server.\n")
    threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.\n")


BANNER = (
    "\n"
    "  #######  #    #  #####   #   #  \n"
    "  #        ##  ##  #    #   # #   \n"
    "  #####    # ## #  #####     #    \n"
    "  #        #    #  #         #    \n"
    "  #######  #    #  #         #    \n"
    "\n"
    "  Empyrean Secure Compression  v" + PROG_VERSION + "\n"
    "  AES-256-GCM  X25519-ECDH  PBKDF2  HKDF  zlib\n"
    "  Copyright Volvi 2026\n"
)


# ─────────────────────────────────────────────────────
#  CLI / GUI entry point
# ─────────────────────────────────────────────────────

def main():
    # ── Fast-path: no args or --gui flag → launch GUI immediately ────────────
    # We check raw sys.argv so the browser opens before argparse does any work.
    _want_gui = (len(sys.argv) == 1
                 or sys.argv[1] in ("gui", "--gui", "-g"))
    if _want_gui:
        print(BANNER)
        port = 7749
        # Allow  --port N  even in gui fast-path
        for i, a in enumerate(sys.argv):
            if a in ("--port", "-P") and i + 1 < len(sys.argv):
                try:    port = int(sys.argv[i + 1])
                except: pass
        class _FakeArgs:
            pass
        fa = _FakeArgs(); fa.port = port
        cmd_gui(fa)
        return

    p = argparse.ArgumentParser(
        prog="empy",
        description=(
            "empy — Empyrean Secure Compression\n"
            "Copyright Volvi 2026\n\n"
            "Run without arguments (or with --gui) to open the browser GUI.\n"
            "Append a subcommand to use the CLI."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
CLI examples:
  python empy.py encrypt  photo.jpg
  python empy.py decrypt  photo.jpg.empy  --outdir ./recovered/
  python empy.py info     photo.jpg.empy
  python empy.py keygen   --name alice
  python empy.py seal     secret.pdf --to bob.empy.pub --key alice.empy.key
  python empy.py open     secret.pdf.empy --key bob.empy.key

GUI:
  python empy.py              (opens browser UI automatically)
  python empy.py --gui
  python empy.py gui --port 8080
        """,
    )
    p.add_argument("--version", action="version",
                   version=f"empy {PROG_VERSION} — Empyrean Secure Compression — Copyright Volvi 2026")
    p.add_argument("--gui", "-g", action="store_true",
                   help="Launch the browser-based GUI (default when no args given)")
    sub = p.add_subparsers(dest="command")

    # encrypt
    e = sub.add_parser("encrypt", help="Encrypt a file → .empy  (standard)")
    e.add_argument("input")
    e.add_argument("output", nargs="?", help="Output path (default: <input>.empy)")
    e.add_argument("-p", "--password")
    e.add_argument("-f", "--force", action="store_true", help="Overwrite existing output")

    # decrypt
    d = sub.add_parser("decrypt", help="Decrypt a standard .empy file")
    d.add_argument("input")
    d.add_argument("-o", "--outdir", default=".", help="Output directory (default: .)")
    d.add_argument("-p", "--password")
    d.add_argument("-f", "--force", action="store_true")

    # info
    i = sub.add_parser("info", help="Inspect .empy file metadata")
    i.add_argument("input")
    i.add_argument("-p", "--password", help="Password (needed for V1 files)")
    i.add_argument("--key", help="Private key file (for V2 peer-sealed files)")

    # keygen
    kg = sub.add_parser("keygen", help="Generate an X25519 peer keypair")
    kg.add_argument("--name", required=True, help="Your alias (e.g. alice)")
    kg.add_argument("--outdir", help="Directory to save keypair (default: .)")
    kg.add_argument("--key-password", help="Password to protect the private key")
    kg.add_argument("-f", "--force", action="store_true", help="Overwrite existing keys")

    # seal
    sl = sub.add_parser("seal", help="Peer-encrypt a file (double-layered)")
    sl.add_argument("input")
    sl.add_argument("--to",  required=True, metavar="RECIP.empy.pub",
                    help="Recipient's public key file")
    sl.add_argument("--key", required=True, metavar="SENDER.empy.key",
                    help="Your private key file")
    sl.add_argument("-o", "--output", help="Output path (default: <input>.empy)")
    sl.add_argument("--base-password",  help="Inner layer password")
    sl.add_argument("--peer-password",  help="Outer layer peer password")
    sl.add_argument("--key-password",   help="Private key protection password")
    sl.add_argument("-f", "--force", action="store_true")

    # open
    op = sub.add_parser("open", help="Peer-decrypt a sealed .empy file")
    op.add_argument("input")
    op.add_argument("--key", required=True, metavar="MY.empy.key",
                    help="Your private key file")
    op.add_argument("-o", "--outdir", default=".", help="Output directory (default: .)")
    op.add_argument("--base-password",  help="Inner layer password")
    op.add_argument("--peer-password",  help="Outer layer peer password")
    op.add_argument("--key-password",   help="Private key protection password")
    op.add_argument("-f", "--force", action="store_true")

    # gui (subcommand form)
    gu = sub.add_parser("gui", help="Launch the browser-based GUI")
    gu.add_argument("--port", type=int, default=7749, help="Local port (default: 7749)")

    args = p.parse_args()

    # --gui flag or bare 'gui' subcommand
    if getattr(args, "gui", False) or args.command == "gui":
        print(BANNER)
        cmd_gui(args)
        return

    # No subcommand given → print help
    if not args.command:
        print(BANNER)
        p.print_help()
        sys.exit(0)

    print(BANNER)

    dispatch = {
        "encrypt": cmd_encrypt,
        "decrypt": cmd_decrypt,
        "info"   : cmd_info,
        "keygen" : cmd_keygen,
        "seal"   : cmd_seal,
        "open"   : cmd_open,
    }

    try:
        dispatch[args.command](args)
    except (ValueError, FileNotFoundError, PermissionError) as err:
        print(f"\n  ❌  ERROR: {err}\n")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n  Aborted.\n")
        sys.exit(1)

    print()


if __name__ == "__main__":
    main()
