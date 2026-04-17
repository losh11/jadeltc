#!/usr/bin/env python3
"""
End-to-end PSBT signing tests against a real Jade device.

Test 1: Standard LTC PSBTv0 signing (P2WPKH)
Test 2: Regression — sign_mweb_input RPC is removed (returns UNKNOWN_METHOD)
Test 3: Pure-MWEB PSBTv2 signing via sign_psbt

Requirements (serial):
    uv run --with cbor2 --with pyserial --with ecdsa --with blake3 --with base58 python test_ltc_psbt.py [device_port]

Requirements (BLE — scan for devices):
    uv run --with cbor2 --with pyserial --with ecdsa --with blake3 --with base58 --with bleak --with aioitertools python test_ltc_psbt.py --ble-scan

Requirements (BLE — run tests):
    uv run --with cbor2 --with pyserial --with ecdsa --with blake3 --with base58 --with bleak --with aioitertools python test_ltc_psbt.py --ble
    uv run --with cbor2 --with pyserial --with ecdsa --with blake3 --with base58 --with bleak --with aioitertools python test_ltc_psbt.py --bleid <serial_suffix>

If the Jade is locked, this script will request PIN entry on-device.
"""

import struct
import sys
import os
import hashlib
import hmac
import time
import argparse
import json
import logging
import threading
import _thread
import urllib.error
import urllib.request

# Force unbuffered stdout so progress is visible immediately
sys.stdout.reconfigure(line_buffering=True)

import blake3 as blake3_mod
import base58
from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point

sys.path.insert(0, os.path.dirname(__file__))
from jadepy import JadeAPI, JadeError

# Enable jadepy logging so BLE scan/connect progress is visible
jadehandler = logging.StreamHandler()
jadehandler.setLevel(logging.INFO)

logger = logging.getLogger('jadepy.jade')
logger.setLevel(logging.DEBUG)
logger.addHandler(jadehandler)

DEFAULT_SERIAL_TIMEOUT = 2.0
DEFAULT_BOOT_TIMEOUT = 30.0
DEFAULT_POLL_INTERVAL = 0.5
DEFAULT_BLE_SCAN_TIMEOUT = 10


# ---------------------------------------------------------------------------
#  Helpers: compact-size / PSBT key-value encoding
# ---------------------------------------------------------------------------

def compact_size(n):
    if n < 0xfd:
        return bytes([n])
    elif n < 0x10000:
        return b'\xfd' + struct.pack('<H', n)
    elif n < 0x100000000:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)


def kv(key_type, key_data, value):
    """Encode a single PSBT key-value pair."""
    key = bytes([key_type]) + key_data
    return compact_size(len(key)) + key + compact_size(len(value)) + value


def separator():
    return b'\x00'


# ---------------------------------------------------------------------------
#  Helpers: Bitcoin transaction serialization
# ---------------------------------------------------------------------------

def serialize_tx(version, inputs, outputs, locktime):
    """Serialize a minimal Bitcoin transaction (no witness)."""
    tx = struct.pack('<i', version)
    tx += compact_size(len(inputs))
    for txid, vout, script_sig, sequence in inputs:
        tx += txid  # 32 bytes, internal byte order
        tx += struct.pack('<I', vout)
        tx += compact_size(len(script_sig)) + script_sig
        tx += struct.pack('<I', sequence)
    tx += compact_size(len(outputs))
    for amount, script_pubkey in outputs:
        tx += struct.pack('<q', amount)
        tx += compact_size(len(script_pubkey)) + script_pubkey
    tx += struct.pack('<I', locktime)
    return tx


def witness_utxo(amount, script_pubkey):
    """Serialize a witness UTXO (CTxOut): 8-byte LE amount + varint script."""
    return struct.pack('<q', amount) + compact_size(len(script_pubkey)) + script_pubkey


def hash160(data):
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()


def p2wpkh_script(pubkey_hash):
    """OP_0 <20-byte-hash>"""
    return b'\x00\x14' + pubkey_hash


def txid_of(raw_tx):
    return hashlib.sha256(hashlib.sha256(raw_tx).digest()).digest()


# ---------------------------------------------------------------------------
#  Helpers: BIP32 path encoding
# ---------------------------------------------------------------------------

H = 0x80000000  # hardened offset


def encode_path(path):
    return b''.join(struct.pack('<I', p) for p in path)


def bip32_derivation_kv(pubkey, fingerprint, path):
    """Input/output type 0x06: BIP32 derivation."""
    value = struct.pack('<I', fingerprint) + encode_path(path)
    return kv(0x06, pubkey, value)


def key_origin_kv(key_type, pubkey, fingerprint_bytes, path):
    """Encode a key-origin map entry using raw 4-byte fingerprint bytes."""
    return kv(key_type, pubkey, fingerprint_bytes + encode_path(path))


# ---------------------------------------------------------------------------
#  Helpers: MWEB crypto
# ---------------------------------------------------------------------------

def mweb_hashed(tag_byte, data):
    """BLAKE3(tag_byte || data) -> 32 bytes."""
    h = blake3_mod.blake3()
    h.update(bytes([tag_byte]))
    h.update(data)
    return h.digest()


_G = SECP256k1.generator
_order = SECP256k1.order
_curve = SECP256k1.curve
_p = _curve.p()


def _compress(point):
    """EC Point → 33-byte compressed pubkey."""
    prefix = b'\x02' if point.y() % 2 == 0 else b'\x03'
    return prefix + point.x().to_bytes(32, 'big')


def _decompress(pubkey_33):
    """33-byte compressed pubkey → EC Point."""
    prefix = pubkey_33[0]
    x = int.from_bytes(pubkey_33[1:], 'big')
    y_sq = (pow(x, 3, _p) + 7) % _p
    y = pow(y_sq, (_p + 1) // 4, _p)
    if (y % 2 == 0) != (prefix == 0x02):
        y = _p - y
    return Point(_curve, x, y)


def ec_pubkey(secret):
    """Compute compressed public key from 32-byte secret."""
    s = int.from_bytes(secret, 'big')
    return _compress(s * _G)


def ec_point_mul(pubkey_bytes, scalar):
    """Multiply a public key point by a scalar."""
    P = _decompress(pubkey_bytes)
    s = int.from_bytes(scalar, 'big')
    return _compress(s * P)


def ec_point_add(pubkey_a, pubkey_b):
    """Add two public key points."""
    A = _decompress(pubkey_a)
    B = _decompress(pubkey_b)
    return _compress(A + B)


def random_valid_secret():
    """Generate a random non-zero secp256k1 scalar encoded in 32 bytes."""
    while True:
        candidate = os.urandom(32)
        scalar = int.from_bytes(candidate, 'big')
        if 0 < scalar < _order:
            return candidate


def derive_mweb_stealth_components(scan_key, spend_pub, address_index):
    """Return (A_i, B_i) for an MWEB address index."""
    mi_input = struct.pack('<I', address_index) + scan_key
    m_i = mweb_hashed(ord('A'), mi_input)
    mi_pub = ec_pubkey(m_i)
    Bi = ec_point_add(spend_pub, mi_pub)
    Ai = ec_point_mul(Bi, scan_key)
    return Ai, Bi


def derive_mweb_spent_output_pubkey(scan_key, spend_pub, address_index, key_exchange_pubkey):
    """Return (shared_secret, spent_output_pubkey) for a synthetic MWEB UTXO."""
    ecdh_result = ec_point_mul(key_exchange_pubkey, scan_key)
    shared_secret = mweb_hashed(ord('D'), ecdh_result)
    out_key_hash = mweb_hashed(ord('O'), shared_secret)
    _, Bi = derive_mweb_stealth_components(scan_key, spend_pub, address_index)
    Ko = ec_point_mul(Bi, out_key_hash)
    return shared_secret, Ko


# ---------------------------------------------------------------------------
#  Helpers: BIP32 public child derivation (non-hardened only)
# ---------------------------------------------------------------------------

def bip32_derive_child_pubkey(xpub_str, *indices):
    """Derive a non-hardened child pubkey from an xpub string.
    Returns (child_pubkey_33bytes, child_chaincode_32bytes)."""
    raw = base58.b58decode_check(xpub_str)
    # xpub: 4 version + 1 depth + 4 fingerprint + 4 child_number + 32 chaincode + 33 pubkey
    chaincode = raw[13:45]
    pubkey = raw[45:78]

    for idx in indices:
        assert idx < H, "Only non-hardened derivation supported"
        data = pubkey + struct.pack('>I', idx)
        I = hmac.new(chaincode, data, hashlib.sha512).digest()
        IL, IR = I[:32], I[32:]
        # child_pubkey = point(IL) + parent_pubkey
        IL_pub = ec_pubkey(IL)
        pubkey = ec_point_add(IL_pub, pubkey)
        chaincode = IR

    return pubkey


def xpub_fingerprint(xpub_str):
    """Get the master fingerprint from a root xpub."""
    raw = base58.b58decode_check(xpub_str)
    pubkey = raw[45:78]
    return hash160(pubkey)[:4]


# ---------------------------------------------------------------------------
#  Helpers: PSBT parsing (minimal, for verification)
# ---------------------------------------------------------------------------

def read_compact_size(data, offset):
    b = data[offset]
    if b < 0xfd:
        return b, offset + 1
    elif b == 0xfd:
        return struct.unpack_from('<H', data, offset + 1)[0], offset + 3
    elif b == 0xfe:
        return struct.unpack_from('<I', data, offset + 1)[0], offset + 5
    else:
        return struct.unpack_from('<Q', data, offset + 1)[0], offset + 9


def parse_psbt_sections(data):
    """Parse raw PSBT bytes into sections of key-value dicts.
    Returns (globals, [inputs], [outputs]).
    Each section is a list of (key_type, key_data, value) tuples.
    """
    assert data[:5] == b'psbt\xff', "Bad PSBT magic"
    pos = 5

    sections = []
    current = []

    while pos < len(data):
        key_len, pos = read_compact_size(data, pos)
        if key_len == 0:
            sections.append(current)
            current = []
            continue
        key = data[pos:pos + key_len]
        pos += key_len
        val_len, pos = read_compact_size(data, pos)
        val = data[pos:pos + val_len]
        pos += val_len
        current.append((key[0], key[1:], val))

    if current:
        sections.append(current)

    # First section is globals, then inputs, then outputs
    return sections


def find_field(section, key_type):
    """Find first field with given key_type in a section."""
    for kt, kd, v in section:
        if kt == key_type:
            return (kd, v)
    return None


# ---------------------------------------------------------------------------
#  BLE device scanning and selection
# ---------------------------------------------------------------------------

def scan_for_jade_devices(scan_timeout=DEFAULT_BLE_SCAN_TIMEOUT):
    """Scan for BLE devices advertising as Jade. Returns list of (name, address)."""
    try:
        import bleak
    except ImportError:
        print("ERROR: bleak not installed. Add --with bleak --with aioitertools to your uv command.",
              file=sys.stderr)
        sys.exit(1)

    import asyncio

    async def _scan():
        print(f"Scanning for Jade BLE devices ({scan_timeout}s)...", flush=True)
        devices = await bleak.BleakScanner.discover(timeout=scan_timeout)
        jade_devices = []
        for dev in devices:
            if dev.name and dev.name.startswith('Jade'):
                jade_devices.append((dev.name, dev.address))
        return jade_devices

    return asyncio.run(_scan())


def select_ble_device(scan_timeout=DEFAULT_BLE_SCAN_TIMEOUT):
    """Scan for Jade BLE devices and interactively select one.
    Returns the serial_number filter string (or None for a bare 'Jade' name)."""
    devices = scan_for_jade_devices(scan_timeout)

    if not devices:
        print("\nNo Jade BLE devices found. Ensure your Jade is:", flush=True)
        print("  - Powered on and past the boot screen", flush=True)
        print("  - Bluetooth enabled (check Jade settings)", flush=True)
        print("  - Not already connected to another host", flush=True)
        sys.exit(1)

    print(f"\nFound {len(devices)} Jade device(s):\n", flush=True)
    for i, (name, addr) in enumerate(devices, 1):
        print(f"  [{i}] {name}  ({addr})", flush=True)

    if len(devices) == 1:
        name, addr = devices[0]
        print(f"\nAuto-selecting: {name}\n", flush=True)
        parts = name.split()
        return parts[-1] if len(parts) > 1 else None

    print()
    while True:
        try:
            raw = input(f"Select device [1-{len(devices)}]: ").strip()
            if not raw:
                continue
            choice = int(raw)
            if 1 <= choice <= len(devices):
                name, addr = devices[choice - 1]
                parts = name.split()
                return parts[-1] if len(parts) > 1 else None
        except (ValueError, EOFError):
            pass
        except KeyboardInterrupt:
            print()
            sys.exit(1)
        print(f"Please enter a number between 1 and {len(devices)}", flush=True)


def parse_args():
    parser = argparse.ArgumentParser(description='Run end-to-end PSBT signing tests against a Jade device.')
    parser.add_argument('serialport', nargs='?', default=None,
                        help='Serial device path. Defaults to auto-detect.')
    parser.add_argument('--ble', action='store_true', default=False,
                        help='Connect over BLE instead of serial.')
    parser.add_argument('--bleid', default=None,
                        help='BLE device serial number (suffix filter). Implies --ble.')
    parser.add_argument('--ble-scan', dest='ble_scan', action='store_true', default=False,
                        help='Scan for Jade BLE devices and exit.')
    parser.add_argument('--ble-scan-timeout', dest='ble_scan_timeout', type=float,
                        default=DEFAULT_BLE_SCAN_TIMEOUT,
                        help=f'BLE scan timeout in seconds (default: {DEFAULT_BLE_SCAN_TIMEOUT}).')
    parser.add_argument('--serial-timeout', dest='serial_timeout', type=float,
                        default=DEFAULT_SERIAL_TIMEOUT,
                        help=f'Per-read serial timeout in seconds (default: {DEFAULT_SERIAL_TIMEOUT:g}).')
    parser.add_argument('--boot-timeout', dest='boot_timeout', type=float,
                        default=DEFAULT_BOOT_TIMEOUT,
                        help=f'Maximum time to wait for Jade to answer after connect (default: {DEFAULT_BOOT_TIMEOUT:g}).')
    parser.add_argument('--poll-interval', dest='poll_interval', type=float,
                        default=DEFAULT_POLL_INTERVAL,
                        help=f'Polling interval while waiting for Jade to boot (default: {DEFAULT_POLL_INTERVAL:g}).')
    parser.add_argument('--log', dest='loglevel', default='INFO',
                        choices=['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL'],
                        help='Logging level (default: INFO).')
    args = parser.parse_args()
    jadehandler.setLevel(getattr(logging, args.loglevel))
    if args.bleid:
        args.ble = True
    if args.ble_scan:
        args.ble = True
    return args


def rpc_with_timeout(fn, timeout, label="RPC"):
    """Run fn() in the main thread with a watchdog timer.

    Uses the same pattern as test_jade.py: a Timer thread sends
    KeyboardInterrupt to the main thread if the call takes too long.
    The RPC stays on the main thread so bleak's event loop works correctly.
    """
    timer = threading.Timer(timeout, _thread.interrupt_main)
    timer.start()
    try:
        return fn()
    except KeyboardInterrupt:
        raise TimeoutError(
            f"{label} timed out after {timeout:g}s — no response from device")
    finally:
        timer.cancel()


def get_version_info(jade, timeout):
    """Get version info with a hard timeout."""
    print("Querying device info...", flush=True)
    return rpc_with_timeout(
        lambda: jade.get_version_info(nonblocking=True),
        timeout=timeout,
        label="get_version_info")


def unlock_jade(jade, timeout):
    """Authenticate with the Jade device (PIN entry + pinserver).

    The user must enter their PIN on the Jade screen.  The pinserver
    handshake is handled automatically via HTTP.
    """
    print("Authenticating — please enter your PIN on the Jade device...", flush=True)
    try:
        result = rpc_with_timeout(
            lambda: jade.auth_user('litecoin', http_request_fn=pinserver_http_request),
            timeout=timeout,
            label="auth_user")
    except JadeError as exc:
        if exc.code == JadeError.USER_CANCELLED:
            raise SystemExit("Unlock cancelled on Jade.")
        raise
    if result is True:
        print("Unlocked!", flush=True)
        return True
    print(f"Auth result: {result}", flush=True)
    return False


def pinserver_http_request(params):
    use_json = params.get('accept') in ('json', 'application/json')
    url = next((candidate for candidate in params['urls'] if not candidate.endswith('.onion')), None)
    if url is None:
        return {'body': None}

    data = None
    headers = {}
    if use_json:
        headers['Accept'] = 'application/json'

    if params['method'] == 'POST':
        payload = params['data']
        if use_json:
            data = json.dumps(payload).encode('utf-8')
            headers['Content-Type'] = 'application/json'
        elif isinstance(payload, str):
            data = payload.encode('utf-8')
        else:
            data = payload
    elif params['method'] != 'GET':
        raise ValueError(f"Unsupported HTTP method: {params['method']}")

    request = urllib.request.Request(url, data=data, headers=headers, method=params['method'])

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
            if use_json:
                return {'body': json.loads(body.decode(response.headers.get_content_charset() or 'utf-8'))}

            content_type = response.headers.get_content_type()
            charset = response.headers.get_content_charset()
            if charset or content_type.startswith('text/'):
                return {'body': body.decode(charset or 'utf-8')}
            return {'body': body}
    except urllib.error.URLError:
        return {'body': None}


def get_mweb_context(jade):
    print("  Exporting scan key... (confirm on device)")
    scan_key = bytes(jade.get_mweb_scan_key('litecoin'))
    scan_pub = ec_pubkey(scan_key)

    root_xpub = jade.get_xpub('litecoin', [])
    fingerprint_bytes = xpub_fingerprint(root_xpub)
    fingerprint = struct.unpack('<I', fingerprint_bytes)[0]

    spend_path = [H | 0, H | 100, H | 1]
    spend_xpub_str = jade.get_xpub('litecoin', spend_path)
    spend_xpub_bytes = base58.b58decode_check(spend_xpub_str)
    spend_pub = spend_xpub_bytes[-33:]

    print(f"  Scan key: {scan_key.hex()}", flush=True)
    print(f"  Scan pubkey: {scan_pub.hex()}", flush=True)
    print(f"  Master fingerprint: {fingerprint:08x}", flush=True)
    print(f"  Spend pubkey: {spend_pub.hex()}", flush=True)

    return {
        'scan_key': scan_key,
        'scan_pub': scan_pub,
        'spend_pub': spend_pub,
        'fingerprint': fingerprint,
        'fingerprint_bytes': fingerprint_bytes,
        'scan_path': [H | 0, H | 100, H | 0],
        'spend_path': spend_path,
    }


# ---------------------------------------------------------------------------
#  Test 1: Standard LTC PSBTv0
# ---------------------------------------------------------------------------

def test_standard_ltc(jade):
    print("\n=== Test 1: Standard LTC PSBTv0 Signing ===\n")

    # 1. Get fingerprint + xpub (minimize Jade calls to avoid timeout)
    root_xpub = jade.get_xpub('litecoin', [])
    fingerprint_bytes = xpub_fingerprint(root_xpub)
    fingerprint = struct.unpack('<I', fingerprint_bytes)[0]
    print(f"  Master fingerprint: {fingerprint:08x}", flush=True)

    account_xpub = jade.get_xpub('litecoin', [H | 84, H | 2, H | 0])
    print(f"  xpub (m/84'/2'/0'): {account_xpub}", flush=True)

    # Derive child pubkey at m/84'/2'/0'/0/0 locally (non-hardened)
    child_pubkey = bip32_derive_child_pubkey(account_xpub, 0, 0)
    print(f"  Child pubkey (m/84'/2'/0'/0/0): {child_pubkey.hex()}", flush=True)

    # 2. Build P2WPKH scriptPubKey
    pkh = hash160(child_pubkey)
    spk = p2wpkh_script(pkh)
    print(f"  P2WPKH scriptPubKey: {spk.hex()}", flush=True)

    # 3. Create a fake previous transaction paying to our address
    input_amount = 100000  # 0.001 LTC
    fake_prev_tx = serialize_tx(
        version=2,
        inputs=[(b'\x00' * 32, 0xffffffff, b'\x01\x00', 0xffffffff)],  # coinbase-like
        outputs=[(input_amount, spk)],
        locktime=0,
    )
    prev_txid = txid_of(fake_prev_tx)
    print(f"  Fake prev txid: {prev_txid[::-1].hex()}", flush=True)

    # 4. Build the unsigned spending transaction
    output_amount = 90000  # fee = 10000
    # Dummy destination: OP_RETURN
    dest_script = b'\x6a\x04test'  # OP_RETURN "test"

    unsigned_tx = serialize_tx(
        version=2,
        inputs=[(prev_txid, 0, b'', 0xfffffffd)],
        outputs=[(output_amount, dest_script)],
        locktime=0,
    )

    # 5. Build PSBTv0
    psbt = b'psbt\xff'

    # Global: unsigned tx (type 0x00)
    psbt += kv(0x00, b'', unsigned_tx)
    psbt += separator()

    # Input 0: witness_utxo (type 0x01) + BIP32 derivation (type 0x06)
    wutxo = witness_utxo(input_amount, spk)
    path = [H | 84, H | 2, H | 0, 0, 0]
    psbt += kv(0x01, b'', wutxo)
    psbt += bip32_derivation_kv(child_pubkey, fingerprint, path)
    psbt += separator()

    # Output 0: empty (no metadata needed for OP_RETURN)
    psbt += separator()

    print(f"  PSBT size: {len(psbt)} bytes", flush=True)
    print(f"  Sending to Jade for signing... (confirm on device)", flush=True)

    # 6. Sign
    signed_psbt = jade.sign_psbt('litecoin', psbt)
    print(f"  Signed PSBT size: {len(signed_psbt)} bytes", flush=True)

    # 7. Parse and verify signature
    sections = parse_psbt_sections(bytes(signed_psbt))
    assert len(sections) >= 2, "Expected at least global + 1 input section"

    input_section = sections[1]
    sig_field = find_field(input_section, 0x02)  # PARTIAL_SIG
    if sig_field:
        sig_pubkey, sig_value = sig_field
        print(f"  Signature found!", flush=True)
        print(f"    Pubkey: {sig_pubkey.hex()}", flush=True)
        print(f"    Sig ({len(sig_value)} bytes): {sig_value.hex()}", flush=True)
        print("\n  *** Test 1 PASSED ***")
        return True
    else:
        print("  ERROR: No partial signature found in signed PSBT!")
        print("  Fields in input section:")
        for kt, kd, v in input_section:
            print(f"    type=0x{kt:02x} key_data={kd.hex()} value_len={len(v)}", flush=True)
        print("\n  *** Test 1 FAILED ***")
        return False


# ---------------------------------------------------------------------------
#  Test 2: sign_mweb_input RPC removal (regression)
# ---------------------------------------------------------------------------

def test_sign_mweb_input_removed(jade):
    """
    The standalone sign_mweb_input RPC has been removed; the atomic sign_psbt
    path (Test 3) is now the only way to produce an MWEB input signature.
    Invoking the method directly must be rejected as UNKNOWN_METHOD (-32601).
    Dummy parameters are sufficient because dashboard.c rejects the method
    before any parameter validation.
    """
    print("\n=== Test 2: sign_mweb_input RPC removed (regression) ===\n")

    dummy = {
        'network': 'litecoin',
        'features': 0x01,
        'spent_output_id': b'\x00' * 32,
        'spent_output_pk': b'\x02' + b'\x00' * 32,
        'amount': 100000,
        'key_exchange_pk': b'\x02' + b'\x00' * 32,
        'address_index': 0,
    }
    try:
        jade._jadeRpc('sign_mweb_input', dummy)
    except JadeError as e:
        if e.code == JadeError.UNKNOWN_METHOD:
            print(f"  Rejected with UNKNOWN_METHOD as expected (code={e.code}, message={e.message!r})",
                  flush=True)
            print("\n  *** Test 2 PASSED ***")
            return True
        print(f"  Unexpected error code={e.code} message={e.message!r}", flush=True)
        print("\n  *** Test 2 FAILED ***")
        return False
    print("  ERROR: sign_mweb_input succeeded — the RPC should be removed!", flush=True)
    print("\n  *** Test 2 FAILED ***")
    return False


def test_mweb_psbt(jade, mweb_ctx):
    print("\n=== Test 3: MWEB PSBTv2 Signing (sign_psbt) ===\n")

    scan_key = mweb_ctx['scan_key']
    spend_pub = mweb_ctx['spend_pub']
    fingerprint_bytes = mweb_ctx['fingerprint_bytes']

    input_address_index = 0
    output_address_index = 1
    input_amount = 100000
    output_amount = 90000
    kernel_fee = input_amount - output_amount
    input_features = 0x01  # STEALTH_KEY_BIT
    output_features = 0x01  # STANDARD_FIELDS_BIT

    kex_secret = random_valid_secret()
    kex_pk = ec_pubkey(kex_secret)
    shared_secret, spent_output_pubkey = derive_mweb_spent_output_pubkey(
        scan_key, spend_pub, input_address_index, kex_pk)
    spent_output_id = os.urandom(32)
    spent_output_commit = b'\x08' + os.urandom(32)

    dest_Ai, dest_Bi = derive_mweb_stealth_components(
        scan_key, spend_pub, output_address_index)
    stealth_address = dest_Ai + dest_Bi

    print(f"  Shared secret: {shared_secret.hex()}", flush=True)
    print(f"  Key exchange pubkey: {kex_pk.hex()}", flush=True)
    print(f"  Spent output id: {spent_output_id.hex()}", flush=True)
    print(f"  Spent output pubkey: {spent_output_pubkey.hex()}", flush=True)
    print(f"  Destination stealth payload: {stealth_address.hex()}", flush=True)
    print(f"  Input amount: {input_amount}", flush=True)
    print(f"  Output amount: {output_amount}", flush=True)
    print(f"  Kernel fee: {kernel_fee}", flush=True)

    # Build a canonical pure-MWEB PSBTv2 matching ltcsuite/python-psbt:
    # - no PREVOUT_HASH / PREVOUT_INDEX for the MWEB input
    # - one MWEB output (amount + stealth address)
    # - one kernel carrying the fee
    psbt = b'psbt\xff'
    psbt += kv(0xfb, b'', struct.pack('<I', 2))  # PSBT version
    psbt += kv(0x02, b'', struct.pack('<I', 2))  # tx version
    psbt += kv(0x04, b'', compact_size(1))       # input count
    psbt += kv(0x05, b'', compact_size(1))       # output count
    psbt += kv(0x92, b'', compact_size(1))       # kernel count
    psbt += separator()

    psbt += kv(0x90, b'', spent_output_id)
    psbt += kv(0x91, b'', spent_output_commit)
    psbt += kv(0x92, b'', spent_output_pubkey)
    psbt += kv(0x94, b'', bytes([input_features]))
    psbt += kv(0x96, b'', struct.pack('<I', input_address_index))
    psbt += kv(0x97, b'', struct.pack('<Q', input_amount))
    psbt += kv(0x99, b'', kex_pk)
    psbt += key_origin_kv(0x9A, mweb_ctx['scan_pub'], fingerprint_bytes, mweb_ctx['scan_path'])
    psbt += key_origin_kv(0x9B, spend_pub, fingerprint_bytes, mweb_ctx['spend_path'])
    psbt += separator()

    psbt += kv(0x03, b'', struct.pack('<Q', output_amount))
    psbt += kv(0x90, b'', stealth_address)
    psbt += kv(0x92, b'', bytes([output_features]))
    psbt += separator()

    psbt += kv(0x02, b'', struct.pack('<Q', kernel_fee))
    psbt += separator()

    print(f"  PSBT size: {len(psbt)} bytes", flush=True)
    print(f"  PSBT hex: {psbt.hex()}", flush=True)

    # Self-check: verify structure with our simple parser
    sections = parse_psbt_sections(psbt)
    print(f"  Self-check: {len(sections)} sections parsed", flush=True)
    for si, sec in enumerate(sections):
        types = [f"0x{kt:02x}" for kt, _, _ in sec]
        print(f"    section {si}: {types}", flush=True)

    print("  Sending to Jade for signing... (confirm MWEB output and fee on device)", flush=True)

    signed_psbt = jade.sign_psbt('litecoin', psbt)
    print(f"  Signed PSBT size: {len(signed_psbt)} bytes", flush=True)
    print(f"  Signed PSBT hex: {bytes(signed_psbt).hex()}", flush=True)

    sections = parse_psbt_sections(bytes(signed_psbt))
    assert len(sections) >= 4, "Expected global, input, output, and kernel sections"

    global_section = sections[0]
    input_section = sections[1]
    output_section = sections[2]
    kernel_section = sections[3]

    tx_offset_field = find_field(global_section, 0x90)
    stealth_offset_field = find_field(global_section, 0x91)
    input_sig_field = find_field(input_section, 0x95)
    input_pubkey_field = find_field(input_section, 0x93)
    commit_field = find_field(input_section, 0x91)

    assert tx_offset_field is not None, "Missing MWEB tx offset in globals"
    assert stealth_offset_field is not None, "Missing MWEB stealth offset in globals"
    assert input_sig_field is not None, "Missing MWEB input signature"
    assert input_pubkey_field is not None, "Missing MWEB input pubkey"
    assert commit_field is not None, "Missing MWEB spent output commit"
    assert find_field(output_section, 0x90) is not None, "Missing MWEB stealth address output"
    assert find_field(kernel_section, 0x02) is not None, "Missing MWEB kernel fee"

    tx_offset = tx_offset_field[1]
    stealth_offset = stealth_offset_field[1]
    input_sig = input_sig_field[1]
    input_pubkey = input_pubkey_field[1]
    output_commit = commit_field[1]

    print(f"  MWEB tx offset: {tx_offset.hex()}", flush=True)
    print(f"  MWEB stealth offset: {stealth_offset.hex()}", flush=True)
    print(f"  MWEB input signature ({len(input_sig)} bytes): {input_sig.hex()}", flush=True)
    print(f"  MWEB input pubkey: {input_pubkey.hex()}", flush=True)
    print(f"  MWEB output commit: {output_commit.hex()}", flush=True)

    assert len(tx_offset) == 32, f"Expected 32-byte tx offset, got {len(tx_offset)}"
    assert len(stealth_offset) == 32, f"Expected 32-byte stealth offset, got {len(stealth_offset)}"
    assert len(input_sig) == 64, f"Expected 64-byte MWEB signature, got {len(input_sig)}"
    assert len(input_pubkey) == 33, f"Expected 33-byte MWEB input pubkey, got {len(input_pubkey)}"
    assert len(output_commit) == 33, f"Expected 33-byte MWEB output commit, got {len(output_commit)}"
    assert any(tx_offset), "MWEB tx offset is all zeroes"
    assert any(stealth_offset), "MWEB stealth offset is all zeroes"
    assert any(input_sig), "MWEB input signature is all zeroes"
    assert output_commit[0] in (0x08, 0x09), f"Bad commit prefix: 0x{output_commit[0]:02x}"

    print("\n  *** Test 3 PASSED ***")
    return True


# ---------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------

def _run_tests(jade, args, is_ble):
    """Core test logic — runs on the main thread (serial) or worker thread (BLE)."""
    passed = 0
    failed = 0
    auth_timeout = max(args.boot_timeout, 120)

    try:
        if is_ble:
            if not unlock_jade(jade, auth_timeout):
                return 1
            try:
                info = get_version_info(jade, timeout=10)
                print(f"Jade version: {info.get('JADE_VERSION', '?')} "
                      f"(state={info.get('JADE_STATE', '?')})", flush=True)
            except (TimeoutError, Exception) as e:
                print(f"Warning: could not get version info after auth: {e}", flush=True)
        else:
            info = get_version_info(jade, timeout=args.boot_timeout)
            state = info.get('JADE_STATE', '?')
            print(f"Jade version: {info.get('JADE_VERSION', '?')} (state={state})", flush=True)

            if state == 'READY':
                print("Device is already unlocked.", flush=True)
            elif not info.get('JADE_HAS_PIN', False):
                print("Device has no PIN set; continuing without auth.", flush=True)
            else:
                if not unlock_jade(jade, auth_timeout):
                    return 1

        # Test 1
        try:
            if test_standard_ltc(jade):
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"\n  *** Test 1 ERROR: {e} ***")
            import traceback; traceback.print_exc()
            failed += 1

        # Test 2 — regression: sign_mweb_input RPC removed.
        # Uses no mweb_ctx because the dashboard rejects the method before
        # any parameters are parsed.
        try:
            if test_sign_mweb_input_removed(jade):
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"\n  *** Test 2 ERROR: {e} ***")
            import traceback; traceback.print_exc()
            failed += 1

        # Test 3
        try:
            mweb_ctx = get_mweb_context(jade)
            if test_mweb_psbt(jade, mweb_ctx):
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"\n  *** Test 3 ERROR: {e} ***")
            import traceback; traceback.print_exc()
            failed += 1
    finally:
        try:
            jade.disconnect()
        except Exception:
            pass

    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


class _DirectBleImpl:
    """BLE impl that uses asyncio.run() + async-with BleakClient on the main
    thread — the only pattern proven to work reliably on macOS CoreBluetooth.

    The main thread runs the async event loop.  A worker thread drives jadepy's
    synchronous read()/write() calls, which post BLE operations back to the
    main loop via run_coroutine_threadsafe().
    """
    IO_TX_CHAR_UUID = '6e400002-b5a3-f393-e0a9-e50e24dcca9e'
    IO_RX_CHAR_UUID = '6e400003-b5a3-f393-e0a9-e50e24dcca9e'

    def __init__(self, client, loop, inbufs):
        self._client = client
        self._loop = loop
        self._inbufs = inbufs          # deque, fed by notification callback
        self._read_buf = bytearray()   # leftover bytes from previous reads

    def connect(self):
        pass  # already connected

    def disconnect(self):
        pass  # handled by the async-with context

    def write(self, bytes_):
        import asyncio
        import time
        # Brief pause to let CoreBluetooth finish processing any pending
        # indication acknowledgments — the ATT bearer is sequential, so
        # writing before the previous indication is confirmed causes the
        # Jade firmware to get BLE_HS_EBUSY (error 6).
        time.sleep(0.05)
        logger.debug(f'BLE write: {len(bytes_)} bytes')
        future = asyncio.run_coroutine_threadsafe(
            self._client.write_gatt_char(
                self.IO_TX_CHAR_UUID, bytearray(bytes_), response=True),
            self._loop)
        future.result()
        logger.debug(f'BLE write: done')
        return len(bytes_)

    def read(self, n):
        """Read up to n bytes from the BLE notification stream.

        Returns as soon as ANY data is available (like a socket read),
        since cbor2.load() calls read(4096) expecting partial returns.
        """
        if not self._read_buf:
            # Wait for at least one chunk of data
            while not self._inbufs:
                import time
                time.sleep(0.005)
            chunk = self._inbufs.popleft()
            self._read_buf.extend(chunk)

        # Return whatever we have, up to n bytes
        available = min(n, len(self._read_buf))
        result = bytes(self._read_buf[:available])
        self._read_buf = self._read_buf[available:]
        return result


def _run_ble_main(args):
    """BLE entry point — runs asyncio.run() on the main thread.

    Uses `async with BleakClient` (the only pattern that reliably receives
    BLE notifications on macOS with bonded devices).  All synchronous jadepy
    API calls run in a worker thread.
    """
    import asyncio
    import collections
    import queue

    result_q = queue.Queue()

    async def _async_main():
        import bleak

        # --- Scan ---
        bleid = args.bleid
        if bleid is None:
            print(f"Scanning for Jade BLE devices ({args.ble_scan_timeout}s)...",
                  flush=True)
            all_devs = await bleak.BleakScanner.discover(
                timeout=args.ble_scan_timeout)
            devices = [(d.name, d.address) for d in all_devs
                       if d.name and d.name.startswith('Jade')]

            if not devices:
                print("\nNo Jade BLE devices found. Ensure your Jade is:",
                      flush=True)
                print("  - Powered on and past the boot screen", flush=True)
                print("  - Bluetooth enabled (check Jade settings)", flush=True)
                print("  - Not already connected to another host", flush=True)
                result_q.put(1)
                return

            print(f"\nFound {len(devices)} Jade device(s):\n", flush=True)
            for i, (name, addr) in enumerate(devices, 1):
                print(f"  [{i}] {name}  ({addr})", flush=True)

            if len(devices) == 1:
                name, addr = devices[0]
                print(f"\nAuto-selecting: {name}\n", flush=True)
                parts = name.split()
                bleid = parts[-1] if len(parts) > 1 else None
            else:
                # Device selection needs to happen in the worker thread
                # (input() can't run on the event loop).  For now, require
                # --bleid when multiple devices are present.
                print("Multiple devices found — please re-run with --bleid <suffix>",
                      flush=True)
                result_q.put(1)
                return

        # --- Scan for the device address ---
        jade_addr = None
        devs = await bleak.BleakScanner.discover(timeout=5)
        for d in devs:
            if d.name and d.name.startswith('Jade'):
                if bleid is None or d.name.endswith(bleid):
                    jade_addr = d.address
                    print(f"Found: {d.name}  ({d.address})", flush=True)
                    break

        if not jade_addr:
            print(f"Could not find Jade device (bleid={bleid})", flush=True)
            result_q.put(1)
            return

        # --- Connect with async-with (proven to work on macOS) ---
        inbufs = collections.deque()

        def on_notify(characteristic, data):
            logger.debug(f'BLE notification: {len(data)} bytes')
            inbufs.append(data)

        print(f"Connecting to Jade over BLE (id={bleid or 'any'})...", flush=True)

        async with bleak.BleakClient(jade_addr) as client:
            await client.start_notify(_DirectBleImpl.IO_RX_CHAR_UUID, on_notify)
            print("Connected and subscribed.", flush=True)

            loop = asyncio.get_running_loop()
            impl = _DirectBleImpl(client, loop, inbufs)

            # Build JadeAPI using our direct BLE impl
            from jadepy.jade import JadeInterface
            jade_iface = JadeInterface(impl)
            jade = JadeAPI(jade_iface)

            # Run the synchronous test logic in a worker thread
            def _worker():
                try:
                    r = _run_tests(jade, args, is_ble=True)
                    result_q.put(r)
                except SystemExit as e:
                    result_q.put(e.code if isinstance(e.code, int) else 1)
                except Exception as e:
                    print(f"\nFatal error: {e}", flush=True)
                    import traceback; traceback.print_exc()
                    result_q.put(1)

            worker = threading.Thread(target=_worker, name='ble-test-worker')
            worker.start()

            # Keep the async context alive while the worker runs
            while worker.is_alive():
                await asyncio.sleep(0.05)

            worker.join(timeout=5)

        print("BLE disconnected.", flush=True)

    asyncio.run(_async_main())
    return result_q.get() if not result_q.empty() else 1


def main():
    args = parse_args()

    # --ble-scan: just list devices and exit
    if args.ble_scan:
        devices = scan_for_jade_devices(args.ble_scan_timeout)
        if not devices:
            print("No Jade BLE devices found.")
        return 0

    if args.ble:
        return _run_ble_main(args)

    # Serial path — runs directly on the main thread
    jade = JadeAPI.create_serial(device=args.serialport, timeout=args.serial_timeout)
    selected_port = jade.jade.impl.device
    port_label = selected_port or 'auto-detected serial device'

    print(f"Connecting to Jade on {port_label}...", flush=True)
    print(f"Using boot timeout {args.boot_timeout:g}s.", flush=True)
    jade.connect()
    print("Connected.", flush=True)

    return _run_tests(jade, args, is_ble=False)


if __name__ == '__main__':
    sys.exit(main())
