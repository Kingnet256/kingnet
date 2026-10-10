"""
Minimal, FAITHFUL WebAuthn core for the KINGNET lab.

NOTE (Phase 3): KingVault's running service (`app.py`) now uses the full standard
`webauthn` library so a real browser passkey works. THIS module is kept as the readable
teaching explainer — the same origin-binding mechanism in plain Python, with no CBOR/COSE
machinery in the way. Lesson 5 points here to show *why* the library's origin check works.

This implements the security-relevant heart of WebAuthn / FIDO2 passkeys: an
origin-bound, challenge-response signature. It is deliberately small and readable
(students are meant to read it), and it is NOT the full CTAP2 / attestation stack —
it omits attestation statement formats, credential exclusion lists, UV/UP policy
nuances, resident-key bookkeeping, etc.

But it is faithful on the ONE property that defeats adversary-in-the-middle phishing:

    The authenticator signs over the ORIGIN the browser is actually talking to,
    plus a hash of the Relying Party ID, and the Relying Party REFUSES any assertion
    whose origin / RP-ID does not match what it expects.

A phishing proxy necessarily lives at a *different origin* than the real service
(different scheme/host/port). So the victim's authenticator signs the proxy's origin,
the real service compares it against its own origin, they differ, and the assertion
is rejected. The attacker captures the assertion but it is cryptographically useless
anywhere except the phishing page. That is why passkeys stop AiTM and shared secrets
(passwords, SMS/TOTP codes, session cookies) do not.

Real WebAuthn does this exact check in the browser + authenticator + RP; here we do
it in plain Python so the mechanism is visible.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

# ---- small helpers ---------------------------------------------------------

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def rp_id_hash(rp_id: str) -> bytes:
    """A WebAuthn RP-ID is a bare domain (no scheme, no port), e.g. 'kingvault.lab'."""
    return sha256(rp_id.encode("ascii"))


def new_challenge() -> str:
    return b64u(os.urandom(32))


def authenticator_data(rp_id: str, sign_count: int, up: bool = True, uv: bool = True) -> bytes:
    """rpIdHash(32) || flags(1) || signCount(4, big-endian) — the real authData layout."""
    flags = 0
    if up:
        flags |= 0x01  # user present
    if uv:
        flags |= 0x04  # user verified
    return rp_id_hash(rp_id) + struct.pack("!B", flags) + struct.pack("!I", sign_count)


# ---- the authenticator (models the victim's platform/roaming authenticator) --
#
# In the real world this lives in the user's phone/laptop/YubiKey and the BROWSER
# feeds it (a) the origin of the page the user is on and (b) the RP-ID the site asked
# for — and the browser refuses to proceed unless the RP-ID is a registrable suffix of
# that origin. So the authenticator can only ever sign the origin the user is actually
# visiting. We model exactly that: the client passes the origin it is really connected
# to, and the signature is bound to it.

@dataclass
class Passkey:
    credential_id: str          # b64u
    rp_id: str
    _private_pem: bytes

    def public_key_pem(self) -> str:
        priv = serialization.load_pem_private_key(self._private_pem, password=None)
        return priv.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")


class SoftAuthenticator:
    """A software passkey store — stands in for the user's authenticator in demos/tests."""

    def __init__(self) -> None:
        self._keys: dict[str, Passkey] = {}  # credential_id -> Passkey

    def create(self, rp_id: str) -> Passkey:
        priv = ec.generate_private_key(ec.SECP256R1())
        pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        pk = Passkey(credential_id=b64u(os.urandom(16)), rp_id=rp_id, _private_pem=pem)
        self._keys[pk.credential_id] = pk
        return pk

    def get_assertion(self, credential_id: str, origin: str, rp_id: str, challenge: str,
                      sign_count: int = 1) -> dict:
        """Produce an assertion for `origin` — THE faithful bit. The client hands us the
        origin of the page it is actually on; we sign that, come what may."""
        pk = self._keys[credential_id]
        client_data = json.dumps(
            {"type": "webauthn.get", "challenge": challenge, "origin": origin},
            separators=(",", ":"), sort_keys=True,
        ).encode("utf-8")
        auth_data = authenticator_data(rp_id, sign_count)
        priv = serialization.load_pem_private_key(pk._private_pem, password=None)
        signature = priv.sign(auth_data + sha256(client_data), ec.ECDSA(hashes.SHA256()))
        return {
            "credential_id": credential_id,
            "client_data_json": b64u(client_data),
            "authenticator_data": b64u(auth_data),
            "signature": b64u(signature),
        }


# ---- the Relying Party verification (runs on the lab target) ----------------

def verify_assertion(*, public_key_pem: str, expected_rp_id: str, expected_origin: str,
                     expected_challenge: str, assertion: dict) -> tuple[bool, str]:
    """Return (ok, reason). The origin / RP-ID checks here are what defeat AiTM."""
    try:
        client_data = b64u_dec(assertion["client_data_json"])
        auth_data = b64u_dec(assertion["authenticator_data"])
        signature = b64u_dec(assertion["signature"])
    except Exception:
        return False, "malformed assertion"

    try:
        cd = json.loads(client_data)
    except Exception:
        return False, "clientData is not valid JSON"

    if cd.get("type") != "webauthn.get":
        return False, f"wrong ceremony type: {cd.get('type')!r}"
    if cd.get("challenge") != expected_challenge:
        return False, "challenge mismatch (possible replay)"

    # *** THE check that stops phishing: the signed origin must be THIS service. ***
    if cd.get("origin") != expected_origin:
        return False, (f"ORIGIN MISMATCH — assertion is bound to {cd.get('origin')!r}, "
                       f"but this service is {expected_origin!r}. Phishing-relay rejected.")

    # RP-ID binding: the authenticator proves which domain it signed for.
    if auth_data[:32] != rp_id_hash(expected_rp_id):
        return False, "RP-ID hash mismatch"

    try:
        pub = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        # Re-encode the raw (r||s) signature we produced? We signed with cryptography's
        # DER output, so verify expects DER too — python 'cryptography' .sign returns DER.
        pub.verify(signature, auth_data + sha256(client_data), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False, "signature does not verify"
    except Exception as e:
        return False, f"verification error: {e}"

    return True, "ok"


def build_client_data(ceremony_type: str, challenge: str, origin: str) -> str:
    """Client-side helper (the 'browser') — builds the clientDataJSON bound to `origin`."""
    cd = json.dumps({"type": ceremony_type, "challenge": challenge, "origin": origin},
                    separators=(",", ":"), sort_keys=True).encode("utf-8")
    return b64u(cd)


def verify_registration(*, expected_origin: str, expected_challenge: str,
                        client_data_json: str) -> tuple[bool, str]:
    """Origin-check at enrollment too: a passkey must be registered on the real site."""
    try:
        cd = json.loads(b64u_dec(client_data_json))
    except Exception:
        return False, "clientData is not valid JSON"
    if cd.get("type") != "webauthn.create":
        return False, f"wrong ceremony type: {cd.get('type')!r}"
    if cd.get("challenge") != expected_challenge:
        return False, "challenge mismatch"
    if cd.get("origin") != expected_origin:
        return False, (f"ORIGIN MISMATCH at registration — {cd.get('origin')!r} != "
                       f"{expected_origin!r}")
    return True, "ok"


def extract_origin(assertion: dict) -> str | None:
    """Best-effort read of the origin an assertion is bound to (for the attacker console)."""
    try:
        return json.loads(b64u_dec(assertion["client_data_json"])).get("origin")
    except Exception:
        return None
