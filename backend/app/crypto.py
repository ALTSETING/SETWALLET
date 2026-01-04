import base64
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature


def compute_address_from_public_pem(public_pem: str) -> str:
    """
    Must match frontend:
    address = "SET" + first 20 bytes of SHA256(publicPem) (40 hex chars)
    """
    h = hashlib.sha256(public_pem.encode("utf-8")).hexdigest()
    return "SET" + h[:40]


def verify_signature_p256(public_pem: str, message: str, signature_b64: str) -> bool:
    """
    Frontend signs with:
    crypto.subtle.sign({name:"ECDSA", hash:"SHA-256"}, privKey, msgBytes)
    Signature in WebCrypto is DER-encoded ECDSA (most browsers), base64 by frontend.

    We verify using cryptography (ECDSA+SHA256).
    """
    try:
        pub = serialization.load_pem_public_key(public_pem.encode("utf-8"))
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            return False

        sig = base64.b64decode(signature_b64)
        pub.verify(sig, message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return True
    except (ValueError, InvalidSignature):
        return False
