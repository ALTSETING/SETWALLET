import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

def verify_signature(public_key_pem: str, message: bytes, signature_b64: str) -> bool:
    try:
        pub = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            return False
        sig = base64.b64decode(signature_b64)
        pub.verify(sig, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (ValueError, InvalidSignature):
        return False
