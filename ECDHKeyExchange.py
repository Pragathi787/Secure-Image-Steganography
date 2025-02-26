from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import base64

def generate_keys():
    """Generate sender's and recipient's ECC key pairs."""
    sender_private_key = ec.generate_private_key(ec.SECP256R1())
    sender_public_key = sender_private_key.public_key()

    recipient_private_key = ec.generate_private_key(ec.SECP256R1())
    recipient_public_key = recipient_private_key.public_key()

    return sender_private_key, sender_public_key, recipient_private_key, recipient_public_key


def derive_shared_key(private_key, encoded_public_key):
    """Derives a shared AES key using ECDH key exchange with Base64 decoding only when needed."""

    # ✅ If the public key is already an ECPublicKey object, use it directly
    if isinstance(encoded_public_key, ec.EllipticCurvePublicKey):
        public_key = encoded_public_key
    else:
        # ✅ Otherwise, assume it's a Base64 string and decode it
        decoded_bytes = base64.b64decode(encoded_public_key)
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), decoded_bytes)

    # Perform key exchange
    shared_secret = private_key.exchange(ec.ECDH(), public_key)

    # Derive AES key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'key exchange'
    ).derive(shared_secret)

    return derived_key
