from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import base64

@DeprecationWarning
def encode_b64():
    """Returns a encrypted base64 string."""

    with open('dist\\client.exe', "rb") as f:
        data = f.read()

    seed = b"ultra_mega_secure_seed"

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=48,
        salt=None,
        info=b'data',
        backend=default_backend()
    )

    derivation = hkdf.derive(seed)
    key = derivation[:32]
    nonce = derivation[32:48]

    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    data = encryptor.update(data)
    file = base64.b64encode(data)
    
    with open("dist\\install.data", "wb") as f:
        f.write(file)

if __name__ == "__main__":
    encode_b64()