#!/usr/bin/env python3

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from kyber_py.ml_kem import ML_KEM_1024
import argparse
import socket

def chacha20_encrypt(data, key, nonce):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data)

def chacha20_decrypt(data, key, nonce):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data)

def start_server(ip, port):
    mlkem = ML_KEM_1024
    server_public_key, server_private_key = mlkem.keygen()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ip, port))
    server.listen(1)
    print(f"[*] Listening on {ip}:{port}")
    client_socket, client_address = server.accept()
    print(f"[*] Connection established with {client_address}")

    try:
        client_socket.send(server_public_key)

        client_public_key_bytes = client_socket.recv(4096)
        shared_key = mlkem.decaps(server_private_key, client_public_key_bytes)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=48,
            salt=None,
            info=b"handshake data",
            backend=default_backend(),
        ).derive(shared_key)

        key = derived_key[:32]
        nonce = derived_key[32:48]

        while True:
            command = input("\n[Server] Enter command: ").strip()
            if command.lower() == "exit":
                encrypted_command = chacha20_encrypt(command.encode("utf-8"), key, nonce)
                client_socket.send(encrypted_command)
                client_socket.close()
                print("[*] Connection closed.")
                break
            encrypted_command = chacha20_encrypt(command.encode("utf-8"), key, nonce)
            client_socket.send(encrypted_command)
            encrypted_response = client_socket.recv(4096)
            if not encrypted_response:
                break
            response = chacha20_decrypt(encrypted_response, key, nonce).decode("utf-8")
            print(f"\n[Client]: {response}")
    except Exception as e:
        print(f"[!] Error: {e}")
        client_socket.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", required=True, help="IP address to bind to")
    parser.add_argument("-p", "--port", required=True, type=int, help="Port to bind to")
    args = parser.parse_args()
    start_server(args.ip, args.port)