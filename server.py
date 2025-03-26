#!/usr/bin/env python3

import argparse
import os
import socket

import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from zstandard import ZstdCompressor, ZstdDecompressor
from cryptography.hazmat.primitives import hashes
from kyber_py.ml_kem import ML_KEM_1024

download_folder = "downloaded"

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
            compressed_command = ZstdCompressor().compress(command.encode("utf-8"))
            encrypted_command = chacha20_encrypt(compressed_command, key, nonce)

            if command.lower() == "exit":
                client_socket.send(encrypted_command)
                client_socket.close()
                break
            elif command.lower() == "upload":
                file_path = input("[Server] Enter file path to upload: ")
                with open(file_path, "rb") as f:
                    file_data = f.read()
                compressed_file_data = ZstdCompressor().compress(file_data)
                encrypted_file_data = chacha20_encrypt(compressed_file_data, key, nonce)
                response = requests.post('http://' + client_address[0] + ':5000/upload', data=encrypted_file_data, headers={'Filename': file_path.split('/')[-1]})
                if response.status_code == 200:
                    print("[Server] File uploaded successfully.")
                else:
                    print(f"[Server] Failed to upload file: {response.json().get('error', 'Unknown error')}")
                continue
            elif command.lower() == "download":
                file_name = input("[Server] Enter file name to download: ")
                response = requests.post('http://' + client_address[0] + ':5000/download', headers={'Filename': file_name})
                if response.status_code == 200:
                    file_data = response.content
                    decrypted_file_data = chacha20_decrypt(file_data, key, nonce)
                    decompressed_file_data = ZstdDecompressor().decompress(decrypted_file_data)
                    
                    if not os.path.exists(download_folder):
                        os.makedirs(download_folder)
                        
                    output_path = os.path.join(download_folder, file_name.split('/')[-1])
                    with open(output_path, "wb") as f:
                        f.write(decompressed_file_data)
                    print("[Server] File downloaded successfully.")
                else:
                    print(f"[Server] Failed to download file: {response.json().get('error', 'Unknown error')}")
                continue

            client_socket.send(encrypted_command)
            encrypted_response = client_socket.recv(4096)
            if not encrypted_response:
                break

            response = chacha20_decrypt(encrypted_response, key, nonce)
            response = ZstdDecompressor().decompress(response).decode("utf-8")
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