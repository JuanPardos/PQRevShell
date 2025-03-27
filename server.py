#!/usr/bin/env python3

import argparse
import os
import socket

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from zstandard import ZstdCompressor, ZstdDecompressor
from cryptography.hazmat.primitives import hashes
from flask import Flask, jsonify, request
from kyber_py.ml_kem import ML_KEM_1024
import threading

key = None
nonce = None

downloads_folder = "downloads"

app = Flask(__name__)

def run_flask():
    app.run(host='0.0.0.0', port=5000)

@app.route('/d', methods=['POST'])
def download():
    data = request.get_data()
    desencrypted_data = chacha20_decrypt(data, key, nonce)
    decompressed_data = ZstdDecompressor().decompress(desencrypted_data)

    if not decompressed_data:
        return jsonify({"error": "No data received"}), 400
    filename = request.headers.get('Filename')
    try:
        if not os.path.exists(downloads_folder):
            os.makedirs(downloads_folder)
                        
        output_path = os.path.join(downloads_folder, filename.split('/')[-1])
        with open(output_path, "wb") as f:
            f.write(decompressed_data)
        print("[Server] File downloaded successfully.")
        return jsonify({"message": "File downloaded successfully."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/u', methods=['POST'])
def upload():
    filename = request.headers.get('Filename')
    if not filename:
        return jsonify({"error": "Filename is missing"}), 400
    try:
        with open(filename, "rb") as f:
            file_data = f.read()
        file_compressed = ZstdCompressor().compress(file_data)
        file_encrypted = chacha20_encrypt(file_compressed, key, nonce)
        print("[Server] File uploaded successfully.")
        return file_encrypted
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def chacha20_encrypt(data, key, nonce):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data)

def chacha20_decrypt(data, key, nonce):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data)

def start_server(ip, port):
    global key, nonce

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
            elif command.lower() == "download":
                file_path = input("[Server] Enter file path to download: ")
                compressed_command = ZstdCompressor().compress(b'-download ' + file_path.encode("utf-8"))
                encrypted_command = chacha20_encrypt(compressed_command, key, nonce)
            elif command.lower() == "upload":
                file_path = input("[Server] Enter file path to upload: ")
                compressed_command = ZstdCompressor().compress(b'-upload ' + file_path.encode("utf-8"))
                encrypted_command = chacha20_encrypt(compressed_command, key, nonce)

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

    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()

    start_server(args.ip, args.port)