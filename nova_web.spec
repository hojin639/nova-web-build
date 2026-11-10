# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for NOVA Web (macOS onefile)."""
import os, sys
from PyInstaller.utils.hooks import collect_data_files

block_cipher = None
base = os.path.dirname(os.path.abspath(SPEC))

a = Analysis(
    [os.path.join(base, 'run.py')],
    pathex=[base],
    binaries=[],
    datas=[
        (os.path.join(base, 'templates'), 'templates'),
        (os.path.join(base, 'static'), 'static'),
    ],
    hiddenimports=[
        'eventlet.hubs.epolls', 'eventlet.hubs.kqueue', 'eventlet.hubs.selects',
        'dns', 'dns.resolver', 'dns.rdatatype', 'dns.name',
        'engineio.async_drivers.eventlet',
        'flask_socketio', 'flask', 'requests', 'cryptography',
        'cryptography.hazmat.primitives.asymmetric.x25519',
        'cryptography.hazmat.primitives.ciphers.aead',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'scipy', 'pandas',
              'PIL', 'cv2', 'pytest', 'unittest'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name='NOVA-Web',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=True,
    console=True,
    target_arch='universal2',
)
