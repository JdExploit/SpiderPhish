# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for SpiderPhish - ANTI-PHISHING ANALYZER
import os

block_cipher = None
ROOT = os.path.abspath(SPECPATH)

a = Analysis(
    ['app\\main.py'],
    pathex=[ROOT],
    binaries=[],
    datas=[
        ('assets', 'assets'),
    ],
    hiddenimports=[
        'bs4', 'bs4.builder._lxml',
        'dns', 'dns.resolver', 'dns.reversename',
        'tldextract',
        'httpx', 'h2', 'hpack', 'hyperframe',
        'reportlab', 'reportlab.lib', 'reportlab.platypus',
        'cryptography', 'cryptography.fernet',
        'pydantic', 'pydantic_settings',
        'dotenv',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'PyQt5', 'IPython'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='SpiderPhish-Console',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets\\spiderphish.ico' if os.path.exists('assets\\spiderphish.ico') else None,
    version='assets\\version_info.txt' if os.path.exists('assets\\version_info.txt') else None,
)

