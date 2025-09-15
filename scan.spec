# -*- mode: python ; coding: utf-8 -*-

import os

import builtwith
import pyfiglet

# Get the path to the builtwith package to find its data files
builtwith_dir = os.path.dirname(builtwith.__file__)

# Get the path to the pyfiglet package to find its fonts directory
pyfiglet_fonts_dir = os.path.join(os.path.dirname(pyfiglet.__file__), 'fonts')

a = Analysis(
    ['scan.py'],
    pathex=['d:\\dev\\osint_tool'],
    binaries=[],
    datas=[
        (os.path.join(SPECPATH, 'data', 'GeoLite2-City.mmdb'), 'data'),
        (os.path.join(builtwith_dir, 'apps.json'), 'builtwith'),
        (os.path.join(builtwith_dir, 'paths.json'), 'builtwith'),
        (pyfiglet_fonts_dir, 'pyfiglet/fonts'),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='scan',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    codesign_identity=None,
    entitlements_file=None,
    target_arch=None,
)
