# -*- mode: python ; coding: utf-8 -*-
import os
import sys
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

datas = []
hidden_imports = [
    'uvicorn',
    'uvicorn.logging',
    'uvicorn.loops',
    'uvicorn.loops.auto',
    'uvicorn.protocols',
    'uvicorn.protocols.http',
    'uvicorn.protocols.http.auto',
    'uvicorn.protocols.websockets',
    'uvicorn.protocols.websockets.auto',
    'uvicorn.middleware',
    'uvicorn.middleware.cors',
    'uvicorn.middleware.proxy_headers',
    'fastapi',
    'pydantic',
    'sqlalchemy',
    'sqlalchemy.ext.declarative',
    'sqlalchemy.orm',
    'yaml',
    'requests',
    'websockets',
    'dotenv',
]

# Collect all submodules from the project
for mod in ['services', 'services.threat_intel', 'services.behavioral_engine',
            'services.risk_scoring', 'services.correlation_engine', 'services.response_engine',
            'services.ml', 'services.ml.base', 'services.ml.isolation_forest',
            'services.ml.one_class_svm', 'services.ml.baseliner',
            'services.platform', 'services.platform.base', 'services.platform.factory',
            'services.platform.windows', 'services.platform.linux', 'services.platform.macos',
            'detector', 'detector.patterns', 'detector.persistence', 'detector.lateral_movement',
            'core', 'core.logging', 'core.exceptions', 'core.config_validator',
            'tracker', 'tracker.tracker', 'tracker.utils', 'tracker.utils.event']:
    hidden_imports.append(mod)

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    name='agent_security_backend',
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
)

# Windows service or hidden window variant
exe_no_console = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='agent_security_backend_service',
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
