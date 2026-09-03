# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for Agent Security EDR Agent
# Build: pyinstaller agent_pyinstaller.spec

import os
import sys
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

# Collect all project modules
hidden_imports = [
    'psutil', 'requests', 'yaml',
    'agent_lib', 'agent_lib.logger', 'agent_lib.network_monitor',
    'agent_lib.file_monitor', 'agent_lib.persistence_monitor',
    'agent_lib.behavioral', 'agent_lib.intel_submitter',
]

# Collect watchdog if available
try:
    import watchdog
    hidden_imports.extend(collect_submodules('watchdog'))
except ImportError:
    pass

# Collect win32 if on Windows
if sys.platform == 'win32':
    try:
        import win32serviceutil
        hidden_imports.extend(collect_submodules('win32serviceutil'))
        hidden_imports.extend(collect_submodules('win32service'))
        hidden_imports.extend(collect_submodules('win32event'))
        hidden_imports.extend(collect_submodules('servicemanager'))
    except ImportError:
        pass

a = Analysis(
    ['agent.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('agent_config.yaml', '.'),
        ('agent_lib/*.py', 'agent_lib'),
    ],
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

# Console mode (default - shows output window)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='agent_security_agent',
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

# No-console mode (for service/background operation)
exe_no_console = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='agent_security_agent_service',
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
