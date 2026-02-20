#!/usr/bin/env python3
"""Build script for winsupervisord using PyInstaller."""

import subprocess
import sys

def build():
    """Build the executable using PyInstaller."""
    cmd = [
        'pyinstaller',
        '--onefile',
        'winsupervisord.py',
        '-w',
        '--add-data=index.html;.'
    ]
    
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    
    return result.returncode

if __name__ == '__main__':
    sys.exit(build())
