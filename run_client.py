#!/usr/bin/env python3
"""
SecChat client entry point — works on both Windows and Linux.
On Windows: python run_client.py
On Linux:   python3 run_client.py
"""

import sys
import os

# Add project root to path so 'client' package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from client.main import main
main()
