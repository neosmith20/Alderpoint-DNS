#!/usr/bin/env python3
"""Deprecated name for alderpointdns_compiler.py.

BindGuard was renamed to Alderpoint DNS. This wrapper exists only so that an
already-installed /etc/sudoers.d/bindguard allowlist entry (naming this exact
path) keeps working until the host's sudoers file and systemd units are
migrated to the Alderpoint DNS names. See docs/compatibility.md for the
planned removal version.
"""

import os
import sys
from pathlib import Path

if __name__ == "__main__":
    target = Path(__file__).resolve().parent / "alderpointdns_compiler.py"
    os.execv(str(target), [str(target)] + sys.argv[1:])
