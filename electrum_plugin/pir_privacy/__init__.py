"""
BitcoinPIR - Privacy-preserving UTXO lookup for Electrum.

Supports three PIR backends (configurable):
  1. DPF 2-server — information-theoretic privacy
  2. HarmonyPIR 2-server — stateful PIR with offline hints
  3. OnionPIRv2 1-server — FHE-based, slower
"""

import os as _os
import sys as _sys

# Add vendored dependencies (websockets) bundled in the plugin zip.
# When loaded from a zip, __file__ is like:
#   /path/to/pir_privacy-0.1.0.zip/pir_privacy/__init__.py
# We add the zip itself to sys.path so "import websockets" works.
_abs = _os.path.abspath(__file__)
if '.zip' in _abs:
    _zip_path = _abs[:_abs.index('.zip') + 4]
    if _zip_path not in _sys.path:
        _sys.path.insert(0, _zip_path)
else:
    # Running from filesystem (development) — use _vendor/ subdir
    _vendor_dir = _os.path.join(_os.path.dirname(_abs), '_vendor')
    if _os.path.isdir(_vendor_dir) and _vendor_dir not in _sys.path:
        _sys.path.insert(0, _vendor_dir)

try:
    from electrum.i18n import _
except ImportError:
    def _(x): return x  # Fallback for standalone usage without Electrum

fullname = _('PIR Privacy')
description = _('Replace Electrum server queries with Private Information Retrieval. '
                'The server learns nothing about which addresses you own.')
available_for = ['qt', 'cmdline']
