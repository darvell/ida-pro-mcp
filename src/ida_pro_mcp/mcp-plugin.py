"""IDA Pro MCP Plugin - Thin shim for plugin loading.

IDA discovers this file and calls PLUGIN_ENTRY(). The actual
implementation lives in the plugin/ package alongside this file.
"""
import os
import sys

# Follow symlinks to find the real source directory where plugin/ lives
_dir = os.path.dirname(os.path.realpath(__file__))
if _dir not in sys.path:
    sys.path.insert(0, _dir)

from plugin import MCPPlugin, PLUGIN_ENTRY  # noqa: F401, E402
