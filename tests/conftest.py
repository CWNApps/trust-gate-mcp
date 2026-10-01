"""conftest.py -- the suite signs with a throwaway key, never the operator's own.

openagentontology reads OAO_RECEIPT_KEY once, when its receipt module is imported, and falls back to
~/.openagentontology/receipt_ed25519.pem. Set the variable before any test module imports the
package, so running the suite on a machine that uses that key neither touches nor depends on it.
"""
import atexit
import os
import pathlib
import shutil
import tempfile

_KEY_DIR = pathlib.Path(tempfile.mkdtemp(prefix="tgmcp-test-key-"))
os.environ["OAO_RECEIPT_KEY"] = str(_KEY_DIR / "receipt_ed25519.pem")
atexit.register(shutil.rmtree, _KEY_DIR, ignore_errors=True)
