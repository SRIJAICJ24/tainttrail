"""The mock upstream MCP server, at the path the docs and tests use.

The server itself lives in the package (tainttrail/mock_upstream.py) so that
`tainttrail simulate` works from a pip install, where examples/ isn't shipped.
Importing this module gives the very same module object, so its state
(`_MEMORY`) is shared; running it as a script starts the server.
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from tainttrail import mock_upstream as _server
except ImportError:                       # run from a checkout without installing
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tainttrail import mock_upstream as _server

if __name__ == "__main__":
    _server.main()
else:
    sys.modules[__name__] = _server
