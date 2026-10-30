"""Test-only: build tools/ed25519-tool for the host so helpers can run it.

Production helpers call the pinned copy at /usr/local/libexec/cdnca; tests
point the module constant ED25519_TOOL at this host build instead.
"""

import functools
import os
from pathlib import Path
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parents[2] / "tools" / "ed25519-tool"


@functools.lru_cache(maxsize=1)
def host_ed25519_tool():
    # Hosts without Go (old-distribution test containers) pass a prebuilt tool.
    if os.environ.get("CDNCA_ED25519_TOOL_PATH"):
        return os.environ["CDNCA_ED25519_TOOL_PATH"]
    output = Path(tempfile.mkdtemp(prefix="cdnca-ed25519-test-")) / "cdnca-ed25519"
    env = {key: value for key, value in os.environ.items() if key not in ("GOFLAGS", "GOEXPERIMENT", "GOOS", "GOARCH")}
    env.update({"GOWORK": "off", "CGO_ENABLED": "0"})
    subprocess.run(["go", "build", "-trimpath", "-o", str(output), "."], cwd=SOURCE, env=env, check=True,
                   stdout=subprocess.DEVNULL, timeout=300)
    return str(output)
