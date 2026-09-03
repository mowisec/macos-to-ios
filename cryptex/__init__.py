"""cryptex -- build a cryptex tree, and check it before paying for an install.

An install cycle costs minutes and a reboot, and nearly every mistake this
project has actually made was visible in the staged tree first: an install name
that did not match what binaries asked for, a reference left pointing at an
absolute macOS path, a bundled library with no chained fixups, a malformed
thread-local descriptor, an unsigned binary. So the checks run on the Mac:

    python3 -m cryptex.verify  --cryptex DIR    9 checks over the staged tree
    python3 -m cryptex.symbols --all --cryptex DIR
                                                the launch prediction, per binary
    python3 -m cryptex.blocklist probe.tsv      a probe result -> exclusion list
    python3 -m cryptex.restage --cryptex DIR    superseded; see its docstring

`scripts/rebuild_cryptex.sh` runs the first two as its last step and exits
non-zero on a failure.
"""

import os
import sys

# machomorph.py is a module at the repo root rather than a package, so importing
# it needs the root on the path. Done here, once, instead of in each module.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
