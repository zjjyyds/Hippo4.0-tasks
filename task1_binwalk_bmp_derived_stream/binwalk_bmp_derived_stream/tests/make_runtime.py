"""Copy dependencies of a TRUSTED scanner binary into a minimal chroot tree.

Run at image build time, before any submission is installed. Never run ldd on
the submitted executable: custom ELF interpreters can execute code via ldd.
"""

import re
import shutil
import subprocess
import sys
from pathlib import Path


def make_runtime(trusted_binary, destination):
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=True)
    output = subprocess.check_output(['ldd', str(trusted_binary)], text=True)
    paths = set(re.findall(r'(/[^\s()]+)', output))
    if not paths:
        raise RuntimeError('No dynamic runtime dependencies found')
    for name in paths:
        src = Path(name)
        dst = root / src.relative_to('/')
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)


if __name__ == '__main__':
    make_runtime(sys.argv[1], sys.argv[2])
