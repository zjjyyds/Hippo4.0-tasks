"""Linux filesystem and privilege boundary for the submitted Rust harness.

The verifier stays root outside the jail. The child sees only the copied harness
and trusted dynamic libraries, reads input on stdin, and runs as nobody with
network syscalls denied. No fixtures, manifest, generator, /proc, or build tree
are mounted in the jail. There is deliberately no unsandboxed fallback.
"""

import ctypes
import errno
import os
import resource
import shutil
import subprocess
import tempfile
from pathlib import Path


MAX_OUTPUT_BYTES = 128 * 1024 * 1024


class HarnessSandbox:
    def __init__(self, harness, runtime_root):
        if os.geteuid() != 0:
            raise RuntimeError('Verification requires root for chroot and privilege dropping')
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.seccomp = ctypes.CDLL('libseccomp.so.2', use_errno=True)
        self.seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
        self.seccomp.seccomp_init.restype = ctypes.c_void_p
        self.seccomp.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
        self.seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
        self.seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
        self.seccomp.seccomp_release.argtypes = [ctypes.c_void_p]
        runtime_root = Path(runtime_root)
        if not runtime_root.is_dir() or not any(runtime_root.rglob('ld-linux*')):
            raise RuntimeError('Trusted runtime root is missing its dynamic loader')
        self.temp = tempfile.TemporaryDirectory(prefix='dbsf-jail-')
        self.root = Path(self.temp.name) / 'root'
        shutil.copytree(runtime_root, self.root)
        shutil.copyfile(harness, self.root / 'harness')
        # Bind no writable directories and strip special bits from every file.
        for path in self.root.rglob('*'):
            if path.is_symlink():
                raise RuntimeError('Symlinks are not permitted in the trusted runtime root')
            # The ELF interpreter also needs execute permission at execve time.
            path.chmod(0o555)
        (self.root / 'harness').chmod(0o555)
        self.root.chmod(0o555)

    def _enter(self):
        os.chdir(self.root)
        os.chroot('.')
        os.chdir('/')
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)
        os.umask(0o077)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT_BYTES, MAX_OUTPUT_BYTES))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
        if self.libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
            raise OSError(ctypes.get_errno(), 'prctl')
        ctx = self.seccomp.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
        if not ctx:
            raise RuntimeError('seccomp_init failed')
        try:
            for name in ('socket', 'socketpair', 'connect', 'bind', 'listen', 'accept',
                         'accept4', 'ptrace', 'process_vm_readv', 'process_vm_writev',
                         'fork', 'vfork', 'clone', 'clone3'):
                number = self.seccomp.seccomp_syscall_resolve_name(name.encode())
                if number >= 0 and self.seccomp.seccomp_rule_add(ctx, 0x00050000 | errno.EPERM, number, 0) != 0:
                    raise RuntimeError('seccomp_rule_add failed')
            if self.seccomp.seccomp_load(ctx) != 0:
                raise RuntimeError('seccomp_load failed')
        finally:
            self.seccomp.seccomp_release(ctx)

    def run(self, args, data):
        # Output goes to bounded, private files rather than an unbounded pipe.
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            proc = subprocess.run(
                ['/harness', *args], input=data, stdout=stdout, stderr=stderr,
                env={'PATH': '/nonexistent', 'HOME': '/nonexistent', 'LC_ALL': 'C.UTF-8'},
                preexec_fn=self._enter, close_fds=True, timeout=20,
            )
            stdout.seek(0)
            stderr.seek(0)
            return subprocess.CompletedProcess(proc.args, proc.returncode,
                                               stdout.read(MAX_OUTPUT_BYTES), stderr.read(8192))

    def close(self):
        self.temp.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
