"""Test configuration: only the upstream project's fixtures, never OBF samples."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

REPO = Path(os.environ.get('LURAPH_REPO', Path(__file__).resolve().parents[3] / 'tools/luraph')).resolve()
ENGINE = REPO / 'Deobfuscator/deobf'
sys.path.insert(0, str(ENGINE))


def run(args, timeout=60):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    proc = subprocess.Popen([str(a) for a in args], cwd=ENGINE, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=(os.name != 'nt'))
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name != 'nt':
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
        proc.communicate()
        raise
    return subprocess.CompletedProcess(args, proc.returncode, stdout.decode('utf-8', 'replace'),
                                       stderr.decode('utf-8', 'replace'))


def cli(script, *args):
    return run([sys.executable, '-B', ENGINE / script, *args])


class RuntimeMixin:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='luraph-regression-')
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)

    def output(self, name='result.lua'):
        return self.work / name

    def assert_lifted(self, result, output, expected):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('0 unlifted blocks, 0 unstructured jumps', result.stderr)
        self.assertNotIn('trace-assisted', result.stderr)
        text = output.read_text()
        self.assertNotIn('RESULT: behavior trace', text)
        self.assertNotIn('luraph_runtime', text)
        self.assertIn('print(', text)
        execution = run([ENGINE / 'bin/luau', output])
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertEqual(execution.stdout.strip(), expected)
