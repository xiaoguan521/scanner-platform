#!/usr/bin/env python3
"""Run the repository's offline input collector from its source-tree path."""
from pathlib import Path
import runpy

_collector = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / 'internal' / 'sshcollect' / 'collector.py'),
    run_name='_scanner_collector_module',
)

if __name__ == '__main__':
    _collector['main']()
else:
    # Keep the historical import path usable by the fixture-based tests and
    # local tooling without executing the CLI parser during import.
    globals().update({name: value for name, value in _collector.items() if not name.startswith('__')})
