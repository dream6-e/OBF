"""Diagnostic observer for concrete loadstring sources; not a static lifter.

Usage: python capture_loadstrings.py UPSTREAM_ENGINE_DIR INPUT [deob.py flags]
Pass --raw PATH to retain byte-exact LOADSTRING_SOURCE hex records. The rendered
trace excludes these protocol records. Does not fetch URLs or replace source.
The two instrumentation sites are checked against the pinned engine layout.
"""
import re
import sys
from pathlib import Path

SOURCE_RECORD = re.compile(r"(?m)^\x00LOADSTRING_SOURCE (\d+) ([0-9a-f]*)\n")


def instrument(text):
    # Same function/frame and line count: a wrapper adds stack depth and can
    # perturb protected programs' environment probes. Still observational,
    # not a proof of equivalence; compare against an uninstrumented run.
    needle = '\tif not f then return nil, err end\n\tR.setfenv(f, ENV)'
    replacement = (
        '\tif not f then return nil, err end; '
        'CHAIN.observedLoadstrings = CHAIN.observedLoadstrings or {}; '
        'CHAIN.observedLoadstrings[src] = true\n\tR.setfenv(f, ENV)'
    )
    if text.count(needle) != 1:
        raise ValueError('loadstring capture site changed or is ambiguous')
    text = text.replace(needle, replacement)
    needle = 'for _, hook in R.ipairs(CHAIN.endHooks or {}) do'
    replacement = (
        'for src in R.next, CHAIN.observedLoadstrings or {} do '
        'R.print("\\0LOADSTRING_SOURCE " .. #src .. " " .. '
        '(R.gsub(src, ".", function(c) return R.fmt("%02x", R.byte(c)) end))) end; '
        + needle
    )
    if text.count(needle) != 1:
        raise ValueError('end-hook capture site changed or is ambiguous')
    return text.replace(needle, replacement)


def source_records(raw):
    """Return unique source bytes in output order; refuse malformed lengths."""
    sources = []
    for size, hex_data in SOURCE_RECORD.findall(raw):
        data = bytes.fromhex(hex_data)
        if len(data) != int(size):
            raise ValueError('captured loadstring length mismatch')
        if data not in sources:
            sources.append(data)
    return sources


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    engine = Path(argv.pop(0)).resolve()
    sys.path.insert(0, str(engine))
    import harness
    import traceout
    import deob

    build = harness.build_harness
    take_strings = traceout.take_strings
    harness.build_harness = lambda *a, **kw: instrument(build(*a, **kw))
    # LAST_RAW is untouched. Only the readable trace loses protocol records.
    traceout.take_strings = lambda body: take_strings(SOURCE_RECORD.sub('', body))
    old_argv = sys.argv
    try:
        sys.argv = [str(engine / 'deob.py'), *argv]
        return deob.main()
    finally:
        sys.argv = old_argv
        harness.build_harness = build
        traceout.take_strings = take_strings


if __name__ == '__main__':
    raise SystemExit(main())
