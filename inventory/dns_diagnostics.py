"""Terminal-only diagnostics; never forward untrusted process text."""

import json
import logging
import os
import selectors
import threading
import time
from contextlib import contextmanager

from django.conf import settings

logger = logging.getLogger("dnsgrid.delivery")
OUTPUT_LIMIT = 4096


def log(event, *, detail=False, **fields):
    if detail and not settings.DNSGRID_DIAGNOSTICS:
        return
    # ASCII JSON escapes terminal controls, including Unicode direction controls.
    message = json.dumps(
        {"event": event, **{key: str(value)[:1024] for key, value in fields.items()}},
        ensure_ascii=True, sort_keys=True,
    )
    logger.log(logging.DEBUG if detail else logging.INFO, message)


def sanitized_output(raw, total):
    # An allowlist is intentional: remote errors/banners may contain arbitrary
    # credentials or file contents, which pattern-based redaction cannot protect.
    text = raw.decode("utf-8", errors="replace").lower()
    phrases = (
        "connection refused", "connection timed out", "connection closed",
        "connection reset", "host key verification failed",
        "remote host identification has changed", "permission denied",
        "no such file or directory", "could not resolve hostname",
        "failure", "no space left on device",
    )
    found = [phrase for phrase in phrases if phrase in text]
    return {
        "diagnostics": found,
        "text": "[redacted]" if total else "[empty]",
        "bytes": total,
        "truncated": total > OUTPUT_LIMIT,
    }


@contextmanager
def capture_output():
    """Drain both pipes without retaining more than OUTPUT_LIMIT per stream."""
    streams = []
    stop = threading.Event()

    def drain(reader, retained):
        deadline = None
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(reader, selectors.EVENT_READ)
                while True:
                    if stop.is_set():
                        if deadline is None:
                            deadline = time.monotonic() + 0.2
                        if time.monotonic() >= deadline:
                            break
                    if not selector.select(timeout=0.1):
                        if stop.is_set():
                            break
                        continue
                    chunk = os.read(reader, OUTPUT_LIMIT)
                    if not chunk:
                        break
                    retained[1] += len(chunk)
                    retained[0].extend(chunk[:max(0, OUTPUT_LIMIT - len(retained[0]))])
        finally:
            os.close(reader)

    try:
        for _ in range(2):
            reader, writer = os.pipe()
            retained = [bytearray(), 0]
            thread = threading.Thread(target=drain, args=(reader, retained), daemon=True)
            streams.append((writer, retained, thread))
            thread.start()
        yield [stream[0] for stream in streams], [stream[1] for stream in streams]
    finally:
        for writer, _, _ in streams:
            os.close(writer)
        stop.set()
        for _, _, thread in streams:
            thread.join()
