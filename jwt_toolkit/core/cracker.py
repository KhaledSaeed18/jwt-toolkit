import hmac
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ProcessPoolExecutor, wait
from dataclasses import dataclass
from itertools import batched

# Cracker module — tests candidate HMAC secrets against a token's signature.
#
# Work is split into batches. With more than one worker the batches run in
# separate processes: HMAC over a short JWT signing input holds the GIL, so
# threads give no speedup on a standard CPython build.

DEFAULT_BATCH_SIZE = 2048

# Below this many candidates, process start-up costs more than it saves.
MIN_PARALLEL_CANDIDATES = 50_000


@dataclass(frozen=True)
class CrackResult:
    # Display label of the matching candidate, or None when nothing matched.
    label: str | None
    # Zero-based position of the match in candidate order.
    position: int | None
    # Number of candidates actually tested.
    attempts: int


def _scan(keys: list[bytes], signing_input: bytes, signature: bytes, digest: str) -> int:
    # Returns the index of the first matching key in this batch, or -1.
    for index, key in enumerate(keys):
        if hmac.compare_digest(hmac.digest(key, signing_input, digest), signature):
            return index
    return -1


def find_secret(
    candidates: Iterable[tuple[str, bytes]],
    *,
    signing_input: bytes,
    signature: bytes,
    digest: str,
    workers: int = 1,
    batch_size: int = DEFAULT_BATCH_SIZE,
    parallel: bool | None = None,
    on_progress: Callable[[int], None] | None = None,
) -> CrackResult:
    # `digest` is a hashlib name ("sha256"). `parallel=None` picks processes
    # only when workers > 1; callers that know the list is small pass False.
    batches = batched(candidates, batch_size, strict=False)
    use_processes = workers > 1 if parallel is None else parallel and workers > 1
    if use_processes:
        return _find_parallel(
            batches,
            signing_input=signing_input,
            signature=signature,
            digest=digest,
            workers=workers,
            on_progress=on_progress,
        )
    return _find_serial(
        batches,
        signing_input=signing_input,
        signature=signature,
        digest=digest,
        on_progress=on_progress,
    )


def _find_serial(
    batches: Iterator[tuple[tuple[str, bytes], ...]],
    *,
    signing_input: bytes,
    signature: bytes,
    digest: str,
    on_progress: Callable[[int], None] | None,
) -> CrackResult:
    attempts = 0
    for batch in batches:
        index = _scan([key for _, key in batch], signing_input, signature, digest)
        if index >= 0:
            position = attempts + index
            attempts += index + 1
            _report(on_progress, attempts)
            return CrackResult(label=batch[index][0], position=position, attempts=attempts)
        attempts += len(batch)
        _report(on_progress, attempts)
    return CrackResult(label=None, position=None, attempts=attempts)


def _find_parallel(
    batches: Iterator[tuple[tuple[str, bytes], ...]],
    *,
    signing_input: bytes,
    signature: bytes,
    digest: str,
    workers: int,
    on_progress: Callable[[int], None] | None,
) -> CrackResult:
    # Keeps a bounded number of batches in flight so memory stays flat. When a
    # match is found, batches that start earlier are still awaited, so the
    # result is always the first match in candidate order.
    pending: dict[Future[int], tuple[int, list[str]]] = {}
    next_start = 0
    attempts = 0
    found: tuple[str, int] | None = None
    exhausted = False

    pool = ProcessPoolExecutor(max_workers=workers)
    try:

        def submit_next() -> None:
            nonlocal next_start, exhausted
            batch = next(batches, None)
            if batch is None:
                exhausted = True
                return
            future = pool.submit(_scan, [key for _, key in batch], signing_input, signature, digest)
            pending[future] = (next_start, [label for label, _ in batch])
            next_start += len(batch)

        while not exhausted and len(pending) < workers * 2:
            submit_next()

        while pending:
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                start, labels = pending.pop(future)
                index = future.result()
                if index < 0:
                    attempts += len(labels)
                    continue
                attempts += index + 1
                if found is None or start + index < found[1]:
                    found = (labels[index], start + index)
            _report(on_progress, attempts)
            if found is None:
                while not exhausted and len(pending) < workers * 2:
                    submit_next()
                continue
            for future, (start, _) in list(pending.items()):
                if start > found[1] and future.cancel():
                    del pending[future]
    finally:
        pool.shutdown(wait=True, cancel_futures=True)

    if found is None:
        return CrackResult(label=None, position=None, attempts=attempts)
    return CrackResult(label=found[0], position=found[1], attempts=attempts)


def _report(on_progress: Callable[[int], None] | None, attempts: int) -> None:
    if on_progress is not None:
        on_progress(attempts)
