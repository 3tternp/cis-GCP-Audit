"""Executes registered checks against projects and produces Result objects."""
from __future__ import annotations

from collections import Counter
from threading import Event
from typing import Callable, Iterable, List, Optional

from . import checks as checks_mod
from .client import ApiError
from .models import ERROR, FAIL, MANUAL, NA, PASS, Check, Result


def _key(c: Check):
    return tuple(int(p) for p in c.id.split("."))


def all_checks() -> List[Check]:
    return sorted(checks_mod.REGISTRY, key=_key)


def select_checks(sections: Optional[Iterable[str]] = None, max_level: int = 2) -> List[Check]:
    secs = set(sections) if sections is not None else None
    return [c for c in all_checks() if (secs is None or c.section in secs) and c.level <= max_level]


def run_check(check: Check, ctx) -> Result:
    def mk(status, message, resources=None):
        return Result(check.id, check.title, check.section, check.level, check.severity, ctx.p,
                      status, message, resources or [], check.description, check.remediation)

    if check.func is None:
        return mk(MANUAL, "Manual verification required - cannot be assessed through the API")
    try:
        out = check.func(ctx)
        return mk(out.status, out.message, out.resources)
    except ApiError as exc:
        if exc.service_disabled:
            return mk(NA, "Required API is not enabled in this project (no resources to audit)")
        if exc.status == 403:
            return mk(ERROR, f"Permission denied - grant a viewer role for this API. {exc.message[:200]}")
        if exc.status == 404:
            return mk(ERROR, f"Resource not found: {exc.message[:200]}")
        return mk(ERROR, str(exc)[:300])
    except Exception as exc:  # a bug or odd payload in one check must not stop the audit
        return mk(ERROR, f"{type(exc).__name__}: {exc}"[:300])


def run_audit(client, projects: List[str], checks: List[Check],
              on_result: Optional[Callable[[Result, int, int], None]] = None,
              stop: Optional[Event] = None) -> List[Result]:
    results: List[Result] = []
    total = len(projects) * len(checks)
    done = 0
    for project in projects:
        ctx = checks_mod.Context(client, project)
        for chk in checks:
            if stop is not None and stop.is_set():
                return results
            res = run_check(chk, ctx)
            results.append(res)
            done += 1
            if on_result:
                on_result(res, done, total)
    return results


def summarize(results: List[Result]) -> dict:
    cnt = Counter(r.status for r in results)
    scored = cnt[PASS] + cnt[FAIL]
    return {
        "counts": {s: cnt.get(s, 0) for s in (PASS, FAIL, ERROR, MANUAL, NA)},
        "total": len(results),
        "score": round(100.0 * cnt[PASS] / scored, 1) if scored else None,
    }
