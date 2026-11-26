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


def discover_orgs(client, projects: Iterable[str]) -> List[str]:
    """Organization IDs found in the hierarchy of the given projects (best effort)."""
    orgs = set()
    for p in projects:
        ancestors, _note = checks_mod.Context(client, p).ancestors()
        orgs.update(ident for kind, ident in ancestors if kind == "organization")
    return sorted(orgs)


def run_audit(client, projects: List[str], checks: List[Check],
              on_result: Optional[Callable[[Result, int, int], None]] = None,
              stop: Optional[Event] = None) -> List[Result]:
    """Run project-scope checks per project and org-scope checks once per organization found."""
    proj_checks = [c for c in checks if c.scope == "project"]
    org_checks = [c for c in checks if c.scope == "org"]
    orgs = discover_orgs(client, projects) if org_checks else []
    total = len(projects) * len(proj_checks) + (len(orgs) or 1) * len(org_checks)

    results: List[Result] = []
    done = 0

    def emit(res: Result):
        nonlocal done
        results.append(res)
        done += 1
        if on_result:
            on_result(res, done, total)

    for project in projects:
        ctx = checks_mod.Context(client, project)
        for chk in proj_checks:
            if stop is not None and stop.is_set():
                return results
            emit(run_check(chk, ctx))

    if org_checks and not orgs:
        for chk in org_checks:
            emit(Result(chk.id, chk.title, chk.section, chk.level, chk.severity, "organization", NA,
                        "No organization found in the project hierarchy (standalone project, or the "
                        "hierarchy is not readable with these credentials)", [], chk.description,
                        chk.remediation))
    for org in orgs:
        ctx = checks_mod.OrgContext(client, org)
        for chk in org_checks:
            if stop is not None and stop.is_set():
                return results
            emit(run_check(chk, ctx))
    return results


def summarize(results: List[Result]) -> dict:
    cnt = Counter(r.status for r in results)
    scored = cnt[PASS] + cnt[FAIL]
    return {
        "counts": {s: cnt.get(s, 0) for s in (PASS, FAIL, ERROR, MANUAL, NA)},
        "total": len(results),
        "score": round(100.0 * cnt[PASS] / scored, 1) if scored else None,
    }
