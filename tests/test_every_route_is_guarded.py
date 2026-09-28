"""Every route resolves a principal, except the few that are public on purpose.

A route added without `Depends(require_role(...))` answers anybody who asks, and nothing
in the suite noticed: the endpoint tests each check their own endpoint, and an endpoint
written tomorrow has no test until somebody writes one. This walks the application's own
routing table instead, so the check covers routes that do not exist yet.

The public set is small and each entry earns its place: the sign-in pair, the two probes a
load balancer calls, the HTML shells (whose data all comes from guarded APIs), and the
catch-all that turns an unknown path into a 404. Adding to this list is a deliberate act -
which is the point of writing it down.
"""

from __future__ import annotations

import unittest

from fastapi.routing import APIRoute

from backend.app import app
from backend.security import Principal

PUBLIC_PATHS = {
    # Authentication itself cannot require authentication.
    "/api/auth/login",
    "/api/auth/register",
    # C1: the refresh cookie IS the credential here, and the access token this route
    # replaces has usually expired by the time it is called - requiring one would make
    # the endpoint useless. Every failure clears the cookie and answers 401 with the
    # same body, so it tells a caller nothing it did not already hold.
    "/api/auth/refresh",
    # C2: the second step of sign-in. Its credential is the five-minute challenge token
    # the password step returned (signed, bound to one account and one purpose, spent
    # on success); every route answers 401 without a valid one, and wrong codes are
    # throttled per account.
    "/api/auth/mfa/verify",
    "/api/auth/mfa/enroll/start",
    "/api/auth/mfa/enroll/confirm",
    # Liveness and readiness: called by whatever restarts the service.
    "/api/health",
    "/api/ready",
    # The console's HTML shells. Every byte of data in them arrives through a
    # guarded /api route, and the browser needs the page before it has a token.
    "/",
    "/administration",
    "/dashboard",
    "/evidence",
    "/findings",
    "/login",
    "/profile",
    "/register",
    "/remediation",
    "/scan",
    # Anything else is a 404 rendered by the application rather than the server.
    "/{unmatched_path:path}",
}


def _resolves_a_principal(route: APIRoute) -> bool:
    """Whether anything in the route's dependency tree produces a Principal.

    Asked of the resolved tree rather than of the source, so a route guarded through
    `require_role`, `require_principal` or the artifact download's own token dependency
    all count, and a route that merely mentions one in a comment does not.
    """
    stack = list(route.dependant.dependencies)
    seen: set[int] = set()
    while stack:
        dependency = stack.pop()
        if id(dependency) in seen:
            continue
        seen.add(id(dependency))
        call = getattr(dependency, "call", None)
        annotations = getattr(call, "__annotations__", {}) or {}
        if annotations.get("return") in (Principal, "Principal"):
            return True
        stack.extend(getattr(dependency, "dependencies", []) or [])
    return False


class EveryRouteIsGuardedTest(unittest.TestCase):
    def setUp(self) -> None:
        self.routes = [route for route in app.routes if isinstance(route, APIRoute)]

    def test_the_application_has_routes_to_check(self) -> None:
        self.assertGreater(len(self.routes), 50, "the routing table could not be read")

    def test_every_route_outside_the_public_set_resolves_a_principal(self) -> None:
        unguarded = sorted(
            f"{','.join(sorted(route.methods))} {route.path}"
            for route in self.routes
            if route.path not in PUBLIC_PATHS and not _resolves_a_principal(route)
        )
        self.assertEqual(unguarded, [], "these routes answer anybody who asks")

    def test_every_api_route_in_the_public_set_is_one_of_the_four_named(self) -> None:
        public_api = sorted(
            route.path for route in self.routes
            if route.path.startswith("/api/") and not _resolves_a_principal(route)
        )
        self.assertEqual(
            public_api,
            ["/api/auth/login", "/api/auth/mfa/enroll/confirm", "/api/auth/mfa/enroll/start",
             "/api/auth/mfa/verify", "/api/auth/refresh", "/api/auth/register",
             "/api/health", "/api/ready"],
            "an /api route became public without being named here",
        )

    def test_the_public_list_does_not_outlive_its_routes(self) -> None:
        paths = {route.path for route in self.routes}
        self.assertEqual(sorted(PUBLIC_PATHS - paths), [],
                         "the public list names a route the application no longer has")


if __name__ == "__main__":
    unittest.main()
