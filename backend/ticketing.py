"""Tickets for findings in Jira or ServiceNow (D3).

A ticket is created from the queue (backend.alert_delivery), so a ticket system that is
down delays it rather than losing it. Creation is made safe to repeat: every ticket
carries Sentro's own reference - a Jira label ``sentro-<id>``, a ServiceNow
``correlation_id`` - and before creating one the system is asked whether a ticket with
that reference exists (a process that died between the create and the record would
otherwise make a second ticket). An open ticket is asked for its status on a schedule;
when the system says it is done, the finding is resolved in Sentro, recorded as the
ticket's doing.

Jira: REST API v2 - Jira Cloud with an account e-mail and API token (basic), Jira Data
Center with a personal access token (bearer, no user name). A ticket is closed when its
status category is ``done``.
ServiceNow: the Table API on ``incident``, basic authentication. A ticket is closed when
its state is Resolved (6), Closed (7) or Canceled (8).
"""

from __future__ import annotations

import base64
from urllib.parse import quote

from backend.outbound import OutboundRefused, https_json

_SERVICENOW_CLOSED = {"6": "Resolved", "7": "Closed", "8": "Canceled"}


def marker(ticket_id: str) -> str:
    return f"sentro-{ticket_id}"


def _basic(username: str, secret: str) -> str:
    return "Basic " + base64.b64encode(f"{username}:{secret}".encode("utf-8")).decode("ascii")


def _check(status: int, what: str, *, expected=(200,)) -> None:
    if status in expected:
        return
    if status in (401, 403):
        raise OutboundRefused(f"{what}: the credentials were refused (HTTP {status}).")
    if status == 404:
        raise OutboundRefused(f"{what}: not found (HTTP 404) - check the address and the project.")
    raise OutboundRefused(f"{what}: HTTP {status}.")


class Jira:
    def __init__(self, config: dict, secret: str) -> None:
        self.base = str(config["base_url"]).rstrip("/")
        self.config = config
        username = str(config.get("username") or "")
        self.headers = {"Authorization": _basic(username, secret) if username else f"Bearer {secret}"}
        self.ca = str(config.get("ca_pem") or "")

    def _call(self, method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
        return https_json(method, f"{self.base}{path}", payload=payload, headers=self.headers, ca_pem=self.ca)

    def test(self) -> str:
        status, body = self._call("GET", "/rest/api/2/myself")
        _check(status, "Jira")
        status, _ = self._call("GET", f"/rest/api/2/project/{quote(self.config['project_key'])}")
        _check(status, f"Jira project {self.config['project_key']}")
        return f"Signed in to Jira as {str(body.get('displayName') or body.get('name') or 'the account')[:80]} and found project {self.config['project_key']}."

    def find(self, ticket_id: str) -> dict | None:
        jql = quote(f'labels = "{marker(ticket_id)}"')
        status, body = self._call("GET", f"/rest/api/2/search?jql={jql}&fields=status&maxResults=1")
        _check(status, "Jira search")
        issues = body.get("issues") or []
        if not issues:
            return None
        return self._ref(str(issues[0].get("key") or ""))

    def _ref(self, key: str) -> dict:
        return {"external_id": key, "external_key": key, "external_url": f"{self.base}/browse/{quote(key)}"}

    def create(self, ticket_id: str, summary: str, description: str) -> dict:
        status, body = self._call("POST", "/rest/api/2/issue", {"fields": {
            "project": {"key": self.config["project_key"]}, "summary": summary[:250], "description": description,
            "issuetype": {"name": self.config.get("issue_type") or "Task"},
            "labels": ["sentro", marker(ticket_id)]}})
        _check(status, "Jira issue", expected=(200, 201))
        key = str(body.get("key") or "")
        if not key:
            raise OutboundRefused("Jira created no issue key.")
        return self._ref(key)

    def status(self, external_id: str) -> tuple[bool, str]:
        status, body = self._call("GET", f"/rest/api/2/issue/{quote(external_id)}?fields=status")
        _check(status, f"Jira issue {external_id}")
        state = (body.get("fields") or {}).get("status") or {}
        category = str((state.get("statusCategory") or {}).get("key") or "")
        return category == "done", str(state.get("name") or category)[:60]


class ServiceNow:
    def __init__(self, config: dict, secret: str) -> None:
        self.base = str(config["instance_url"]).rstrip("/")
        self.config = config
        self.headers = {"Authorization": _basic(str(config.get("username") or ""), secret)}
        self.ca = str(config.get("ca_pem") or "")

    def _call(self, method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
        return https_json(method, f"{self.base}{path}", payload=payload, headers=self.headers, ca_pem=self.ca)

    def test(self) -> str:
        status, _ = self._call("GET", "/api/now/table/incident?sysparm_limit=1&sysparm_fields=sys_id")
        _check(status, "ServiceNow")
        return "Signed in to ServiceNow and read the incident table."

    def _ref(self, row: dict) -> dict:
        sys_id = str(row.get("sys_id") or "")
        return {"external_id": sys_id, "external_key": str(row.get("number") or sys_id),
                "external_url": f"{self.base}/nav_to.do?uri=incident.do?sys_id={quote(sys_id)}"}

    def find(self, ticket_id: str) -> dict | None:
        query = quote(f"correlation_id={marker(ticket_id)}")
        status, body = self._call("GET", f"/api/now/table/incident?sysparm_query={query}"
                                         "&sysparm_fields=sys_id,number&sysparm_limit=1")
        _check(status, "ServiceNow search")
        rows = body.get("result") or []
        return self._ref(rows[0]) if rows else None

    def create(self, ticket_id: str, summary: str, description: str) -> dict:
        payload = {"short_description": summary[:160], "description": description,
                   "correlation_id": marker(ticket_id), "correlation_display": "Sentro DSPM"}
        if self.config.get("assignment_group"):
            payload["assignment_group"] = self.config["assignment_group"]
        status, body = self._call("POST", "/api/now/table/incident", payload)
        _check(status, "ServiceNow incident", expected=(200, 201))
        row = body.get("result") or {}
        if not row.get("sys_id"):
            raise OutboundRefused("ServiceNow created no incident.")
        return self._ref(row)

    def status(self, external_id: str) -> tuple[bool, str]:
        status, body = self._call("GET", f"/api/now/table/incident/{quote(external_id)}?sysparm_fields=state,number")
        _check(status, f"ServiceNow incident {external_id}")
        state = str((body.get("result") or {}).get("state") or "")
        return state in _SERVICENOW_CLOSED, _SERVICENOW_CLOSED.get(state, f"state {state}" if state else "")


def client(system: str, config: dict, secret: str):
    if system == "jira":
        return Jira(config, secret)
    if system == "servicenow":
        return ServiceNow(config, secret)
    raise OutboundRefused("Unknown ticket system.")
