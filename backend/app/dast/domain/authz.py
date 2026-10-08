"""Multi-role authorization testing, pure parts (DAST-10-010 .. -040).

The idea: take what one identity (the *owner*) could reach, replay the same requests as every other
identity (the *actor*, Anonymous included) and see where a request that should have been refused
came back successful and materially the same. That is `auth_boundary_crossed`
(`detectors.auth_boundary_crossed`); this module decides which pairs to try, how privilege is
ordered, how a crossing is classified, and how results become the role-by-role matrix.

Identities are named by their **label** throughout (a scan may have two identities with the same
role); the role decides privilege.

Privilege order: Admin > User > Viewer > Anonymous, derived from the identity roles and overridable
per scan. A Custom role has no implicit place in that order; until the operator sets one, a crossing
involving it is reported `false_positive` with the reason, never guessed.

Precision limits (documented): an endpoint that is public by design and returns the same thing to
everyone is indistinguishable from a missing check, so well-known public paths (login, health,
schema documents, ...) and endpoints an anonymous identity was *observed* reaching are not replayed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .browser_probe import is_destructive_destination
from .entities import Endpoint, EndpointSource, Location, RoleName
from .identities import IdentitySpec

# ---- privilege ------------------------------------------------------------------------------------

DEFAULT_PRIVILEGE = {RoleName.ADMIN.value: 3, RoleName.USER.value: 2, RoleName.VIEWER.value: 1, RoleName.ANONYMOUS.value: 0}

BFLA, BOLA, AUTHN = "dast-bfla", "dast-bola", "dast-authn"

# Public by design: replaying these as anonymous would "find" what is meant to be there.
# Static assets (`/assets/`, `/static/`, `/public/` mounts, or a recognized file extension) are a
# separate, orthogonal notion handled by `Endpoint.kind == "asset"` (`inventory.guess_kind`) -
# `replayable()` below checks that independently so there is exactly one place that decides what
# counts as a static file.
PUBLIC_PATH = re.compile(
    r"^/(?:|login|log-in|signin|sign-in|register|signup|sign-up|health|healthz|ping|status|robots\.txt|favicon\.ico|"
    r"openapi(?:\.json|\.yaml)?|swagger(?:\.json|\.yaml|-ui.*)?|docs|api-docs|v\d/api-docs|\.well-known/.*)/?$",
    re.IGNORECASE,
)
_OBJECT_ID_PARAM = re.compile(r"(?:^|_)(?:id|uuid|guid|key|ref|number|no)$|^(?:user|account|order|customer|doc|file|object|item|invoice|profile)", re.IGNORECASE)
_ID_SEGMENT = re.compile(r"(?<=/)(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,})(?=/|$)")
_PLACEHOLDER = re.compile(r"\{[^{}/]+\}")


def privilege_of(spec: IdentitySpec, overrides: Mapping[str, int] | None = None) -> int | None:
    """The identity's privilege rank, or None for a Custom role the operator has not ranked.
    `overrides` maps an identity label or a custom role name to a rank."""
    overrides = {k.lower(): v for k, v in (overrides or {}).items()}
    for key in (spec.label.lower(), spec.role.label.lower()):
        if key and key in overrides:
            return int(overrides[key])
    if spec.role.name is RoleName.CUSTOM:
        return None
    return DEFAULT_PRIVILEGE[spec.role.name.value]


# ---- pairs ------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class RolePair:
    owner: str  # identity label of the one whose requests are replayed
    actor: str  # identity label of the one replaying them
    anonymous: bool  # the actor is the anonymous baseline


def role_pairs(specs: Sequence[IdentitySpec]) -> list[RolePair]:
    """Every ordered (owner, actor) pair: each authenticated identity as owner, every *other*
    authenticated identity as actor, then Anonymous. For A authenticated identities that is
    A*(A-1) + A pairs, in declaration order (so a run is reproducible)."""
    authenticated = [s for s in specs if s.authenticated and not s.is_anonymous]
    anonymous = next((s for s in specs if s.is_anonymous), None)
    pairs: list[RolePair] = []
    for owner in authenticated:
        for actor in authenticated:
            if actor.identity_id != owner.identity_id:
                pairs.append(RolePair(owner.label, actor.label, False))
        if anonymous is not None:
            pairs.append(RolePair(owner.label, anonymous.label, True))
    return pairs


# ---- which requests are worth replaying -------------------------------------------------------------


def has_object_identifier(endpoint: Endpoint) -> bool:
    """The request names an object: a path placeholder or an id-looking query/body parameter."""
    if _PLACEHOLDER.search(endpoint.path_template):
        return True
    return any(_OBJECT_ID_PARAM.search(p.name) for p in endpoint.parameters)


def is_public_path(endpoint: Endpoint) -> bool:
    return bool(PUBLIC_PATH.match(urlsplit(endpoint.url or endpoint.path_template).path or "/"))


def replayable(endpoint: Endpoint, *, allow_state_changing: bool, anonymous_id: str | None, spa: bool = False) -> bool:
    """A request worth replaying: an API or page the scan can address, not a static asset or a public
    path, not already seen reachable by Anonymous, and read-only unless state-changing methods were
    opted in.

    `spa=True` (the fingerprinted shape is a single-page app) additionally excludes `kind=="page"`
    endpoints: a client-rendered route typically serves the same shell markup to every identity
    regardless of authorization, so replaying it looks like a boundary crossing that never happened.
    API operations captured during the crawl or from a schema are unaffected.

    A logout/deletion/payment-shaped endpoint is never a candidate either: replaying it as another
    identity would tear down that identity's own session or trigger a real side effect, not test a
    boundary."""
    if endpoint.kind == "asset" or not endpoint.url or "#" in endpoint.path_template:
        return False
    if is_destructive_destination(endpoint.url or endpoint.path_template):
        return False
    if spa and endpoint.kind == "page":
        return False
    if endpoint.state_changing and not allow_state_changing:
        return False
    if is_public_path(endpoint):
        return False
    return not (anonymous_id and anonymous_id in endpoint.seen_as)


_SOURCE_RANK = {EndpointSource.SCHEMA: 0, EndpointSource.BOTH: 0, EndpointSource.OBSERVED: 1}


def owner_candidates(endpoints: Iterable[Endpoint], owner_id: str, *, allow_state_changing: bool, anonymous_id: str | None, spa: bool = False) -> list[Endpoint]:
    """The requests `owner_id` is taken to have reached: endpoints the crawl saw it use, plus
    schema-only endpoints nobody has used yet (the owner's own request will tell whether it may call
    them: a refusal means it did not reach them). Deterministic order.

    On a single-page app (`spa=True`), a real API operation (schema-described or `kind=="api"`) is
    ordered before any other replayable entry, so the replay cap (when reached) truncates the less
    informative tail first rather than crowding out API coverage with client-side routes."""
    out = []
    for e in endpoints:
        if not replayable(e, allow_state_changing=allow_state_changing, anonymous_id=anonymous_id, spa=spa):
            continue
        if owner_id in e.seen_as or (not e.seen_as and e.source is EndpointSource.SCHEMA):
            out.append(e)
    if spa:
        return sorted(out, key=lambda e: (0 if e.kind == "api" else 1, _SOURCE_RANK.get(e.source, 1), e.path_template, e.method))
    return sorted(out, key=lambda e: (e.path_template, e.method))


# ---- classification -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Boundary:
    check_id: str  # dast-authn | dast-bfla | dast-bola
    kind: str  # "anonymous" | "function" | "object"
    verdict: str  # "true_positive" | "false_positive" | "unverified"
    reason: str = ""


def _security_gated(check_id: str, kind: str, endpoint: Endpoint) -> Boundary:
    """What an otherwise-qualifying crossing is worth, given whether the endpoint ever declared
    a security requirement (`Endpoint.security_declared`, from the ingested OpenAPI document):

    * declared (True): the crossing is real proof - a boundary that was supposed to hold did not.
    * declared absent (False): equal access is expected for an endpoint with no stated requirement;
      this is not a finding.
    * unknown (None, no schema source ever described this endpoint): neither proven nor
      dismissed - `unverified`, for a human to confirm."""
    if endpoint.security_declared is True:
        return Boundary(check_id, kind, "true_positive")
    if endpoint.security_declared is False:
        return Boundary(check_id, kind, "false_positive", "the endpoint declares no security requirement, so equal access by a different identity is expected")
    return Boundary(check_id, kind, "unverified", "the endpoint's security requirement is not described by any ingested API schema; confirm manually")


def classify_crossing(
    pair: RolePair,
    owner: IdentitySpec | None,
    actor: IdentitySpec | None,
    endpoint: Endpoint,
    *,
    privilege: Mapping[str, int] | None = None,
) -> Boundary | None:
    """What a successful, materially-equivalent replay means, or None when it is expected.

    * Anonymous actor: broken authentication (API2): a request made with a session worked with none.
    * Actor of lower privilege than the owner: broken function-level authorization (API5) when the
      endpoint is a privileged function (no object identifier, or one the actor was never seen
      reaching); broken object-level authorization (API1) when it names an object.
    * Actor of equal privilege: only object-level (a peer reading a peer's object). A peer reaching a
      plain function is normal.
    * Actor of higher privilege than the owner: expected, never a finding.
    * A rank that cannot be determined (Custom role without an order): `false_positive`, with the reason.

    Every case that would otherwise be `true_positive` is additionally gated on whether the
    endpoint's OpenAPI description ever declared a security requirement for it (`_security_gated`):
    without that proof the crossing is downgraded to `false_positive` (no requirement declared) or
    `unverified` (no schema ever described the endpoint)."""
    if pair.anonymous:
        return _security_gated(AUTHN, "anonymous", endpoint)
    if owner is None or actor is None:
        return None
    owner_rank, actor_rank = privilege_of(owner, privilege), privilege_of(actor, privilege)
    object_ids = has_object_identifier(endpoint)
    if owner_rank is None or actor_rank is None:
        who = ", ".join(s.role_display for s in (owner, actor) if privilege_of(s, privilege) is None)
        kind = "object" if object_ids else "function"
        return Boundary(
            BOLA if object_ids else BFLA, kind, "false_positive",
            f"the role {who!r} has no privilege order, so it cannot be said whether this access is excessive; set an order for it to decide",
        )
    if actor_rank > owner_rank:
        return None
    if actor_rank < owner_rank:
        reached_by_actor = actor.identity_id in endpoint.seen_as
        if object_ids and reached_by_actor:
            return _security_gated(BOLA, "object", endpoint)
        return _security_gated(BFLA, "function", endpoint)
    return _security_gated(BOLA, "object", endpoint) if object_ids else None


def _path_shape(path: str) -> str:
    return _ID_SEGMENT.sub("{}", path or "")


def alternate_object_value(endpoint: Endpoint, pool: Sequence[Endpoint]) -> tuple[str, Location, str] | None:
    """An object id seen on the same method and path shape, different from the one this request uses."""
    own: dict[tuple[Location, str], str] = {}
    for param in endpoint.parameters:
        if _OBJECT_ID_PARAM.search(param.name) and param.observed_values:
            own[(param.location, param.name)] = str(param.observed_values[0])
    shape = _path_shape(urlsplit(endpoint.url or endpoint.path_template).path)
    for other in pool:
        if other is endpoint or other.method.upper() != endpoint.method.upper():
            continue
        if _path_shape(urlsplit(other.url or other.path_template).path) != shape:
            continue
        for param in other.parameters:
            key = (param.location, param.name)
            if key not in own or not param.observed_values:
                continue
            value = str(param.observed_values[0])
            if value and value != own[key]:
                return param.name, param.location, value
    return None


def endpoint_with_object_value(endpoint: Endpoint, name: str, location: Location, value: str) -> Endpoint:
    """A copy of `endpoint` whose URL and matching parameter use `value` instead of the observed id."""
    parameters = tuple(
        replace(param, observed_values=(value,)) if param.name == name and param.location is location else param
        for param in endpoint.parameters
    )
    parts = urlsplit(endpoint.url)
    path = parts.path
    query = parse_qsl(parts.query, keep_blank_values=True)
    if location is Location.PATH:
        matches = list(_ID_SEGMENT.finditer(path))
        if matches:
            last = matches[-1]
            path = path[: last.start()] + value + path[last.end() :]
        elif "{" + name + "}" in (endpoint.path_template or ""):
            path = endpoint.path_template.replace("{" + name + "}", value)
    elif location is Location.QUERY:
        query = [(key, value if key == name else current) for key, current in query]
        if name not in {key for key, _ in query}:
            query.append((name, value))
    url = urlunsplit((parts.scheme, parts.netloc, path, urlencode(query), ""))
    return replace(endpoint, parameters=parameters, url=url)


# ---- the matrix -----------------------------------------------------------------------------------------

OK, FAIL, UNTESTED = "OK", "FAIL", "untested"


@dataclass(frozen=True)
class ReplaySummary:
    """What one (owner, actor) pair's replays amounted to, as stored in the scan's discovery summary."""

    owner: str
    actor: str
    replays: int  # requests replayed as the actor
    denied: int = 0  # the target correctly refused (401/403 or equivalent)
    crossed: int = 0  # successful, materially equivalent: a boundary was crossed
    owned: int = 0  # requests the owner reached (the candidates)
    truncated: bool = False  # the replay cap stopped this pair early
    session_lost: bool = False  # the actor's session died mid-replay; remaining requests were skipped

    def to_dict(self) -> dict[str, Any]:
        return {
            "owner": self.owner, "actor": self.actor, "replays": self.replays, "denied": self.denied,
            "crossed": self.crossed, "owned": self.owned, "truncated": self.truncated, "session_lost": self.session_lost,
        }


@dataclass(frozen=True)
class MatrixCell:
    owner: str
    actor: str
    result: str  # OK | FAIL | untested
    failures: int = 0
    reason: str = ""  # why untested
    finding_ids: tuple[str, ...] = ()
    finding_keys: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "owner": self.owner, "actor": self.actor, "result": self.result, "failures": self.failures, "reason": self.reason,
            "finding_ids": list(self.finding_ids), "finding_keys": list(self.finding_keys),
        }


@dataclass(frozen=True)
class FindingRef:
    finding_id: str
    key: str  # "rule|target"
    roles: tuple[str, ...]  # (owner label, actor label)
    verdict: str


def untested_reason(pair: RolePair, specs: Sequence[IdentitySpec], *, ran: bool, replay: ReplaySummary | None) -> str:
    authenticated = [s for s in specs if s.authenticated and not s.is_anonymous]
    if not ran:
        return "the authorization checks have not run yet"
    if not pair.anonymous and len(authenticated) < 2:
        return "no second identity was supplied"
    if replay is not None and replay.session_lost:
        return f"{pair.owner}'s or {pair.actor}'s session was lost mid-replay; the remaining requests were skipped"
    if replay is None or replay.owned == 0:
        return f"no resource reached by {pair.owner} was discovered"
    if replay.replays == 0:
        return "every request was skipped (state-changing methods are not enabled, or the replay cap was reached)"
    return ""


def derive_matrix(
    specs: Sequence[IdentitySpec],
    replays: Sequence[ReplaySummary | Mapping[str, Any]],
    findings: Sequence[FindingRef],
    *,
    ran: bool,
) -> list[MatrixCell]:
    """The matrix, recomputed from what is stored: replay summaries (what was tried) and findings
    (what failed). Nothing here is kept between calls, so it cannot drift from the findings.

    A cell is `FAIL` with `failures` equal to the number of findings behind it (confirmed or
    unverified), `OK` when replays ran for the pair and produced none, and `untested` with a reason
    otherwise. Anonymous is always a column; an owner row exists for each authenticated identity."""
    summaries = {
        (r.owner, r.actor): r for r in (ReplaySummary(**{k: v for k, v in dict(x).items() if k in ReplaySummary.__dataclass_fields__}) if isinstance(x, Mapping) else x for x in replays)
    }
    by_pair: dict[tuple[str, str], list[FindingRef]] = {}
    for ref in findings:
        if len(ref.roles) >= 2:
            by_pair.setdefault((ref.roles[0], ref.roles[1]), []).append(ref)
    cells: list[MatrixCell] = []
    for pair in role_pairs(specs):
        refs = by_pair.get((pair.owner, pair.actor), [])
        replay = summaries.get((pair.owner, pair.actor))
        if refs:
            cells.append(MatrixCell(pair.owner, pair.actor, FAIL, len(refs), "", tuple(r.finding_id for r in refs), tuple(r.key for r in refs)))
        elif ran and replay is not None and replay.replays > 0:
            cells.append(MatrixCell(pair.owner, pair.actor, OK))
        else:
            cells.append(MatrixCell(pair.owner, pair.actor, UNTESTED, 0, untested_reason(pair, specs, ran=ran, replay=replay)))
    return cells


def matrix_notes(specs: Sequence[IdentitySpec]) -> dict[str, Any]:
    authenticated = [s for s in specs if s.authenticated and not s.is_anonymous]
    return {
        "degraded": len(authenticated) < 2,
        "degraded_reason": "no second identity: only the anonymous replay runs" if len(authenticated) < 2 else "",
        "authenticated_identities": len(authenticated),
    }
