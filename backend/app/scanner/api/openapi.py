"""Parsing OpenAPI 3.x and Swagger 2.0 documents.

A specification is a claim, not a fact. It says an operation exists; it does not
say the operation is reachable, that it works, or that the document is current.
So everything parsed here is recorded as `documented`, distinct from `observed`,
and the report keeps the two apart. **Nothing described by a specification is
ever executed** — this module reads a document and stops.

Security requirements are read as metadata only. Learning that an API expects a
bearer token does not cause the scanner to construct one, prompt for one, or try
one. Credentials come from the authorized user and from nowhere else.

Parsing is total: any malformed, hostile or simply unexpected document yields
`None` or a partial result rather than an exception. A scan must not fail
because a target published broken JSON.
"""

from __future__ import annotations

import logging
from typing import Any

from app.scanner.api.types import (
    ApiConfidence,
    ApiEndpoint,
    ApiParameter,
    ApiParameterLocation,
    ApiSource,
    ApiDiscoveryLimits,
    OpenApiDocument,
    SecurityScheme,
)

logger = logging.getLogger(__name__)

#: The methods an OpenAPI path item may declare. Anything else in the object is
#: metadata (`parameters`, `summary`, `servers`) and is not an operation.
_HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")

_LOCATION_BY_NAME = {
    "path": ApiParameterLocation.PATH,
    "query": ApiParameterLocation.QUERY,
    "header": ApiParameterLocation.HEADER,
    "cookie": ApiParameterLocation.COOKIE,
    "formData": ApiParameterLocation.BODY,
    "body": ApiParameterLocation.BODY,
}


def looks_like_specification(document: Any) -> bool:
    """Whether a parsed document is an OpenAPI or Swagger specification.

    Requires both the version marker and a `paths` object. A document with
    `openapi: 3.0.0` and nothing else describes no surface, and treating it as a
    specification would let any JSON file with a stray key be counted as API
    documentation.
    """
    if not isinstance(document, dict):
        return False
    has_version = isinstance(document.get("openapi"), str) or isinstance(
        document.get("swagger"), str
    )
    return has_version and isinstance(document.get("paths"), dict)


def _version_of(document: dict) -> str | None:
    openapi = document.get("openapi")
    if isinstance(openapi, str) and openapi.strip():
        return openapi.strip()
    swagger = document.get("swagger")
    if isinstance(swagger, str) and swagger.strip():
        return swagger.strip()
    return None


def _text(value: Any, limit: int = 255) -> str | None:
    """A bounded string, or None. Specification text is untrusted input."""
    if not isinstance(value, str):
        return None
    cleaned = value.strip().replace("\r", " ").replace("\n", " ")
    return cleaned[:limit] or None


def _security_schemes(document: dict, version: str) -> tuple[SecurityScheme, ...]:
    """Declared authentication schemes. Names and kinds only.

    Recorded so a reviewer can see what the API expects. The scanner does not
    act on any of it.
    """
    if version.startswith("2"):
        raw = document.get("securityDefinitions")
    else:
        components = document.get("components")
        raw = components.get("securitySchemes") if isinstance(components, dict) else None

    if not isinstance(raw, dict):
        return ()

    schemes: list[SecurityScheme] = []
    for name, definition in list(raw.items())[:50]:
        if not isinstance(definition, dict):
            continue
        schemes.append(
            SecurityScheme(
                name=str(name)[:120],
                kind=_text(definition.get("type"), 40) or "unknown",
                location=_text(definition.get("in"), 40),
                scheme=_text(definition.get("scheme"), 40),
            )
        )
    return tuple(schemes)


def _parameters(raw: Any, limit: int) -> list[ApiParameter]:
    """Parameters from an operation or path item. Names and locations only."""
    if not isinstance(raw, list):
        return []

    parameters: list[ApiParameter] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        # A `$ref` is not resolved: following references into a document the
        # target controls is a graph walk with cycles, and the name it would
        # yield is not worth the complexity here.
        name = _text(entry.get("name"), 255)
        if not name:
            continue
        location = _LOCATION_BY_NAME.get(
            entry.get("in") if isinstance(entry.get("in"), str) else "", ApiParameterLocation.QUERY
        )
        required = entry.get("required")
        parameters.append(
            ApiParameter(
                name=name,
                location=location,
                required=required if isinstance(required, bool) else None,
            )
        )
        if len(parameters) >= limit:
            break
    return parameters


def _body_parameters(operation: dict, version: str, limit: int) -> list[ApiParameter]:
    """Named request-body fields, where the document spells them out.

    Names only, and never submitted: phase 13 sends no request body at all. This
    exists so a reviewer can see what an operation accepts.
    """
    if version.startswith("2"):
        return []

    request_body = operation.get("requestBody")
    if not isinstance(request_body, dict):
        return []
    content = request_body.get("content")
    if not isinstance(content, dict):
        return []

    required_names: set[str] = set()
    names: list[str] = []
    for media in content.values():
        if not isinstance(media, dict):
            continue
        schema = media.get("schema")
        if not isinstance(schema, dict):
            continue
        required = schema.get("required")
        if isinstance(required, list):
            required_names.update(str(item) for item in required if isinstance(item, str))
        properties = schema.get("properties")
        if isinstance(properties, dict):
            for name in properties:
                if str(name) not in names:
                    names.append(str(name))
        if len(names) >= limit:
            break

    return [
        ApiParameter(
            name=name[:255],
            location=ApiParameterLocation.BODY,
            required=True if name in required_names else None,
        )
        for name in names[:limit]
    ]


def _first_media_type(container: Any, version: str) -> str | None:
    """The first declared media type of a request body or response."""
    if not isinstance(container, dict):
        return None
    content = container.get("content")
    if isinstance(content, dict):
        for media in content:
            return _text(media, 120)
    return None


def _response_media_type(operation: dict, version: str) -> str | None:
    if version.startswith("2"):
        produces = operation.get("produces")
        if isinstance(produces, list) and produces:
            return _text(produces[0], 120)
        return None

    responses = operation.get("responses")
    if not isinstance(responses, dict):
        return None
    # Prefer a success response: what the endpoint returns when it works is what
    # describes it, not what it returns when it fails.
    for status in ("200", "201", "default"):
        media = _first_media_type(responses.get(status), version)
        if media:
            return media
    for response in responses.values():
        media = _first_media_type(response, version)
        if media:
            return media
    return None


def _request_media_type(operation: dict, version: str) -> str | None:
    if version.startswith("2"):
        consumes = operation.get("consumes")
        if isinstance(consumes, list) and consumes:
            return _text(consumes[0], 120)
        return None
    return _first_media_type(operation.get("requestBody"), version)


def _operation_security(operation: dict, document: dict) -> tuple[str, ...]:
    """Security scheme names for one operation, falling back to the document's.

    An operation with `security: []` has explicitly opted out, which is
    different from having said nothing — so an empty list is respected rather
    than replaced by the document-level default.
    """
    raw = operation.get("security")
    if not isinstance(raw, list):
        raw = document.get("security")
    if not isinstance(raw, list):
        return ()

    names: list[str] = []
    for requirement in raw[:20]:
        if not isinstance(requirement, dict):
            continue
        for name in requirement:
            text = _text(name, 120)
            if text and text not in names:
                names.append(text)
    return tuple(names)


def parse_specification(
    document: Any, *, url: str, limits: ApiDiscoveryLimits | None = None
) -> tuple[OpenApiDocument, list[ApiEndpoint]] | None:
    """Read a specification into a document summary and its operations.

    Returns `None` when the input is not a specification. Never raises: a
    malformed document yields whatever could be read, because a target's broken
    JSON is not a reason to fail a scan.
    """
    bounds = limits or ApiDiscoveryLimits()

    if not looks_like_specification(document):
        return None

    version = _version_of(document)
    if version is None:  # pragma: no cover - looks_like_specification checked it
        return None

    info = document.get("info")
    title = _text(info.get("title")) if isinstance(info, dict) else None
    document_version = _text(info.get("version"), 60) if isinstance(info, dict) else None

    paths = document.get("paths")
    endpoints: list[ApiEndpoint] = []
    truncated = False
    path_count = 0
    source = ApiSource.SWAGGER if version.startswith("2") else ApiSource.OPENAPI

    try:
        for raw_path, path_item in paths.items():
            if path_count >= bounds.max_parsed_paths:
                truncated = True
                break
            if not isinstance(path_item, dict):
                continue

            path = _text(raw_path, 1024)
            if not path or not path.startswith("/"):
                continue
            path_count += 1

            # Path-level parameters apply to every operation beneath them.
            shared = _parameters(
                path_item.get("parameters"), bounds.max_parameters_per_endpoint
            )

            for method in _HTTP_METHODS:
                operation = path_item.get(method)
                if not isinstance(operation, dict):
                    continue

                parameters = list(shared)
                parameters.extend(
                    _parameters(
                        operation.get("parameters"), bounds.max_parameters_per_endpoint
                    )
                )
                parameters.extend(
                    _body_parameters(operation, version, bounds.max_parameters_per_endpoint)
                )

                # Deduplicate by name and location, keeping declaration order.
                unique: dict[tuple[str, str], ApiParameter] = {}
                for parameter in parameters:
                    unique.setdefault(parameter.identity, parameter)

                endpoints.append(
                    ApiEndpoint(
                        path=path,
                        method=method.upper(),
                        # Documented, not observed: there is no URL the scanner
                        # actually requested, and inventing one would blur the
                        # distinction the whole report rests on.
                        url=None,
                        confidence=ApiConfidence.MEDIUM,
                        sources=frozenset({source}),
                        request_media_type=_request_media_type(operation, version),
                        response_media_type=_response_media_type(operation, version),
                        operation_id=_text(operation.get("operationId"), 255),
                        parameters=tuple(
                            list(unique.values())[: bounds.max_parameters_per_endpoint]
                        ),
                        security=_operation_security(operation, document),
                    )
                )
    except Exception:  # noqa: BLE001 - a target's document must not end a scan
        logger.exception("Failed while reading an API specification")

    summary = OpenApiDocument(
        url=url,
        version=version,
        title=title,
        document_version=document_version,
        path_count=path_count,
        operation_count=len(endpoints),
        security_schemes=_security_schemes(document, version),
        truncated=truncated,
    )
    return summary, endpoints
