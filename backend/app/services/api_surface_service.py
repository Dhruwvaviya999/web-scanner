"""Persistence and retrieval of the discovered API attack surface.

The only place an `ApiSurface` becomes database rows. The API package itself
holds no session and imports no model, exactly like the crawler.

Two things this module is careful about:

* **Observed operations are linked to their crawl row**, so the API view and the
  attack-surface view describe the same thing rather than two parallel
  inventories. A documented-only operation has no such row, and that absence is
  the record of it never having been reached.
* **Nothing sensitive is written.** The surface handed in already contains no
  response body, no parameter value and no credential; this module copies field
  names, counters and media types, and there is no branch here that could copy
  anything else.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models.api_surface import (
    ApiDocument,
    ApiEndpointParameter,
    ApiEndpointRow,
    join_list,
)
from app.models.attack_surface import Endpoint
from app.models.scan import Scan
from app.models.user import User
from app.scanner.api.types import ApiSurface
from app.services import scan_service


def replace_api_surface(
    db: Session,
    scan: Scan,
    surface: ApiSurface | None,
    endpoints_by_url: Mapping[str, Endpoint] | None = None,
) -> None:
    """Store `surface` as the complete API attack surface for `scan`.

    Existing rows are cleared first, so a re-run cannot leave a stale endpoint
    behind. A `None` surface — the stage disabled, or the probe never connected
    — leaves the counters NULL rather than writing zeroes, keeping "did not look"
    distinguishable from "looked and found nothing".
    """
    scan.api_endpoints.clear()
    scan.api_documents.clear()
    db.flush()

    if surface is None:
        return

    by_url = endpoints_by_url or {}
    stats = surface.stats

    scan.api_detected = bool(
        stats.endpoints_discovered or stats.documents_found or stats.graphql_endpoints
    )
    scan.api_endpoints_discovered = stats.endpoints_discovered
    scan.api_endpoints_observed = stats.endpoints_observed
    scan.api_endpoints_documented_only = stats.endpoints_documented_only
    scan.api_parameters_discovered = stats.parameters_discovered
    scan.api_document_count = stats.documents_found
    scan.api_authenticated_endpoints = stats.authenticated_endpoints
    scan.api_unknown_auth_endpoints = stats.unknown_auth_endpoints
    scan.api_truncated = stats.truncated
    scan.api_graphql_detected = surface.graphql.detected
    scan.api_graphql_path = surface.graphql.path

    for endpoint in surface.endpoints:
        # Link to the crawl row when this operation was actually reached. A
        # documented-only one has no URL and therefore no match, which is
        # precisely what records that nobody requested it.
        crawl_row = by_url.get(endpoint.url) if endpoint.url else None
        shape = endpoint.json_shape

        row = ApiEndpointRow(
            scan_id=scan.id,
            endpoint_id=crawl_row.id if crawl_row is not None else None,
            path=endpoint.path,
            method=endpoint.method,
            url=endpoint.url,
            confidence=endpoint.confidence.value,
            sources=join_list(sorted(source.value for source in endpoint.sources)),
            auth_status=endpoint.auth_status.value,
            observed=endpoint.observed,
            documented=endpoint.documented,
            status_code=endpoint.status_code,
            request_media_type=endpoint.request_media_type,
            response_media_type=endpoint.response_media_type,
            operation_id=endpoint.operation_id,
            security=join_list(endpoint.security),
            json_top_level=shape.top_level if shape else None,
            # Names only. The values behind them were discarded with the body.
            json_field_names=join_list(shape.field_names) if shape else None,
            json_depth=shape.depth if shape else None,
            json_field_count=shape.field_count if shape else None,
        )
        row.parameters = [
            ApiEndpointParameter(
                name=parameter.name,
                location=parameter.location.value,
                required=parameter.required,
            )
            for parameter in endpoint.parameters
        ]
        db.add(row)

    for document in surface.documents:
        db.add(
            ApiDocument(
                scan_id=scan.id,
                url=document.url,
                version=document.version,
                title=document.title,
                document_version=document.document_version,
                path_count=document.path_count,
                operation_count=document.operation_count,
                security_schemes=join_list(
                    scheme.name for scheme in document.security_schemes
                ),
                truncated=document.truncated,
            )
        )

    db.flush()


def list_api_endpoints(
    db: Session, user: User, scan_id: uuid.UUID
) -> list[ApiEndpointRow]:
    """API endpoints for a scan the user owns.

    Ownership goes through `scan_service.get_scan`, so another user's scan id
    raises the same 404 as one that does not exist.
    """
    scan = scan_service.get_scan(db, user, scan_id)
    return list(
        db.scalars(
            select(ApiEndpointRow)
            .where(ApiEndpointRow.scan_id == scan.id)
            .options(selectinload(ApiEndpointRow.parameters))
            .order_by(ApiEndpointRow.path, ApiEndpointRow.method)
        )
    )


def list_api_documents(db: Session, user: User, scan_id: uuid.UUID) -> list[ApiDocument]:
    scan = scan_service.get_scan(db, user, scan_id)
    return list(
        db.scalars(
            select(ApiDocument)
            .where(ApiDocument.scan_id == scan.id)
            .order_by(ApiDocument.url)
        )
    )


def summarize(scan: Scan) -> dict[str, object]:
    """Counters for the API attack-surface header. Safe to display."""
    return {
        "detected": bool(scan.api_detected),
        "endpoints_discovered": scan.api_endpoints_discovered,
        "endpoints_observed": scan.api_endpoints_observed,
        "endpoints_documented_only": scan.api_endpoints_documented_only,
        "parameters_discovered": scan.api_parameters_discovered,
        "documents": scan.api_document_count,
        "authenticated_endpoints": scan.api_authenticated_endpoints,
        "unknown_auth_endpoints": scan.api_unknown_auth_endpoints,
        "graphql_detected": bool(scan.api_graphql_detected),
        "graphql_path": scan.api_graphql_path,
        "truncated": bool(scan.api_truncated),
    }
