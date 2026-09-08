"""Persistence and retrieval of discovered attack surface.

The only place a `CrawlResult` becomes database rows. The crawler itself holds
no session and imports no model.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models.attack_surface import Endpoint, EndpointParameter, Form, FormField
from app.models.scan import Scan
from app.models.user import User
from app.scanner.crawler.types import CrawlResult, ParameterLocation
from app.services import scan_service


def replace_attack_surface(db: Session, scan: Scan, crawl: CrawlResult | None) -> None:
    """Store `crawl` as the complete attack surface for `scan`.

    Existing rows are cleared first so a re-run cannot leave stale endpoints
    behind. A `None` crawl (crawler disabled, or the probe never connected)
    leaves the summary columns NULL rather than writing zeroes, so "did not
    crawl" stays distinguishable from "crawled and found nothing".
    """
    scan.endpoints.clear()
    scan.forms.clear()
    db.flush()

    if crawl is None:
        return

    scan.pages_crawled = crawl.pages_crawled
    scan.pages_skipped = crawl.pages_skipped
    scan.max_depth_reached = crawl.max_depth_reached
    scan.crawl_limit_reached = crawl.limit_reached

    for discovered in crawl.endpoints:
        endpoint = Endpoint(
            scan_id=scan.id,
            url=discovered.url,
            path=discovered.path,
            method=discovered.method,
            status_code=discovered.status_code,
            content_type=discovered.content_type,
            depth=discovered.depth,
            page_title=discovered.page_title,
        )
        endpoint.parameters = [
            # Names only. The crawler never hands over a parameter value.
            EndpointParameter(name=name, location=ParameterLocation.QUERY)
            for name in discovered.parameters
        ]
        db.add(endpoint)

    for discovered_form in crawl.forms:
        form = Form(
            scan_id=scan.id,
            page_url=discovered_form.page_url,
            action=discovered_form.action,
            method=discovered_form.method,
        )
        form.fields = [
            FormField(name=field.name, kind=field.kind, input_type=field.input_type)
            for field in discovered_form.fields
        ]
        db.add(form)


def list_endpoints(db: Session, user: User, scan_id: uuid.UUID) -> list[Endpoint]:
    """Endpoints for a scan the user owns, shallowest first.

    Ownership goes through `scan_service.get_scan`, so another user's scan id
    raises the same 404 as one that does not exist.
    """
    scan = scan_service.get_scan(db, user, scan_id)
    return list(
        db.scalars(
            select(Endpoint)
            .where(Endpoint.scan_id == scan.id)
            .options(selectinload(Endpoint.parameters))
            .order_by(Endpoint.depth, Endpoint.path, Endpoint.url)
        )
    )


def list_forms(db: Session, user: User, scan_id: uuid.UUID) -> list[Form]:
    """Forms for a scan the user owns."""
    scan = scan_service.get_scan(db, user, scan_id)
    return list(
        db.scalars(
            select(Form)
            .where(Form.scan_id == scan.id)
            .options(selectinload(Form.fields))
            .order_by(Form.method, Form.action)
        )
    )


def summarize(db: Session, scan: Scan) -> dict[str, int | bool | None]:
    """Counters for the attack-surface header, computed in three small queries."""
    endpoint_count = (
        db.scalar(select(func.count()).select_from(Endpoint).where(Endpoint.scan_id == scan.id))
        or 0
    )
    form_count = (
        db.scalar(select(func.count()).select_from(Form).where(Form.scan_id == scan.id)) or 0
    )
    # Distinct names: the same parameter seen on five endpoints is one input.
    parameter_count = (
        db.scalar(
            select(func.count(func.distinct(EndpointParameter.name)))
            .select_from(EndpointParameter)
            .join(Endpoint, Endpoint.id == EndpointParameter.endpoint_id)
            .where(Endpoint.scan_id == scan.id)
        )
        or 0
    )

    return {
        "endpoints": endpoint_count,
        "forms": form_count,
        "parameters": parameter_count,
        "pages_crawled": scan.pages_crawled,
        "pages_skipped": scan.pages_skipped,
        "max_depth_reached": scan.max_depth_reached,
        "crawl_limit_reached": scan.crawl_limit_reached,
    }
