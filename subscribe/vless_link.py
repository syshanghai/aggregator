# -*- coding: utf-8 -*-

"""Local VLESS share-link parser.

SubConverter v0.9.0 (the version this deployment vendors) has no VLESS
support at all: its link parser, Clash parser and proxy model never mention
the protocol, so every vless:// link is silently dropped and a VLESS-only
source yields zero nodes. This module parses vless:// URIs directly into the
Clash proxy dicts this project already uses (field contract in
subscribe/outbound/vless.py), so crawled VLESS nodes flow through the normal
verify -> alive-check -> output pipeline. Dicts returned here are validated
by the project's own VlessVerifier downstream (airport.parse / decode).
"""

from __future__ import annotations

import urllib.parse

import utils

VLESS_NETWORKS = ("tcp", "ws", "grpc", "http", "h2", "xhttp")


def _query_params(query: str) -> dict[str, str]:
    params: dict[str, str] = {}
    for key, values in urllib.parse.parse_qs(query, keep_blank_values=True).items():
        if values:
            params[key.lower()] = values[0]
    return params


def parse_vless_uri(uri: str) -> dict[str, object] | None:
    """Parse one vless:// share link into a Clash proxy dict, or None.

    Returns None when the link cannot be represented faithfully as a Clash
    proxy (bad uuid, unsupported network/security, missing REALITY public
    key, non-"none" TCP header obfuscation, ...). Callers drop such links.
    """
    if not uri or not isinstance(uri, str):
        return None
    uri = utils.trim(uri)
    if not uri.lower().startswith("vless://"):
        return None

    try:
        parsed = urllib.parse.urlparse(uri)
        port = parsed.port
    except Exception:
        return None

    uuid = urllib.parse.unquote(parsed.username or "")
    if not utils.verify_uuid(uuid):
        return None
    server = utils.trim(parsed.hostname or "")
    if not server or not port or not 0 < port <= 65535:
        return None

    params = _query_params(parsed.query)
    name = urllib.parse.unquote(parsed.fragment or "") or f"vless-{server}:{port}"

    network = (params.get("type") or "tcp").lower()
    if network not in VLESS_NETWORKS:
        return None
    security = (params.get("security") or "none").lower()
    if security not in ("none", "tls", "reality"):
        return None
    # TCP header obfuscation (headerType=http) has no Clash equivalent.
    if network == "tcp" and (params.get("headertype") or "none").lower() != "none":
        return None

    proxy: dict[str, object] = {
        "name": name,
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": uuid,
        "network": network,
    }

    encryption = utils.trim(params.get("encryption", ""))
    if encryption:
        proxy["encryption"] = encryption

    flow = utils.trim(params.get("flow", ""))
    if flow:
        proxy["flow"] = flow

    if security in ("tls", "reality"):
        proxy["tls"] = True
        servername = utils.trim(params.get("sni") or params.get("servername", ""))
        if servername:
            proxy["servername"] = servername
        fingerprint = utils.trim(params.get("fp", ""))
        if fingerprint:
            proxy["fingerprint"] = fingerprint
        alpn = utils.trim(params.get("alpn", ""))
        if alpn:
            proxy["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
        if params.get("allowinsecure", "").lower() in ("1", "true"):
            proxy["skip-cert-verify"] = True

    if security == "reality":
        public_key = utils.trim(params.get("pbk", ""))
        if not public_key:
            return None
        reality_opts: dict[str, object] = {"public-key": public_key}
        short_id = utils.trim(params.get("sid", ""))
        if short_id:
            reality_opts["short-id"] = short_id
        proxy["reality-opts"] = reality_opts

    if network == "ws":
        ws_opts: dict[str, object] = {}
        path = params.get("path")
        if path is not None:
            ws_opts["path"] = urllib.parse.unquote(path)
        host = utils.trim(params.get("host", ""))
        if host:
            ws_opts["headers"] = {"Host": host}
        if ws_opts:
            proxy["ws-opts"] = ws_opts
    elif network == "grpc":
        service_name = utils.trim(params.get("servicename", ""))
        if service_name:
            proxy["grpc-opts"] = {"grpc-service-name": service_name}
    elif network == "h2":
        host = utils.trim(params.get("host", ""))
        if host:
            proxy["h2-opts"] = {"host": [host]}
    elif network == "http":
        http_opts: dict[str, object] = {}
        path = params.get("path")
        if path is not None:
            http_opts["path"] = [urllib.parse.unquote(path)]
        host = utils.trim(params.get("host", ""))
        if host:
            http_opts["headers"] = {"Host": [host]}
        if http_opts:
            proxy["http-opts"] = http_opts
    elif network == "xhttp":
        xhttp_opts: dict[str, object] = {}
        path = params.get("path")
        if path is not None:
            xhttp_opts["path"] = urllib.parse.unquote(path)
        host = utils.trim(params.get("host", ""))
        if host:
            xhttp_opts["host"] = host
        if xhttp_opts:
            proxy["xhttp-opts"] = xhttp_opts

    return proxy
