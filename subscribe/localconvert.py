# -*- coding: utf-8 -*-

"""Build final subscription files directly from checked Clash proxy dicts.

SubConverter v0.9.0 has no VLESS support: it drops vless proxies not only
when parsing links, but also when converting a Clash config (explodeClash
has no vless branch). The final stage therefore cannot route through
SubConverter at all once a group contains VLESS nodes. This module builds
all three targets locally from the already-verified, already-alive-checked
proxy dicts:

- clash   -> full Clash config (proxies + url-test/select groups + MATCH
             rule) via clash.filter_proxies, which the alive check uses too.
- singbox -> sing-box JSON {"version": 3, "outbounds": [...]}.
- v2ray   -> share links (one per line); the caller base64-encodes them,
             as it did for SubConverter's v2ray output.

Only vless/vmess/shadowsocks/trojan are converted for singbox/v2ray; other
protocols still appear in the Clash output. A proxy that cannot be
represented in a target is skipped for that target (and logged), never
silently mangled.
"""

from __future__ import annotations

import base64
import json
import urllib.parse

import utils
import yaml
from logger import logger

import clash


# --------------------------------------------------------------------------
# Clash
# --------------------------------------------------------------------------


def build_clash_config(final_config: dict[str, object]) -> str:
    yaml.add_representer(clash.QuotedStr, clash.quoted_scalar)
    return yaml.dump(final_config, allow_unicode=True)


# --------------------------------------------------------------------------
# sing-box
# --------------------------------------------------------------------------


def _singbox_transport(proxy: dict[str, object]) -> dict[str, object] | None:
    network = utils.trim(str(proxy.get("network", "tcp") or "tcp")).lower()
    if network in ("", "tcp"):
        return None
    if network == "ws":
        ws_opts = proxy.get("ws-opts") or {}
        transport: dict[str, object] = {"type": "ws"}
        path = ws_opts.get("path")
        if path:
            transport["path"] = path
        headers = ws_opts.get("headers") or {}
        if isinstance(headers, dict) and headers:
            transport["headers"] = dict(headers)
        return transport
    if network == "grpc":
        grpc_opts = proxy.get("grpc-opts") or {}
        transport = {"type": "grpc"}
        service_name = grpc_opts.get("grpc-service-name")
        if service_name:
            transport["service_name"] = service_name
        return transport
    if network == "http":
        http_opts = proxy.get("http-opts") or {}
        transport = {"type": "http"}
        host = http_opts.get("host")
        if host:
            transport["host"] = host
        path = http_opts.get("path")
        if isinstance(path, list) and path:
            transport["path"] = path[0]
        elif isinstance(path, str) and path:
            transport["path"] = path
        return transport
    if network == "h2":
        h2_opts = proxy.get("h2-opts") or {}
        transport = {"type": "http"}
        host = h2_opts.get("host")
        if host:
            transport["host"] = host
        return transport
    if network == "xhttp":
        xhttp_opts = proxy.get("xhttp-opts") or {}
        transport = {"type": "httpupgrade"}
        host = xhttp_opts.get("host")
        if host:
            transport["host"] = host
        path = xhttp_opts.get("path")
        if path:
            transport["path"] = path
        return transport
    return None


def _singbox_tls(proxy: dict[str, object], reality: bool = False) -> dict[str, object] | None:
    if not proxy.get("tls"):
        return None
    tls: dict[str, object] = {"enabled": True}
    servername = utils.trim(str(proxy.get("servername") or proxy.get("sni") or ""))
    if servername:
        tls["server_name"] = servername
    if proxy.get("skip-cert-verify"):
        tls["insecure"] = True
    alpn = proxy.get("alpn")
    if isinstance(alpn, list) and alpn:
        tls["alpn"] = list(alpn)
    fingerprint = utils.trim(str(proxy.get("fingerprint") or ""))
    if fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    if reality:
        reality_opts = proxy.get("reality-opts") or {}
        public_key = utils.trim(str(reality_opts.get("public-key") or ""))
        if not public_key:
            return None
        reality_block: dict[str, object] = {"enabled": True, "public_key": public_key}
        short_id = utils.trim(str(reality_opts.get("short-id") or ""))
        if short_id:
            reality_block["short_id"] = short_id
        tls["reality"] = reality_block
    return tls


def clash_proxy_to_singbox(proxy: dict[str, object]) -> dict[str, object] | None:
    """Convert one Clash proxy dict to a sing-box outbound, or None."""
    ptype = utils.trim(str(proxy.get("type", "") or "")).lower()
    name = utils.trim(str(proxy.get("name", "") or ""))
    server = utils.trim(str(proxy.get("server", "") or ""))
    try:
        port = int(proxy.get("port", 0))
    except Exception:
        return None
    if not name or not server or not 0 < port <= 65535:
        return None

    outbound: dict[str, object] = {"tag": name, "server": server, "server_port": port}
    transport = _singbox_transport(proxy)

    if ptype == "vless":
        uuid = utils.trim(str(proxy.get("uuid", "") or ""))
        if not utils.verify_uuid(uuid):
            return None
        # sing-box cannot express VLESS ML-KEM encryption; skip such nodes
        # here (they still ship in the Clash file and the v2ray links).
        encryption = utils.trim(str(proxy.get("encryption", "") or ""))
        if encryption and encryption != "none":
            logger.debug(f"skip singbox for mlkem vless proxy: {name}")
            return None
        outbound["type"] = "vless"
        outbound["uuid"] = uuid
        flow = utils.trim(str(proxy.get("flow", "") or ""))
        if flow:
            outbound["flow"] = flow
        tls = _singbox_tls(proxy, reality=bool(proxy.get("reality-opts")))
        if tls is None and proxy.get("reality-opts"):
            return None
        if tls:
            outbound["tls"] = tls
        if transport:
            outbound["transport"] = transport
        return outbound

    if ptype == "vmess":
        uuid = utils.trim(str(proxy.get("uuid", "") or ""))
        if not utils.verify_uuid(uuid):
            return None
        outbound["type"] = "vmess"
        outbound["uuid"] = uuid
        outbound["security"] = utils.trim(str(proxy.get("cipher", "") or "")) or "auto"
        alter_id = proxy.get("alterId", 0)
        try:
            outbound["alter_id"] = int(alter_id)
        except Exception:
            outbound["alter_id"] = 0
        tls = _singbox_tls(proxy)
        if tls:
            outbound["tls"] = tls
        if transport:
            outbound["transport"] = transport
        return outbound

    if ptype in ("ss", "shadowsocks"):
        method = utils.trim(str(proxy.get("cipher", "") or ""))
        password = proxy.get("password", "")
        if not method or password is None:
            return None
        outbound["type"] = "shadowsocks"
        outbound["method"] = method
        outbound["password"] = str(password)
        plugin = utils.trim(str(proxy.get("plugin", "") or ""))
        if plugin:
            outbound["plugin"] = plugin
            plugin_opts = proxy.get("plugin-opts")
            if plugin_opts:
                outbound["plugin_opts"] = plugin_opts if isinstance(plugin_opts, str) else str(plugin_opts)
        return outbound

    if ptype == "trojan":
        password = proxy.get("password", "")
        if password is None or utils.trim(str(password)) == "":
            return None
        outbound["type"] = "trojan"
        outbound["password"] = str(password)
        tls = _singbox_tls(proxy)
        if tls:
            outbound["tls"] = tls
        elif proxy.get("tls"):
            return None
        if transport:
            outbound["transport"] = transport
        return outbound

    logger.debug(f"no singbox conversion for protocol: {ptype}, proxy: {name}")
    return None


def build_singbox(proxies: list[dict[str, object]]) -> str | None:
    outbounds: list[dict[str, object]] = []
    for proxy in proxies:
        outbound = clash_proxy_to_singbox(proxy)
        if outbound is not None:
            outbounds.append(outbound)
    if not outbounds:
        return None
    return json.dumps({"version": 3, "outbounds": outbounds}, ensure_ascii=False, indent=2)


# --------------------------------------------------------------------------
# v2ray share links
# --------------------------------------------------------------------------


def _quote(text: str) -> str:
    return urllib.parse.quote(text, safe="")


def _vless_link(proxy: dict[str, object]) -> str | None:
    uuid = utils.trim(str(proxy.get("uuid", "") or ""))
    server = utils.trim(str(proxy.get("server", "") or ""))
    try:
        port = int(proxy.get("port", 0))
    except Exception:
        return None
    if not utils.verify_uuid(uuid) or not server or not 0 < port <= 65535:
        return None

    params: list[tuple[str, str]] = []
    encryption = utils.trim(str(proxy.get("encryption", "") or ""))
    if encryption:
        params.append(("encryption", encryption))
    flow = utils.trim(str(proxy.get("flow", "") or ""))
    if flow:
        params.append(("flow", flow))
    if proxy.get("tls"):
        if proxy.get("reality-opts"):
            params.append(("security", "reality"))
        else:
            params.append(("security", "tls"))
    else:
        params.append(("security", "none"))
    servername = utils.trim(str(proxy.get("servername") or proxy.get("sni") or ""))
    if servername:
        params.append(("sni", servername))
    fingerprint = utils.trim(str(proxy.get("fingerprint") or ""))
    if fingerprint:
        params.append(("fp", fingerprint))
    alpn = proxy.get("alpn")
    if isinstance(alpn, list) and alpn:
        params.append(("alpn", ",".join(alpn)))
    if proxy.get("skip-cert-verify"):
        params.append(("allowInsecure", "1"))
    reality_opts = proxy.get("reality-opts") or {}
    if isinstance(reality_opts, dict):
        public_key = utils.trim(str(reality_opts.get("public-key") or ""))
        if public_key:
            params.append(("pbk", public_key))
        short_id = utils.trim(str(reality_opts.get("short-id") or ""))
        if short_id:
            params.append(("sid", short_id))
    network = utils.trim(str(proxy.get("network", "tcp") or "tcp")).lower()
    params.append(("type", network))
    if network == "ws":
        ws_opts = proxy.get("ws-opts") or {}
        if isinstance(ws_opts, dict):
            path = ws_opts.get("path")
            if path:
                params.append(("path", str(path)))
            headers = ws_opts.get("headers") or {}
            if isinstance(headers, dict) and headers.get("Host"):
                params.append(("host", str(headers["Host"])))
    elif network == "grpc":
        grpc_opts = proxy.get("grpc-opts") or {}
        if isinstance(grpc_opts, dict) and grpc_opts.get("grpc-service-name"):
            params.append(("serviceName", str(grpc_opts["grpc-service-name"])))
    elif network == "http":
        http_opts = proxy.get("http-opts") or {}
        if isinstance(http_opts, dict):
            path = http_opts.get("path")
            if isinstance(path, list) and path:
                params.append(("path", str(path[0])))
            headers = http_opts.get("headers") or {}
            if isinstance(headers, dict) and headers.get("Host"):
                host = headers["Host"]
                params.append(("host", str(host[0] if isinstance(host, list) and host else host)))
    elif network == "h2":
        h2_opts = proxy.get("h2-opts") or {}
        if isinstance(h2_opts, dict):
            host = h2_opts.get("host")
            if isinstance(host, list) and host:
                params.append(("host", str(host[0])))
    elif network == "xhttp":
        xhttp_opts = proxy.get("xhttp-opts") or {}
        if isinstance(xhttp_opts, dict):
            if xhttp_opts.get("path"):
                params.append(("path", str(xhttp_opts["path"])))
            if xhttp_opts.get("host"):
                params.append(("host", str(xhttp_opts["host"])))

    query = "&".join(f"{k}={_quote(v)}" for k, v in params)
    name = utils.trim(str(proxy.get("name", "") or ""))
    return f"vless://{uuid}@{server}:{port}?{query}#{_quote(name)}"


def _vmess_link(proxy: dict[str, object]) -> str | None:
    uuid = utils.trim(str(proxy.get("uuid", "") or ""))
    server = utils.trim(str(proxy.get("server", "") or ""))
    try:
        port = int(proxy.get("port", 0))
    except Exception:
        return None
    if not utils.verify_uuid(uuid) or not server or not 0 < port <= 65535:
        return None
    network = utils.trim(str(proxy.get("network", "tcp") or "tcp")).lower()
    config: dict[str, object] = {
        "v": "2",
        "ps": utils.trim(str(proxy.get("name", "") or "")),
        "add": server,
        "port": str(port),
        "id": uuid,
        "aid": str(proxy.get("alterId", 0)),
        "scy": utils.trim(str(proxy.get("cipher", "") or "")) or "auto",
        "net": network,
        "type": "none",
        "host": "",
        "path": "",
        "tls": "tls" if proxy.get("tls") else "",
    }
    if proxy.get("servername") or proxy.get("sni"):
        config["sni"] = utils.trim(str(proxy.get("servername") or proxy.get("sni") or ""))
    if network == "ws":
        ws_opts = proxy.get("ws-opts") or {}
        if isinstance(ws_opts, dict):
            if ws_opts.get("path"):
                config["path"] = str(ws_opts["path"])
            headers = ws_opts.get("headers") or {}
            if isinstance(headers, dict) and headers.get("Host"):
                config["host"] = str(headers["Host"])
    elif network == "grpc":
        grpc_opts = proxy.get("grpc-opts") or {}
        if isinstance(grpc_opts, dict) and grpc_opts.get("grpc-service-name"):
            config["path"] = str(grpc_opts["grpc-service-name"])
    payload = json.dumps(config, ensure_ascii=False, separators=(",", ":"))
    return "vmess://" + base64.b64encode(payload.encode("utf-8")).decode("utf-8")


def _ss_link(proxy: dict[str, object]) -> str | None:
    method = utils.trim(str(proxy.get("cipher", "") or ""))
    password = proxy.get("password", "")
    server = utils.trim(str(proxy.get("server", "") or ""))
    try:
        port = int(proxy.get("port", 0))
    except Exception:
        return None
    if not method or password is None or not server or not 0 < port <= 65535:
        return None
    raw = f"{method}:{password}@{server}:{port}"
    name = utils.trim(str(proxy.get("name", "") or ""))
    return "ss://" + base64.b64encode(raw.encode("utf-8")).decode("utf-8") + "#" + _quote(name)


def _trojan_link(proxy: dict[str, object]) -> str | None:
    password = proxy.get("password", "")
    server = utils.trim(str(proxy.get("server", "") or ""))
    try:
        port = int(proxy.get("port", 0))
    except Exception:
        return None
    if password is None or utils.trim(str(password)) == "" or not server or not 0 < port <= 65535:
        return None
    params: list[tuple[str, str]] = []
    servername = utils.trim(str(proxy.get("servername") or proxy.get("sni") or ""))
    if servername:
        params.append(("sni", servername))
    if proxy.get("skip-cert-verify"):
        params.append(("allowInsecure", "1"))
    query = "&".join(f"{k}={_quote(v)}" for k, v in params)
    name = utils.trim(str(proxy.get("name", "") or ""))
    link = f"trojan://{_quote(str(password))}@{server}:{port}"
    if query:
        link += "?" + query
    return link + "#" + _quote(name)


def clash_proxy_to_link(proxy: dict[str, object]) -> str | None:
    ptype = utils.trim(str(proxy.get("type", "") or "")).lower()
    if ptype == "vless":
        return _vless_link(proxy)
    if ptype == "vmess":
        return _vmess_link(proxy)
    if ptype in ("ss", "shadowsocks"):
        return _ss_link(proxy)
    if ptype == "trojan":
        return _trojan_link(proxy)
    logger.debug(f"no share-link conversion for protocol: {ptype}")
    return None


def build_v2ray(proxies: list[dict[str, object]]) -> str | None:
    links: list[str] = []
    for proxy in proxies:
        link = clash_proxy_to_link(proxy)
        if link:
            links.append(link)
    if not links:
        return None
    return "\n".join(links)


# --------------------------------------------------------------------------
# Dispatcher
# --------------------------------------------------------------------------


def build_target_content(
    target: str, final_config: dict[str, object], final_proxies: list[dict[str, object]]
) -> str | None:
    """Build one target's file content from the final proxy list."""
    target = utils.trim(target).lower()
    if target == "clash":
        return build_clash_config(final_config)
    if target == "singbox":
        return build_singbox(final_proxies)
    if target in ("v2ray", "mixed"):
        return build_v2ray(final_proxies)
    if "ss" in target:
        return build_v2ray(final_proxies)
    logger.error(f"unsupported convert target: {target}")
    return None
