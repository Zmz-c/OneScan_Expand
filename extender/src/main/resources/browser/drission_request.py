import argparse
import base64
import json
import os
import re
import socket
import sys
import time
import traceback
from urllib.parse import parse_qsl, urlparse

from DrissionPage import Chromium, ChromiumOptions

GET_INITIAL_LOAD_MAX_SECONDS = 0.6
GET_RELOAD_READY_MAX_SECONDS = 0.9
GET_FINAL_RENDER_MAX_SECONDS = 1.1
GET_RENDER_SETTLE_SECONDS = 0.18
GET_POLL_INTERVAL_SECONDS = 0.08
POST_CHALLENGE_WAIT_SECONDS = 1.2
POST_PROVISIONAL_WAIT_SECONDS = 1.4
EMPTY_BODY_SETTLE_SECONDS = 0.22
EMPTY_BODY_HIDDEN_FORM_STABLE_SECONDS = 0.35
POST_RETRY_ATTEMPTS = 1
POST_CHALLENGE_BODY_LIMIT = 220000
BLANK_LIKE_URL_PREFIXES = (
    "about:blank",
    "data:",
    "chrome-error://",
    "edge-error://",
)
BLOCKED_RESOURCE_PATTERNS = [
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.webp",
    "*.svg",
    "*.ico",
    "*.bmp",
    "*.woff",
    "*.woff2",
    "*.ttf",
    "*.otf",
    "*.eot",
    "*.mp3",
    "*.mp4",
    "*.avi",
    "*.mov",
    "*.webm",
    "*.m4a",
]


def load_state(state_file):
    if not state_file or not os.path.isfile(state_file):
        return {}
    try:
        with open(state_file, "r", encoding="utf-8") as file:
            data = {}
            for raw_line in file:
                line = raw_line.strip()
                if not line or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                data[key] = value
            return data
    except Exception:
        return {}


def save_state(state_file, port):
    if not state_file:
        return
    os.makedirs(os.path.dirname(state_file), exist_ok=True)
    with open(state_file, "w", encoding="utf-8") as file:
        file.write(f"PORT={port}\n")


def clear_state(state_file):
    if state_file and os.path.isfile(state_file):
        try:
            os.remove(state_file)
        except Exception:
            pass


def read_request_file(request_file):
    data = {}
    with open(request_file, "r", encoding="utf-8") as file:
        for raw_line in file:
            line = raw_line.rstrip("\r\n")
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            data[key] = value

    header_count = int(data.get("HEADER_COUNT", "0") or "0")
    headers = []
    for index in range(header_count):
        encoded = data.get(f"HEADER_{index}", "")
        headers.append(base64.b64decode(encoded).decode("utf-8", errors="replace"))

    return {
        "method": base64.b64decode(data.get("METHOD", "")).decode("utf-8", errors="replace").upper(),
        "url": base64.b64decode(data.get("URL", "")).decode("utf-8", errors="replace"),
        "headers": headers,
        "body": base64.b64decode(data.get("BODY", "") or ""),
    }


def print_response(result):
    headers = result.get("headers") or {}
    if isinstance(headers, dict):
        header_lines = [f"{key}: {value}" for key, value in headers.items()]
    else:
        header_lines = list(headers)

    body = result.get("body") or b""
    if isinstance(body, str):
        body = body.encode("utf-8", errors="replace")

    print(f"STATUS={int(result.get('status', 0))}")
    print(f"REASON={b64_text(result.get('reason', ''))}")
    print(f"FINAL_URL={b64_text(result.get('final_url', ''))}")
    print(f"TITLE={b64_text(result.get('title', ''))}")
    print(f"HEADER_COUNT={len(header_lines)}")
    for index, header_line in enumerate(header_lines):
        print(f"HEADER_{index}={b64_text(header_line)}")
    print(f"BODY={base64.b64encode(body).decode('ascii')}")


def b64_text(value):
    return base64.b64encode((value or "").encode("utf-8", errors="replace")).decode("ascii")


def find_free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def is_port_open(port):
    if not port:
        return False
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.25)
    try:
        return sock.connect_ex(("127.0.0.1", int(port))) == 0
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


def candidate_existing_ports(args):
    result = []
    state = load_state(args.state_file)
    saved_port = state.get("PORT")
    if saved_port and saved_port.isdigit() and is_port_open(saved_port):
        result.append(int(saved_port))
    if is_port_open(args.port) and args.port not in result:
        result.append(args.port)
    return result


def next_launch_port(args):
    if args.port and not is_port_open(args.port):
        return args.port
    return find_free_port()


def resolve_mac_app_bundle(path):
    if not path:
        return ""
    if os.path.isfile(path):
        return path
    normalized = os.path.abspath(os.path.expanduser(path))
    if normalized.lower().endswith(".app"):
        app_name = os.path.splitext(os.path.basename(normalized))[0]
        macos_binary = os.path.join(normalized, "Contents", "MacOS", app_name)
        if os.path.isfile(macos_binary):
            return macos_binary
        if os.path.isdir(os.path.join(normalized, "Contents", "MacOS")):
            for item in os.listdir(os.path.join(normalized, "Contents", "MacOS")):
                candidate = os.path.join(normalized, "Contents", "MacOS", item)
                if os.path.isfile(candidate):
                    return candidate
    if os.path.isdir(normalized):
        for relative in (
            ("Contents", "MacOS"),
            ("MacOS",),
        ):
            current = os.path.join(normalized, *relative)
            if os.path.isdir(current):
                for item in os.listdir(current):
                    candidate = os.path.join(current, item)
                    if os.path.isfile(candidate):
                        return candidate
    return ""


def resolve_browser_path(path):
    normalized = os.path.abspath(os.path.expanduser(path or ""))
    if os.path.isfile(normalized):
        return normalized
    resolved_app = resolve_mac_app_bundle(normalized)
    if resolved_app:
        return resolved_app
    return ""


def find_browser_path(browser_type, explicit_path=""):
    browser_type = (browser_type or "edge").lower()
    if explicit_path:
        resolved = resolve_browser_path(explicit_path)
        if resolved:
            return resolved
        raise RuntimeError(f"Browser executable not found: {os.path.abspath(os.path.expanduser(explicit_path))}")

    if browser_type == "chrome":
        candidates = [
            os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(os.environ.get("PROGRAMFILES", ""), "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "Application", "chrome.exe"),
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            "/usr/bin/google-chrome",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/opt/google/chrome/chrome",
        ]
    else:
        candidates = [
            os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join(os.environ.get("PROGRAMFILES", ""), "Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Edge", "Application", "msedge.exe"),
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Microsoft Edge Canary.app/Contents/MacOS/Microsoft Edge Canary",
            "/usr/bin/microsoft-edge",
            "/usr/bin/microsoft-edge-stable",
        ]

    for candidate in candidates:
        resolved = resolve_browser_path(candidate)
        if resolved:
            return resolved
    raise RuntimeError(f"{browser_type} browser executable not found")


def build_options(args, port, existing_only=False):
    options = ChromiumOptions()
    options.set_local_port(port)
    options.set_user_data_path(args.user_data_path)
    options.set_load_mode("eager")
    options.ignore_certificate_errors()
    options.set_argument("--allow-insecure-localhost")
    options.set_argument("--disable-background-networking")
    options.set_argument("--disable-component-update")
    options.set_argument("--disable-domain-reliability")
    options.set_argument("--disable-sync")
    options.set_argument("--no-first-run")
    options.set_argument("--no-default-browser-check")
    options.set_argument("--disable-default-apps")
    options.set_argument("--disable-breakpad")
    if not args.load_static_resources:
        options.set_argument("--blink-settings=imagesEnabled=false")
    options.set_argument("--disable-features=AutofillServerCommunication,CertificateTransparencyComponentUpdater,OptimizationHints,MediaRouter")
    options.set_browser_path(find_browser_path(args.browser_type, args.browser_path))
    if existing_only:
        options.existing_only()

    timeout_seconds = max(float(args.timeout_ms) / 1000.0, 5.0)
    options.set_timeouts(base=timeout_seconds, page_load=timeout_seconds)
    return options


def to_tab(browser, tab_or_id):
    if tab_or_id is None:
        return None
    if isinstance(tab_or_id, str):
        try:
            return browser.get_tab(tab_or_id)
        except Exception:
            return None
    return tab_or_id


def iter_browser_tabs(browser):
    seen = set()

    def add_tab(tab_or_id):
        tab = to_tab(browser, tab_or_id)
        if tab is None:
            return
        tab_id = getattr(tab, "tab_id", None) or getattr(tab, "_tab_id", None) or id(tab)
        if tab_id in seen:
            return
        seen.add(tab_id)
        tabs.append(tab)

    tabs = []
    for attr_name in ("tabs", "tab_ids"):
        try:
            value = getattr(browser, attr_name, None)
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    add_tab(item)
        except Exception:
            pass

    try:
        get_tabs = getattr(browser, "get_tabs", None)
        if callable(get_tabs):
            for item in get_tabs():
                add_tab(item)
    except Exception:
        pass

    try:
        add_tab(browser.latest_tab)
    except Exception:
        pass
    return tabs


def resolve_request_tab(browser, request):
    target_origin = origin_url(request["url"])
    referer = header_value(request, "Referer")
    tabs = iter_browser_tabs(browser)
    if is_http_url(referer):
        for tab in tabs:
            tab_url = getattr(tab, "url", "") or ""
            if tab_url == referer or tab_url.startswith(referer):
                return tab
    for tab in tabs:
        if current_origin(tab) == target_origin:
            return tab
    if tabs:
        return tabs[0]
    return to_tab(browser, getattr(browser, "latest_tab", None))


def resolve_live_tab(tab):
    if tab is None:
        return None
    browser = getattr(tab, "browser", None) or getattr(tab, "_browser", None)
    tab_id = getattr(tab, "tab_id", None) or getattr(tab, "_tab_id", None)
    if browser is not None and tab_id:
        try:
            resolved = browser.get_tab(tab_id)
            if resolved is not None:
                return resolved
        except Exception:
            pass
    if browser is not None:
        try:
            latest = to_tab(browser, getattr(browser, "latest_tab", None))
            if latest is not None:
                return latest
        except Exception:
            pass
    return tab


def safe_tab_url(tab):
    current_tab = resolve_live_tab(tab)
    try:
        return getattr(current_tab, "url", "") or ""
    except Exception:
        return ""


def restore_page_hooks(tab):
    current_tab = resolve_live_tab(tab)
    if current_tab is None:
        return
    script = """
(() => {
    try {
        if (window.__passrsOriginalFetch) {
            window.fetch = window.__passrsOriginalFetch;
        }
        if (window.__passrsOriginalXhrOpen) {
            XMLHttpRequest.prototype.open = window.__passrsOriginalXhrOpen;
        }
        if (window.__passrsOriginalXhrSend) {
            XMLHttpRequest.prototype.send = window.__passrsOriginalXhrSend;
        }
        if (window.__passrsOriginalFormSubmit) {
            HTMLFormElement.prototype.submit = window.__passrsOriginalFormSubmit;
        }
        if (window.__passrsUnloadHandler) {
            window.removeEventListener('beforeunload', window.__passrsUnloadHandler, true);
            window.removeEventListener('pagehide', window.__passrsUnloadHandler, true);
        }
        if (typeof window.name === 'string' && window.name.startsWith('__PASSRS__:')) {
            const separator = window.name.indexOf('\n');
            window.name = separator >= 0 ? window.name.slice(separator + 1) : '';
        }
        delete window.__passrsOriginalFetch;
        delete window.__passrsOriginalXhrOpen;
        delete window.__passrsOriginalXhrSend;
        delete window.__passrsOriginalFormSubmit;
        delete window.__passrsUnloadHandler;
        delete window.__passrsLastResponse;
        delete window.__passrsLastResponseAt;
        delete window.__passrsHooked;
        return true;
    } catch (e) {
        return false;
    }
})();
"""
    try:
        current_tab.run_js(script)
    except Exception:
        pass


def restore_browser_hooks(browser):
    for tab in iter_browser_tabs(browser):
        restore_page_hooks(tab)


def configure_tab_network(tab, allow_static_resources):
    current_tab = resolve_live_tab(tab)
    if current_tab is None:
        return
    try:
        current_tab.run_cdp("Network.enable")
    except Exception:
        pass
    if not allow_static_resources:
        try:
            current_tab.run_cdp("Network.setBlockedURLs", urls=BLOCKED_RESOURCE_PATTERNS)
        except Exception:
            pass


def parse_headers(header_lines):
    result = []
    for line in header_lines:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        result.append((name.strip(), value.strip()))
    return result


def header_value(request, name):
    expected = (name or "").lower()
    for header_name, header_value_text in parse_headers(request["headers"]):
        if header_name.lower() == expected:
            return header_value_text
    return ""


def request_content_type(request):
    return header_value(request, "Content-Type").lower()


def request_accepts_html(request):
    accept = header_value(request, "Accept").lower()
    return "text/html" in accept or "application/xhtml+xml" in accept


def is_navigation_get(request):
    fetch_mode = header_value(request, "Sec-Fetch-Mode").lower()
    fetch_dest = header_value(request, "Sec-Fetch-Dest").lower()
    if fetch_mode == "navigate":
        return True
    if fetch_dest in ("document", "frame", "iframe"):
        return True
    if header_value(request, "Upgrade-Insecure-Requests") == "1":
        return True
    return request_accepts_html(request)


def is_navigation_post(request):
    fetch_mode = header_value(request, "Sec-Fetch-Mode").lower()
    fetch_dest = header_value(request, "Sec-Fetch-Dest").lower()
    if fetch_mode == "navigate":
        return True
    if fetch_dest in ("document", "frame", "iframe"):
        return True
    if header_value(request, "Upgrade-Insecure-Requests") == "1":
        return True
    return request_accepts_html(request)


def is_form_urlencoded_post(request):
    return request_content_type(request).startswith("application/x-www-form-urlencoded")


def is_multipart_form_post(request):
    return request_content_type(request).startswith("multipart/form-data")


def request_has_body(request):
    return bool(request.get("body"))


def is_empty_body_post(request):
    return request.get("method") == "POST" and not request_has_body(request)


def can_replay_urlencoded_as_form(request):
    if not is_form_urlencoded_post(request):
        return False
    body_text = decode_body_text(request.get("body") or b"")
    if not body_text:
        return True
    for segment in body_text.split("&"):
        if not segment:
            continue
        if "=" not in segment:
            return False
    return True


def is_http_url(value):
    parsed = urlparse(value or "")
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def preferred_context_url(request):
    referer = header_value(request, "Referer")
    if is_http_url(referer):
        return referer
    return origin_url(request["url"])


def set_request_cookies(tab, request):
    current_tab = resolve_live_tab(tab)
    if current_tab is None:
        return
    cookies = []
    for name, value in parse_headers(request["headers"]):
        if name.lower() != "cookie":
            continue
        for item in value.split(";"):
            cookie_line = item.strip()
            if not cookie_line or "=" not in cookie_line:
                continue
            cookie_name, cookie_value = cookie_line.split("=", 1)
            cookies.append((cookie_name.strip(), cookie_value.strip()))

    for cookie_name, cookie_value in cookies:
        try:
            current_tab.run_cdp("Network.setCookie", name=cookie_name, value=cookie_value, url=request["url"])
        except Exception:
            pass


def submit_form_post_request(tab, request):
    current_tab = resolve_live_tab(tab)
    if current_tab is None:
        raise RuntimeError("browser tab is unavailable")
    body_text = decode_body_text(request["body"])
    form_pairs = parse_qsl(body_text, keep_blank_values=True)
    if not form_pairs and body_text:
        raise RuntimeError("cannot parse x-www-form-urlencoded post body")

    script = """
(() => {
    const targetUrl = __URL__;
    const pairs = __PAIRS__;
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = targetUrl;
    form.style.display = 'none';
    for (const [name, value] of pairs) {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = name;
        input.value = value;
        form.appendChild(input);
    }
    document.body.appendChild(form);
    form.submit();
    return true;
})();
"""
    script = script.replace("__URL__", json.dumps(request["url"]))
    script = script.replace("__PAIRS__", json.dumps(form_pairs, ensure_ascii=False))
    current_tab.run_js(script)


def submit_empty_post_request(tab, request):
    current_tab = resolve_live_tab(tab)
    if current_tab is None:
        raise RuntimeError("browser tab is unavailable")
    script = """
(() => {
    const targetUrl = __URL__;
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = targetUrl;
    form.style.display = 'none';
    document.body.appendChild(form);
    form.submit();
    return true;
})();
"""
    script = script.replace("__URL__", json.dumps(request["url"]))
    current_tab.run_js(script)


def multipart_boundary(content_type):
    match = re.search(r'boundary="?([^";]+)"?', content_type or "", re.IGNORECASE)
    if not match:
        return ""
    return match.group(1).strip()


def parse_multipart_form_fields(request):
    boundary = multipart_boundary(request_content_type(request))
    if not boundary:
        return None
    marker = ("--" + boundary).encode("utf-8", errors="ignore")
    body = request.get("body") or b""
    if not body or marker not in body:
        return None

    parts = []
    for raw_part in body.split(marker):
        part = raw_part
        if not part:
            continue
        if part.startswith(b"\r\n"):
            part = part[2:]
        if part.endswith(b"\r\n"):
            part = part[:-2]
        if not part or part == b"--":
            continue
        if part.endswith(b"--"):
            part = part[:-2]
        if not part:
            continue
        if part.startswith(b"--"):
            break
        header_bytes, separator, value_bytes = part.partition(b"\r\n\r\n")
        if not separator:
            return None
        value_bytes = value_bytes.rstrip(b"\r\n")
        headers = {}
        for raw_line in header_bytes.split(b"\r\n"):
            line = raw_line.decode("utf-8", errors="replace")
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()

        disposition = headers.get("content-disposition", "")
        name_match = re.search(r'name="([^"]+)"', disposition, re.IGNORECASE)
        filename_match = re.search(r'filename="([^"]*)"', disposition, re.IGNORECASE)
        if not name_match:
            continue
        if filename_match and filename_match.group(1):
            return None
        parts.append({
            "name": name_match.group(1),
            "value": decode_body_text(value_bytes),
        })
    return parts


def can_submit_as_navigation_post(request):
    if is_empty_body_post(request):
        return True
    if is_form_urlencoded_post(request):
        return can_replay_urlencoded_as_form(request)
    if is_multipart_form_post(request):
        return parse_multipart_form_fields(request) is not None
    return False


def can_auto_submit_intermediate(request):
    if is_empty_body_post(request):
        return False
    return can_submit_as_navigation_post(request)


def can_auto_submit_challenge_intermediate(request):
    return request.get("method") == "POST" and is_navigation_post(request)


def is_navigation_non_form_post(request):
    return is_navigation_post(request) and not can_submit_as_navigation_post(request)


def submit_multipart_post_request(tab, request):
    current_tab = resolve_live_tab(tab)
    if current_tab is None:
        raise RuntimeError("browser tab is unavailable")
    form_parts = parse_multipart_form_fields(request)
    if form_parts is None:
        raise RuntimeError("cannot parse multipart form-data post body")

    script = """
(() => {
    const targetUrl = __URL__;
    const parts = __PARTS__;
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = targetUrl;
    form.enctype = 'multipart/form-data';
    form.style.display = 'none';
    for (const part of parts) {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = part.name;
        input.value = part.value;
        form.appendChild(input);
    }
    document.body.appendChild(form);
    form.submit();
    return true;
})();
"""
    script = script.replace("__URL__", json.dumps(request["url"]))
    script = script.replace("__PARTS__", json.dumps(form_parts, ensure_ascii=False))
    current_tab.run_js(script)


def allowed_script_headers(request):
    headers = {}
    skip_names = {
        "host",
        "content-length",
        "connection",
        "cookie",
        "origin",
        "referer",
        "accept-encoding",
        "upgrade-insecure-requests",
    }
    for name, value in parse_headers(request["headers"]):
        lower = name.lower()
        if lower in skip_names or lower.startswith("sec-") or lower.startswith("proxy-"):
            continue
        headers[name] = value
    return headers


def response_headers_from_string(headers_text):
    result = []
    for line in (headers_text or "").splitlines():
        line = line.strip()
        if line:
            result.append(line)
    return result


def response_headers(response):
    try:
        headers = response.headers
        if hasattr(headers, "items"):
            return dict(headers.items())
    except Exception:
        pass
    return {}


def origin_url(url):
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}/"


def current_origin(tab):
    current_url = getattr(tab, "url", "") or ""
    parsed = urlparse(current_url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}/"
    return ""


def ensure_origin(tab, request, timeout_seconds):
    target_origin = origin_url(request["url"])
    if current_origin(tab) == target_origin:
        return
    tab.get(target_origin, retry=0, interval=0, timeout=timeout_seconds)


def ensure_post_context(tab, request, timeout_seconds):
    current_url = getattr(tab, "url", "") or ""
    referer = header_value(request, "Referer")
    if is_http_url(referer) and (current_url == referer or current_url.startswith(referer)):
        return
    if current_origin(tab) == origin_url(request["url"]):
        return
    tab.get(preferred_context_url(request), retry=0, interval=0, timeout=timeout_seconds)


def ensure_fetch_context(tab, request, timeout_seconds):
    current_url = getattr(tab, "url", "") or ""
    referer = header_value(request, "Referer")
    if is_http_url(referer) and (current_url == referer or current_url.startswith(referer)):
        return
    if current_origin(tab) == origin_url(request["url"]):
        return
    tab.get(preferred_context_url(request), retry=0, interval=0, timeout=timeout_seconds)


def packet_response(packet):
    if packet is None:
        return None
    return getattr(packet, "response", None)


def packet_status(packet):
    response = packet_response(packet)
    if response is None:
        return 0
    try:
        return int(getattr(response, "status", 0) or 0)
    except Exception:
        return 0


def wait_for_document_packet(tab, timeout_seconds):
    current_tab = resolve_live_tab(tab)
    if current_tab is None:
        return None
    deadline = time.time() + timeout_seconds
    last_packet = None
    while time.time() < deadline:
        remaining = max(0.1, deadline - time.time())
        packet = current_tab.listen.wait(timeout=min(1.0, remaining))
        if packet is None:
            break
        last_packet = packet
    return last_packet


def wait_for_page_complete(tab, timeout_seconds):
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            current_tab = resolve_live_tab(tab)
            state = current_tab.run_js("return document.readyState")
            if state == "complete":
                return
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError("page load not completed")


def wait_for_ready_state(tab, timeout_seconds, acceptable_states):
    deadline = time.time() + timeout_seconds
    last_state = ""
    accepted = tuple(acceptable_states or ())
    while time.time() < deadline:
        try:
            current_tab = resolve_live_tab(tab)
            last_state = current_tab.run_js("return document.readyState") or ""
            if last_state in accepted:
                return last_state
        except Exception:
            pass
        time.sleep(GET_POLL_INTERVAL_SECONDS)
    return last_state


def wait_for_initial_load(tab, timeout_seconds):
    wait_for_ready_state(tab, max(0.3, min(timeout_seconds, GET_INITIAL_LOAD_MAX_SECONDS)), ("interactive", "complete"))


def page_render_snapshot(tab):
    script = """
return JSON.stringify({
    ready: document.readyState || "",
    href: location.href || "",
    title: document.title || "",
    html_len: document.documentElement ? document.documentElement.outerHTML.length : 0,
    text_len: document.body ? (document.body.innerText || "").trim().length : 0,
    child_count: document.body ? document.body.childElementCount : 0
});
"""
    try:
        current_tab = resolve_live_tab(tab)
        raw = current_tab.run_js(script)
        if not raw:
            return {}
        return json.loads(raw)
    except Exception:
        return {}


def wait_for_page_rendered(tab, timeout_seconds):
    deadline = time.time() + max(0.5, min(timeout_seconds, GET_FINAL_RENDER_MAX_SECONDS))
    last_snapshot = {}
    last_signature = None
    last_change_at = time.time()

    while time.time() < deadline:
        snapshot = page_render_snapshot(tab)
        if snapshot:
            last_snapshot = snapshot
        signature = (
            snapshot.get("href", ""),
            snapshot.get("title", ""),
            int(snapshot.get("html_len", 0) or 0),
            int(snapshot.get("text_len", 0) or 0),
            int(snapshot.get("child_count", 0) or 0),
        )
        ready = snapshot.get("ready") in ("interactive", "complete")
        html_len = signature[2]
        text_len = signature[3]
        child_count = signature[4]
        populated = html_len >= 1500 or text_len >= 80 or child_count >= 8

        if signature != last_signature:
            last_signature = signature
            last_change_at = time.time()
        elif ready and populated and time.time() - last_change_at >= GET_RENDER_SETTLE_SECONDS:
            return snapshot

        if ready and html_len >= 4000:
            return snapshot
        if ready and text_len >= 300:
            return snapshot

        time.sleep(GET_POLL_INTERVAL_SECONDS)

    if last_snapshot:
        return last_snapshot
    return {}


def snapshot_is_populated(snapshot):
    if not snapshot:
        return False
    html_len = int(snapshot.get("html_len", 0) or 0)
    text_len = int(snapshot.get("text_len", 0) or 0)
    child_count = int(snapshot.get("child_count", 0) or 0)
    return html_len >= 1500 or text_len >= 80 or child_count >= 8


def is_meaningful_document(tab, body_text):
    snapshot = page_render_snapshot(tab)
    if snapshot_is_populated(snapshot):
        return True
    html_len = max(int(snapshot.get("html_len", 0) or 0), len(body_text or ""))
    text_len = int(snapshot.get("text_len", 0) or 0)
    child_count = int(snapshot.get("child_count", 0) or 0)
    lowered = (body_text or "").lower()
    has_active_markup = any(marker in lowered for marker in (
        "<script",
        "<form",
        "<iframe",
        "<frame",
        "xmlhttprequest",
        "fetch(",
        "<meta http-equiv=\"refresh\"",
        "<meta http-equiv='refresh'",
    ))
    if text_len >= 12:
        return True
    if child_count >= 2:
        return True
    if html_len >= 1200:
        return True
    return has_active_markup


def reload_page(tab, timeout_seconds):
    phase_timeout = max(0.35, min(timeout_seconds, GET_RELOAD_READY_MAX_SECONDS))
    current_tab = resolve_live_tab(tab)
    try:
        current_tab.run_cdp("Page.reload", ignoreCache=True)
        wait_for_ready_state(current_tab, phase_timeout, ("interactive", "complete"))
        return
    except Exception:
        pass
    try:
        current_tab.run_js("location.reload()")
        wait_for_ready_state(current_tab, phase_timeout, ("interactive", "complete"))
        return
    except Exception:
        pass
    current_url = safe_tab_url(current_tab)
    if current_url:
        current_tab.get(current_url, retry=0, interval=0, timeout=phase_timeout)


def page_html(tab):
    current_tab = resolve_live_tab(tab)
    try:
        html = getattr(current_tab, "html", None)
        if isinstance(html, str) and html:
            return html
    except Exception:
        pass
    try:
        html = current_tab.run_js("return document.documentElement ? document.documentElement.outerHTML : ''")
        return html or ""
    except Exception:
        return ""


def capture_page_html(tab, timeout_seconds):
    deadline = time.time() + max(0.15, min(timeout_seconds, 0.45))
    best_html = ""
    while time.time() < deadline:
        html = page_html(tab)
        if len(html) > len(best_html):
            best_html = html
        if len(html) >= 1500:
            return html
        time.sleep(GET_POLL_INTERVAL_SECONDS)
    return best_html


def stop_page_loading(tab):
    try:
        current_tab = resolve_live_tab(tab)
        current_tab.run_cdp("Page.stopLoading")
    except Exception:
        pass


def evaluate_async_json(tab, script):
    current_tab = resolve_live_tab(tab)
    if current_tab is None:
        raise RuntimeError("browser tab is unavailable")
    result = current_tab.run_cdp(
        "Runtime.evaluate",
        expression=script,
        awaitPromise=True,
        returnByValue=True,
        userGesture=True,
    )
    if isinstance(result, dict):
        if result.get("exceptionDetails"):
            text = result["exceptionDetails"].get("text") or "Runtime.evaluate failed"
            raise RuntimeError(text)
        runtime_result = result.get("result") or {}
        if "value" in runtime_result:
            return runtime_result.get("value")
    if isinstance(result, str):
        return result
    raise RuntimeError("post request returned invalid browser result")


def parse_script_response(tab, result_text, request):
    if not result_text:
        raise RuntimeError("browser request returned empty result")
    result = json.loads(result_text)
    if result.get("error"):
        raise RuntimeError(result["error"])
    content_type = ""
    for header_line in response_headers_from_string(result.get("headers", "")):
        name, _, value = header_line.partition(":")
        if name.strip().lower() == "content-type":
            content_type = value.strip()
            break
    return {
        "status": int(result.get("status", 0)),
        "reason": result.get("reason", ""),
        "headers": response_headers_from_string(result.get("headers", "")),
        "body": base64.b64decode(result.get("body_base64", "") or ""),
        "final_url": result.get("final_url", request["url"]),
        "content_type": content_type,
        "title": getattr(resolve_live_tab(tab), "title", ""),
        "navigation_pending": bool(result.get("navigation_pending")),
        "navigation_kind": result.get("navigation_kind", ""),
        "challenge_like": bool(result.get("challenge_like")),
    }


def execute_xhr_request(tab, request):
    headers = allowed_script_headers(request)
    script = """
(async () => {
    const method = __METHOD__;
    const url = __URL__;
    const headers = __HEADERS__;
    const bodyBase64 = __BODY__;
    const decode = (value) => {
        if (!value) {
            return new Uint8Array(0);
        }
        const binary = atob(value);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    };
    const encode = (bytes) => {
        let binary = "";
        const chunkSize = 0x8000;
        for (let i = 0; i < bytes.length; i += chunkSize) {
            binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
        }
        return btoa(binary);
    };
    try {
        const body = decode(bodyBase64);
        const result = await new Promise((resolve) => {
            const xhr = new XMLHttpRequest();
            xhr.open(method, url, true);
            xhr.withCredentials = true;
            xhr.responseType = "arraybuffer";
            for (const [name, value] of Object.entries(headers)) {
                try {
                    xhr.setRequestHeader(name, value);
                } catch (e) {
                }
            }
            xhr.onloadend = () => {
                try {
                    const responseHeaders = xhr.getAllResponseHeaders() || "";
                    let responseBytes = new Uint8Array(0);
                    if (xhr.response instanceof ArrayBuffer) {
                        responseBytes = new Uint8Array(xhr.response);
                    } else if (typeof xhr.responseText === "string") {
                        responseBytes = new TextEncoder().encode(xhr.responseText);
                    }
                    resolve(JSON.stringify({
                        status: xhr.status || 0,
                        reason: xhr.statusText || "",
                        headers: responseHeaders,
                        body_base64: encode(responseBytes),
                        final_url: xhr.responseURL || url
                    }));
                } catch (e) {
                    resolve(JSON.stringify({error: String(e)}));
                }
            };
            xhr.onerror = () => resolve(JSON.stringify({error: "XMLHttpRequest failed"}));
            xhr.ontimeout = () => resolve(JSON.stringify({error: "XMLHttpRequest timeout"}));
            try {
                xhr.send(body.length ? body : null);
            } catch (e) {
                resolve(JSON.stringify({error: String(e)}));
            }
        });
        return result;
    } catch (e) {
        return JSON.stringify({error: String(e)});
    }
})();
"""
    script = script.replace("__METHOD__", json.dumps(request["method"]))
    script = script.replace("__URL__", json.dumps(request["url"]))
    script = script.replace("__HEADERS__", json.dumps(headers, ensure_ascii=False))
    script = script.replace("__BODY__", json.dumps(base64.b64encode(request["body"]).decode("ascii")))
    return parse_script_response(tab, evaluate_async_json(tab, script), request)


def execute_fetch_request(tab, request):
    headers = allowed_script_headers(request)
    script = """
(async () => {
    const method = __METHOD__;
    const url = __URL__;
    const headers = __HEADERS__;
    const bodyBase64 = __BODY__;
    const referrer = __REFERRER__;
    const decode = (value) => {
        if (!value) {
            return new Uint8Array(0);
        }
        const binary = atob(value);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    };
    const encode = (bytes) => {
        let binary = "";
        const chunkSize = 0x8000;
        for (let i = 0; i < bytes.length; i += chunkSize) {
            binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
        }
        return btoa(binary);
    };
    try {
        const body = decode(bodyBase64);
        const options = {
            method,
            headers,
            credentials: "include",
            redirect: "follow",
            cache: "no-store",
            referrer: referrer || undefined,
        };
        if (method !== "GET" && method !== "HEAD" && body.length) {
            options.body = body;
        }
        const response = await fetch(url, options);
        const responseBytes = new Uint8Array(await response.arrayBuffer());
        const responseHeaders = [];
        response.headers.forEach((value, name) => {
            responseHeaders.push(`${name}: ${value}`);
        });
        return JSON.stringify({
            status: response.status,
            reason: response.statusText || "",
            headers: responseHeaders.join("\\n"),
            body_base64: encode(responseBytes),
            final_url: response.url || url
        });
    } catch (e) {
        return JSON.stringify({error: String(e)});
    }
})();
"""
    script = script.replace("__METHOD__", json.dumps(request["method"]))
    script = script.replace("__URL__", json.dumps(request["url"]))
    script = script.replace("__HEADERS__", json.dumps(headers, ensure_ascii=False))
    script = script.replace("__BODY__", json.dumps(base64.b64encode(request["body"]).decode("ascii")))
    script = script.replace("__REFERRER__", json.dumps(header_value(request, "Referer")))
    return parse_script_response(tab, evaluate_async_json(tab, script), request)


def execute_fetch_post_request(tab, request):
    try:
        return execute_fetch_request(tab, request)
    except Exception:
        return execute_xhr_request(tab, request)


def execute_fetch_get_request(tab, request):
    if request_has_body(request):
        return execute_xhr_request(tab, request)
    return execute_fetch_request(tab, request)


def decode_body_text(body_bytes):
    if not body_bytes:
        return ""
    for encoding in ("utf-8", "gbk", "gb18030", "latin-1"):
        try:
            return body_bytes.decode(encoding)
        except Exception:
            pass
    return body_bytes.decode("utf-8", errors="replace")


def challenge_body_score(body_text):
    text = (body_text or "").lower()
    if not text:
        return 0
    markers = [
        "document.cookie",
        "window.location",
        "location.href",
        "location.replace",
        "location.reload",
        "settimeout(",
        "setinterval(",
        "fetch(",
        "xmlhttprequest",
        "form.submit(",
        "<meta http-equiv=\"refresh\"",
        "<meta http-equiv='refresh'",
        "challenge",
        "anti-bot",
        "verify",
        "token",
        "acw_sc__v2",
        "arg1=",
    ]
    score = 0
    if "<script" in text:
        score += 2
    if "<form" in text:
        score += 1
    for marker in markers:
        if marker in text:
            score += 1
    return score


def looks_like_challenge_document(body_text):
    text = (body_text or "").lower()
    if not text:
        return False

    hard_markers = [
        "acw_sc__v2",
        "arg1=",
        "anti-bot",
        "captcha",
        "cf-browser-verification",
        "cf_chl_",
        "challenge-platform",
        "geetest",
        "slider captcha",
        "verify you are human",
        "waf",
    ]
    navigation_markers = [
        "document.cookie",
        "window.location",
        "location.href",
        "location.replace",
        "location.reload",
        "form.submit(",
        "<meta http-equiv=\"refresh\"",
        "<meta http-equiv='refresh'",
    ]
    timer_markers = [
        "settimeout(",
        "setinterval(",
    ]
    soft_markers = [
        "challenge",
        "verify",
        "token",
    ]

    hard_hits = sum(1 for marker in hard_markers if marker in text)
    navigation_hits = sum(1 for marker in navigation_markers if marker in text)
    timer_hits = sum(1 for marker in timer_markers if marker in text)
    soft_hits = sum(1 for marker in soft_markers if marker in text)
    has_script = "<script" in text
    has_form = "<form" in text

    if hard_hits >= 1 and (navigation_hits + timer_hits + soft_hits >= 1 or has_script):
        return True
    if navigation_hits >= 3 and (has_script or has_form):
        return True
    if navigation_hits >= 2 and timer_hits >= 1 and has_script:
        return True
    if soft_hits >= 2 and navigation_hits >= 1 and has_script:
        return True
    return False


def page_looks_like_challenge(tab, body_text):
    lowered = (body_text or "").lower()
    if not lowered or len(lowered) > POST_CHALLENGE_BODY_LIMIT:
        return False
    if not looks_like_challenge_document(lowered):
        return False

    snapshot = page_render_snapshot(tab)
    html_len = max(int(snapshot.get("html_len", 0) or 0), len(body_text or ""))
    text_len = int(snapshot.get("text_len", 0) or 0)
    child_count = int(snapshot.get("child_count", 0) or 0)
    title = (snapshot.get("title", "") or "").strip()

    hard_markers = (
        "acw_sc__v2",
        "arg1=",
        "anti-bot",
        "captcha",
        "cf-browser-verification",
        "cf_chl_",
        "challenge-platform",
        "geetest",
        "slider captcha",
        "verify you are human",
        "waf",
    )
    hard_hit = any(marker in lowered for marker in hard_markers)

    if hard_hit:
        return True
    if html_len >= 5000 and text_len >= 160 and child_count >= 6 and title:
        return False
    if html_len >= 3500 and text_len >= 120 and child_count >= 6:
        return False
    if text_len >= 280:
        return False
    if child_count >= 14:
        return False
    if html_len >= 45000 and title:
        return False
    return True


def is_blank_like_url(url):
    lowered = (url or "").strip().lower()
    if not lowered:
        return True
    return lowered.startswith(BLANK_LIKE_URL_PREFIXES)


def is_browser_error_url(url):
    lowered = (url or "").strip().lower()
    return lowered.startswith("chrome-error://") or lowered.startswith("edge-error://")


def browser_error_result(tab, request, body_text):
    snapshot = page_render_snapshot(tab)
    current_tab = resolve_live_tab(tab)
    final_url = snapshot.get("href", "") or safe_tab_url(tab) or request["url"]
    if not is_browser_error_url(final_url):
        return None

    title = (snapshot.get("title", "") or getattr(current_tab, "title", "") or "").strip()
    html_len = max(int(snapshot.get("html_len", 0) or 0), len(body_text or ""))
    text_len = int(snapshot.get("text_len", 0) or 0)
    child_count = int(snapshot.get("child_count", 0) or 0)
    if html_len < 120 and text_len < 12 and child_count < 2 and not title:
        return None

    lowered = (body_text or "").lower()
    status = 502
    reason = "Bad Gateway"
    if "504" in title or "504" in lowered:
        status = 504
        reason = "Gateway Timeout"
    elif "503" in title or "503" in lowered:
        status = 503
        reason = "Service Unavailable"
    elif "500" in title or "500" in lowered:
        status = 500
        reason = "Internal Server Error"
    elif "502" in title or "502" in lowered:
        status = 502
        reason = "Bad Gateway"

    return {
        "status": status,
        "reason": reason,
        "headers": {
            "Content-Type": "text/html; charset=UTF-8",
            "Cache-Control": "no-store",
        },
        "body": (body_text or "").encode("utf-8", errors="replace"),
        "final_url": request["url"],
        "title": title or reason,
    }


def is_blank_like_snapshot(snapshot):
    if not snapshot:
        return True
    html_len = int(snapshot.get("html_len", 0) or 0)
    text_len = int(snapshot.get("text_len", 0) or 0)
    child_count = int(snapshot.get("child_count", 0) or 0)
    href = snapshot.get("href", "") or ""
    if html_len >= 128 or text_len >= 12 or child_count >= 2:
        return False
    return is_blank_like_url(href) or (html_len < 96 and text_len == 0 and child_count == 0)


def is_provisional_browser_document(body_text, snapshot):
    lowered = (body_text or "").lower()
    html_len = max(int(snapshot.get("html_len", 0) or 0), len(body_text or ""))
    text_len = int(snapshot.get("text_len", 0) or 0)
    child_count = int(snapshot.get("child_count", 0) or 0)
    title = (snapshot.get("title", "") or "").strip()

    if html_len >= 8000 or text_len >= 120 or child_count >= 10:
        return False

    active_markup = any(marker in lowered for marker in (
        "<script",
        "<form",
        "<iframe",
        "<frame",
        "fetch(",
        "xmlhttprequest",
        "window.location",
        "location.href",
        "location.replace",
        "location.reload",
        "form.submit(",
        "<meta http-equiv=\"refresh\"",
        "<meta http-equiv='refresh'",
    ))

    if active_markup and text_len < 40 and child_count < 6 and html_len < 5000:
        return True
    if not title and text_len < 16 and child_count < 3 and html_len < 1200:
        return True
    return False


def normalized_document_url(url):
    value = (url or "").strip()
    if not value:
        return ""
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return value
    return parsed._replace(fragment="").geturl()


def can_reload_navigation_result(tab, request):
    current_url = normalized_document_url(safe_tab_url(tab))
    if not current_url or not is_http_url(current_url):
        return False
    if is_blank_like_url(current_url):
        return False
    original_url = normalized_document_url(request["url"])
    return current_url != original_url


def looks_like_hidden_form_intermediate_html(body_text):
    html = body_text or ""
    lowered = html.lower()
    if not lowered or len(lowered) > POST_CHALLENGE_BODY_LIMIT:
        return False
    if "<form" not in lowered or "</form>" not in lowered:
        return False

    form_match = re.search(r"<form\b[^>]*\bmethod\s*=\s*(['\"]?)post\1[^>]*>(.*?)</form>", html, re.IGNORECASE | re.DOTALL)
    if not form_match:
        return False

    form_html = form_match.group(0)
    if re.search(r"<(?:button|select)\b", form_html, re.IGNORECASE):
        return False
    if re.search(
        r"<input\b[^>]*\btype\s*=\s*(['\"]?)(?:text|password|checkbox|radio|file|email|search|url|tel|number|date|datetime-local|month|week|time|color)\1",
        form_html,
        re.IGNORECASE,
    ):
        return False

    hidden_style = any(marker in lowered for marker in (
        "visibility:hidden",
        "visibility: hidden",
        "display:none",
        "display: none",
    ))
    has_hidden_input = re.search(r"<input\b[^>]*\btype\s*=\s*(['\"]?)hidden\1", form_html, re.IGNORECASE) is not None
    has_generic_input = re.search(r"<input\b(?![^>]*\btype\s*=)[^>]*\bname\s*=", form_html, re.IGNORECASE) is not None
    has_textarea = re.search(r"<textarea\b", form_html, re.IGNORECASE) is not None

    visible_text = re.sub(r"<script\b.*?</script>", " ", html, flags=re.IGNORECASE | re.DOTALL)
    visible_text = re.sub(r"<style\b.*?</style>", " ", visible_text, flags=re.IGNORECASE | re.DOTALL)
    visible_text = re.sub(r"<[^>]+>", " ", visible_text)
    visible_text = re.sub(r"\s+", " ", visible_text).strip()

    return (hidden_style or has_hidden_input or has_generic_input or has_textarea) and len(visible_text) <= 120


def is_post_challenge_result(result):
    if not result:
        return False
    if result.get("challenge_like"):
        return True
    status = int(result.get("status", 0) or 0)
    if status in (401, 403, 409, 412, 425, 428, 429, 503):
        return True
    content_type = (result.get("content_type", "") or "").lower()
    if "text/html" not in content_type:
        return False
    body_text = decode_body_text(result.get("body", b"")).lower()
    if not body_text:
        return False
    if len(body_text) > POST_CHALLENGE_BODY_LIMIT:
        return False
    if looks_like_hidden_form_intermediate_html(body_text):
        return True
    if looks_like_challenge_document(body_text):
        return True
    score = challenge_body_score(body_text)
    return score >= 3 and status >= 300 and ("location.reload" in body_text or "form.submit(" in body_text)


def build_current_html_result(tab, request, body_text, allow_challenge=False, relaxed=False, min_body_len=128):
    current_tab = resolve_live_tab(tab)
    snapshot = page_render_snapshot(tab)
    final_url = snapshot.get("href", "") or safe_tab_url(tab) or request["url"]
    if not is_http_url(final_url) or is_blank_like_url(final_url):
        return None

    text_len = int(snapshot.get("text_len", 0) or 0)
    child_count = int(snapshot.get("child_count", 0) or 0)
    title = getattr(current_tab, "title", "") or ""

    if len(body_text) < min_body_len:
        if not relaxed:
            return None
        if len(body_text) < 48 and text_len < 8 and child_count == 0 and not title.strip():
            return None

    if not relaxed:
        if not is_meaningful_document(tab, body_text):
            return None
    else:
        if not snapshot_is_populated(snapshot) and text_len < 8 and child_count == 0 and len(body_text) < 96 and not title.strip():
            return None
    if is_provisional_browser_document(body_text, snapshot):
        return None

    lowered = body_text.lower()
    if not allow_challenge and page_looks_like_challenge(tab, body_text):
        return None
    if looks_like_hidden_form_intermediate_html(body_text):
        return None
    if hidden_form_intermediate_snapshot(tab, request).get("auto"):
        return None

    return {
        "status": 200,
        "reason": "OK",
        "headers": {
            "Content-Type": "text/html; charset=UTF-8",
            "Cache-Control": "no-store",
        },
        "body": body_text.encode("utf-8", errors="replace"),
        "final_url": final_url,
        "title": title,
    }


def resolve_provisional_document(tab, request, timeout_seconds):
    deadline = time.time() + max(0.35, min(timeout_seconds, POST_PROVISIONAL_WAIT_SECONDS))
    last_signature = None
    last_change_at = time.time()
    best_body_text = ""

    while time.time() < deadline:
        captured_result = captured_browser_result(tab, request)
        if captured_result is not None:
            if captured_result.get("navigation_pending"):
                last_change_at = time.time()
            elif not is_post_challenge_result(captured_result):
                return {
                    "result": captured_result,
                }

        if hidden_form_intermediate_snapshot(tab, request).get("auto"):
            return {
                "retry": True,
            }

        snapshot = page_render_snapshot(tab)
        body_text = page_html(tab)
        if len(body_text) > len(best_body_text):
            best_body_text = body_text

        signature = (
            snapshot.get("href", "") or "",
            snapshot.get("title", "") or "",
            int(snapshot.get("html_len", 0) or 0),
            int(snapshot.get("text_len", 0) or 0),
            int(snapshot.get("child_count", 0) or 0),
        )
        if signature != last_signature:
            last_signature = signature
            last_change_at = time.time()
        elif not is_provisional_browser_document(body_text, snapshot) and time.time() - last_change_at >= GET_RENDER_SETTLE_SECONDS:
            return {
                "body_text": body_text,
            }

        time.sleep(GET_POLL_INTERVAL_SECONDS)

    return {
        "body_text": best_body_text or capture_page_html(tab, 0.3),
    }


def load_challenge_page(tab, request, result, timeout_seconds):
    current_tab = resolve_live_tab(tab)
    if current_tab is None:
        raise RuntimeError("browser tab is unavailable")
    html = decode_body_text(result.get("body", b""))
    if not html:
        return
    restore_page_hooks(current_tab)
    cleanup_timeout_ms = max(5000, int(max(timeout_seconds, 5.0) * 1000))
    script = """
(() => {
    const url = __URL__;
    const html = __HTML__;
    const cleanupTimeoutMs = __CLEANUP_TIMEOUT_MS__;
    const resultPrefix = "__PASSRS__:";
    const challengeStatuses = new Set([401, 403, 409, 412, 425, 428, 429, 503]);
    const encode = (bytes) => {
        let binary = "";
        const chunkSize = 0x8000;
        for (let i = 0; i < bytes.length; i += chunkSize) {
            binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
        }
        return btoa(binary);
    };
    const toHeaderText = (headers) => {
        const lines = [];
        if (!headers) {
            return "";
        }
        if (typeof headers.forEach === "function") {
            headers.forEach((value, name) => lines.push(`${name}: ${value}`));
            return lines.join("\\n");
        }
        return String(headers || "");
    };
    const persistSerialized = (serialized) => {
        try {
            const currentName = typeof window.name === "string" ? window.name : "";
            const preservedName = currentName.startsWith(resultPrefix)
                ? ((currentName.indexOf("\\n") >= 0) ? currentName.slice(currentName.indexOf("\\n") + 1) : "")
                : currentName;
            window.name = `${resultPrefix}${serialized}\\n${preservedName}`;
        } catch (e) {
        }
    };
    const currentSavedPayload = () => {
        try {
            if (!window.__passrsLastResponse) {
                return null;
            }
            return JSON.parse(window.__passrsLastResponse);
        } catch (e) {
            return null;
        }
    };
    const hasStableResult = () => {
        const payload = currentSavedPayload();
        if (!payload) {
            return false;
        }
        return !payload.navigation_pending && !payload.challenge_like;
    };
    const saveResult = (payload) => {
        try {
            const serialized = JSON.stringify(payload || {});
            window.__passrsLastResponse = serialized;
            window.__passrsLastResponseAt = Date.now();
            persistSerialized(serialized);
        } catch (e) {
        }
    };
    const markNavigationPending = (targetUrl, kind) => {
        if (hasStableResult()) {
            return;
        }
        saveResult({
            status: 0,
            reason: "",
            headers: "",
            body_base64: "",
            final_url: targetUrl || url,
            navigation_pending: true,
            navigation_kind: kind || "",
            challenge_like: false
        });
    };
    const decodeBytes = (bytes) => {
        try {
            return new TextDecoder('utf-8').decode(bytes || new Uint8Array(0));
        } catch (e) {
            try {
                return new TextDecoder('gb18030').decode(bytes || new Uint8Array(0));
            } catch (e2) {
                let binary = '';
                const data = bytes || new Uint8Array(0);
                for (let i = 0; i < data.length; i++) {
                    binary += String.fromCharCode(data[i]);
                }
                return binary;
            }
        }
    };
    const looksLikeChallengeBody = (text) => {
        const lowered = String(text || '').toLowerCase();
        if (!lowered || lowered.length > 220000) {
            return false;
        }
        if (lowered.includes('<form') && (lowered.includes('visibility:hidden') || lowered.includes('visibility: hidden') || lowered.includes('display:none') || lowered.includes('display: none'))) {
            return true;
        }
        const hardMarkers = [
            'acw_sc__v2',
            'arg1=',
            'anti-bot',
            'captcha',
            'cf-browser-verification',
            'cf_chl_',
            'challenge-platform',
            'geetest',
            'slider captcha',
            'verify you are human',
            'waf',
        ];
        for (const marker of hardMarkers) {
            if (lowered.includes(marker)) {
                return true;
            }
        }
        const navigationMarkers = [
            'document.cookie',
            'window.location',
            'location.href',
            'location.replace',
            'location.reload',
            'form.submit(',
            '<meta http-equiv=\"refresh\"',
            "<meta http-equiv='refresh'",
        ];
        const timerMarkers = ['settimeout(', 'setinterval('];
        const softMarkers = ['challenge', 'verify', 'token'];
        let navigationHits = 0;
        let timerHits = 0;
        let softHits = 0;
        for (const marker of navigationMarkers) {
            if (lowered.includes(marker)) {
                navigationHits += 1;
            }
        }
        for (const marker of timerMarkers) {
            if (lowered.includes(marker)) {
                timerHits += 1;
            }
        }
        for (const marker of softMarkers) {
            if (lowered.includes(marker)) {
                softHits += 1;
            }
        }
        const hasScript = lowered.includes('<script');
        const hasForm = lowered.includes('<form');
        if (navigationHits >= 3 && (hasScript || hasForm)) {
            return true;
        }
        if (navigationHits >= 2 && timerHits >= 1 && hasScript) {
            return true;
        }
        return softHits >= 2 && navigationHits >= 1 && hasScript;
    };
    const isChallengeLike = (status, headersText, bodyBytes) => {
        if (challengeStatuses.has(Number(status || 0))) {
            return true;
        }
        const loweredHeaders = String(headersText || '').toLowerCase();
        if (!loweredHeaders.includes('content-type: text/html')) {
            return false;
        }
        return looksLikeChallengeBody(decodeBytes(bodyBytes));
    };
    const restoreHooks = () => {
        try {
            if (window.__passrsOriginalFetch) {
                window.fetch = window.__passrsOriginalFetch;
            }
            if (window.__passrsOriginalXhrOpen) {
                XMLHttpRequest.prototype.open = window.__passrsOriginalXhrOpen;
            }
            if (window.__passrsOriginalXhrSend) {
                XMLHttpRequest.prototype.send = window.__passrsOriginalXhrSend;
            }
            if (window.__passrsOriginalFormSubmit) {
                HTMLFormElement.prototype.submit = window.__passrsOriginalFormSubmit;
            }
            if (window.__passrsUnloadHandler) {
                window.removeEventListener("beforeunload", window.__passrsUnloadHandler, true);
                window.removeEventListener("pagehide", window.__passrsUnloadHandler, true);
            }
            if (window.__passrsCleanupTimer) {
                clearTimeout(window.__passrsCleanupTimer);
            }
            delete window.__passrsCleanupTimer;
            delete window.__passrsOriginalFetch;
            delete window.__passrsOriginalXhrOpen;
            delete window.__passrsOriginalXhrSend;
            delete window.__passrsOriginalFormSubmit;
            delete window.__passrsUnloadHandler;
            delete window.__passrsHooked;
        } catch (e) {
        }
    };
    if (!window.__passrsHooked) {
        window.__passrsHooked = true;
        const originalFetch = window.fetch ? window.fetch.bind(window) : null;
        if (originalFetch && !window.__passrsOriginalFetch) {
            window.__passrsOriginalFetch = originalFetch;
        }
        window.__passrsCleanupTimer = setTimeout(restoreHooks, cleanupTimeoutMs);
        if (originalFetch) {
            window.fetch = async (...args) => {
                const response = await originalFetch(...args);
                try {
                    const clone = response.clone();
                    const bodyBytes = new Uint8Array(await clone.arrayBuffer());
                    const headersText = toHeaderText(response.headers);
                    const challengeLike = isChallengeLike(response.status, headersText, bodyBytes);
                    saveResult({
                        status: response.status || 0,
                        reason: response.statusText || "",
                        headers: headersText,
                        body_base64: encode(bodyBytes),
                        final_url: response.url || (args[0] && String(args[0])) || url,
                        challenge_like: challengeLike
                    });
                    if (!challengeLike) {
                        restoreHooks();
                    }
                } catch (e) {
                }
                return response;
            };
        }
        const originalOpen = XMLHttpRequest.prototype.open;
        const originalSend = XMLHttpRequest.prototype.send;
        if (!window.__passrsOriginalXhrOpen) {
            window.__passrsOriginalXhrOpen = originalOpen;
        }
        if (!window.__passrsOriginalXhrSend) {
            window.__passrsOriginalXhrSend = originalSend;
        }
        const originalFormSubmit = HTMLFormElement.prototype.submit;
        if (!window.__passrsOriginalFormSubmit) {
            window.__passrsOriginalFormSubmit = originalFormSubmit;
        }
        const unloadHandler = () => {
            markNavigationPending(location.href || url, "unload");
        };
        window.__passrsUnloadHandler = unloadHandler;
        try {
            window.addEventListener("beforeunload", unloadHandler, true);
            window.addEventListener("pagehide", unloadHandler, true);
        } catch (e) {
        }
        XMLHttpRequest.prototype.open = function(method, targetUrl) {
            this.__passrsMethod = method;
            this.__passrsUrl = targetUrl;
            return originalOpen.apply(this, arguments);
        };
        XMLHttpRequest.prototype.send = function(body) {
            const xhr = this;
            const finalize = () => {
                try {
                    let bodyBytes = new Uint8Array(0);
                    if (xhr.response instanceof ArrayBuffer) {
                        bodyBytes = new Uint8Array(xhr.response);
                    } else if (typeof xhr.responseText === "string") {
                        bodyBytes = new TextEncoder().encode(xhr.responseText);
                    }
                    const headersText = xhr.getAllResponseHeaders() || "";
                    const challengeLike = isChallengeLike(xhr.status, headersText, bodyBytes);
                    saveResult({
                        status: xhr.status || 0,
                        reason: xhr.statusText || "",
                        headers: headersText,
                        body_base64: encode(bodyBytes),
                        final_url: xhr.responseURL || xhr.__passrsUrl || url,
                        challenge_like: challengeLike
                    });
                    if (!challengeLike) {
                        restoreHooks();
                    }
                } catch (e) {
                }
            };
            try {
                xhr.addEventListener("loadend", finalize, {once: true});
            } catch (e) {
                xhr.addEventListener("loadend", finalize);
            }
            return originalSend.apply(this, arguments);
        };
        HTMLFormElement.prototype.submit = function() {
            try {
                markNavigationPending(this.action || location.href || url, "form-submit");
            } catch (e) {
            }
            return originalFormSubmit.apply(this, arguments);
        };
    }
    try {
        history.replaceState({}, "", url);
    } catch (e) {
    }
    document.open();
    document.write(html);
    document.close();
    return true;
})();
"""
    script = script.replace("__URL__", json.dumps(result.get("final_url") or request["url"]))
    script = script.replace("__HTML__", json.dumps(html))
    script = script.replace("__CLEANUP_TIMEOUT_MS__", json.dumps(cleanup_timeout_ms))
    current_tab.run_js(script)


def captured_browser_result(tab, request):
    try:
        current_tab = resolve_live_tab(tab)
        raw = current_tab.run_js("""
(() => {
    const prefix = "__PASSRS__:";
    const takePersistedValue = () => {
        try {
            const currentName = typeof window.name === "string" ? window.name : "";
            if (!currentName.startsWith(prefix)) {
                return "";
            }
            const separator = currentName.indexOf("\\n");
            const persisted = separator >= 0 ? currentName.slice(prefix.length, separator) : currentName.slice(prefix.length);
            window.name = separator >= 0 ? currentName.slice(separator + 1) : "";
            return persisted;
        } catch (e) {
            return "";
        }
    };
    const value = window.__passrsLastResponse || takePersistedValue() || "";
    window.__passrsLastResponse = "";
    return value;
})();
""")
    except Exception:
        return None
    if not raw:
        return None
    try:
        return parse_script_response(tab, raw, request)
    except Exception:
        return None


def wait_for_captured_browser_result(tab, request, timeout_seconds):
    deadline = time.time() + max(0.3, min(timeout_seconds, POST_CHALLENGE_WAIT_SECONDS))
    while time.time() < deadline:
        result = captured_browser_result(tab, request)
        if result is not None:
            return result
        time.sleep(GET_POLL_INTERVAL_SECONDS)
    return None


def wait_for_post_challenge(tab, timeout_seconds):
    deadline = time.time() + max(0.4, min(timeout_seconds, POST_CHALLENGE_WAIT_SECONDS))
    last_cookie = ""
    last_change_at = time.time()
    while time.time() < deadline:
        try:
            current_tab = resolve_live_tab(tab)
            cookie_text = current_tab.run_js("return document.cookie || ''") or ""
        except Exception:
            cookie_text = ""
        if cookie_text != last_cookie:
            last_cookie = cookie_text
            last_change_at = time.time()
        snapshot = page_render_snapshot(tab)
        ready = snapshot.get("ready") in ("interactive", "complete")
        if ready and time.time() - last_change_at >= 0.18:
            return
        time.sleep(GET_POLL_INTERVAL_SECONDS)


def hidden_form_intermediate_snapshot(tab, request):
    script = """
return JSON.stringify((() => {
    const form = document.forms && document.forms.length ? document.forms[0] : null;
    const body = document.body;
    if (!form || !body) {
        return {auto: false};
    }
    const isEffectivelyHidden = (element) => {
        let current = element;
        while (current && current.nodeType === 1) {
            const style = window.getComputedStyle ? window.getComputedStyle(current) : null;
            if (style && (style.display === 'none' || style.visibility === 'hidden')) {
                return true;
            }
            current = current.parentElement;
        }
        return false;
    };
    const hiddenInputs = form.querySelectorAll('input[type="hidden"], input:not([type]), textarea[hidden]').length;
    const visibleControls = Array.from(form.querySelectorAll('input, button, select, textarea'))
        .filter((element) => {
            const type = (element.type || '').toLowerCase();
            if (type === 'hidden') {
                return false;
            }
            if (isEffectivelyHidden(element)) {
                return false;
            }
            return true;
        }).length;
    const bodyText = (body.innerText || '').trim();
    const formAction = form.action || location.href || '';
    const currentUrl = location.href || '';
    const expectedUrl = __EXPECTED_URL__;
    const sameTarget = !expectedUrl || formAction === expectedUrl || currentUrl === expectedUrl || formAction === currentUrl;
    const formHidden = isEffectivelyHidden(form);
    const controlCount = form.querySelectorAll('input, button, select, textarea').length;
    const auto = (hiddenInputs > 0 || formHidden) && visibleControls == 0
        && controlCount <= 8
        && (sameTarget || bodyText.length <= 48)
        && bodyText.length <= 120;
    return {
        auto,
        same_target: sameTarget,
        form_hidden: formHidden,
        hidden_inputs: hiddenInputs,
        control_count: controlCount,
        visible_controls: visibleControls,
        body_text_len: bodyText.length
    };
})());
"""
    script = script.replace("__EXPECTED_URL__", json.dumps(request["url"]))
    try:
        current_tab = resolve_live_tab(tab)
        raw = current_tab.run_js(script)
        if not raw:
            return {}
        return json.loads(raw)
    except Exception:
        return {}


def submit_hidden_form_intermediate(tab, request):
    snapshot = hidden_form_intermediate_snapshot(tab, request)
    if not snapshot.get("auto"):
        return False
    script = """
(() => {
    const form = document.forms && document.forms.length ? document.forms[0] : null;
    if (!form) {
        return false;
    }
    if (!form.action) {
        form.action = __TARGET_URL__;
    }
    if (!form.method) {
        form.method = 'POST';
    }
    form.submit();
    return true;
})();
"""
    script = script.replace("__TARGET_URL__", json.dumps(request["url"]))
    try:
        current_tab = resolve_live_tab(tab)
        return bool(current_tab.run_js(script))
    except Exception:
        return False


def current_page_result(tab, request):
    body_text = capture_page_html(tab, 0.35)
    if looks_like_hidden_form_intermediate_html(body_text):
        return None
    return build_current_html_result(tab, request, body_text, min_body_len=256)


def current_document_result(tab, request, timeout_seconds, allow_challenge=False):
    wait_for_post_challenge(tab, timeout_seconds)
    for _ in range(2):
        wait_for_page_rendered(tab, timeout_seconds)
        if not can_auto_submit_intermediate(request):
            break
        if not submit_hidden_form_intermediate(tab, request):
            break
        wait_for_initial_load(tab, timeout_seconds)
    body_text = capture_page_html(tab, timeout_seconds)
    initial_snapshot = page_render_snapshot(tab)
    if is_provisional_browser_document(body_text, initial_snapshot):
        provisional_resolution = resolve_provisional_document(tab, request, timeout_seconds)
        if provisional_resolution.get("result") is not None:
            return provisional_resolution.get("result")
        if provisional_resolution.get("retry"):
            return None
        body_text = provisional_resolution.get("body_text", body_text) or body_text
    result = build_current_html_result(
        tab,
        request,
        body_text,
        allow_challenge=allow_challenge,
        min_body_len=128
    )
    if result is None:
        return None
    stop_page_loading(tab)
    return result


def relaxed_document_result(tab, request, timeout_seconds, allow_challenge=False):
    wait_for_post_challenge(tab, timeout_seconds)
    wait_for_page_rendered(tab, timeout_seconds)
    body_text = capture_page_html(tab, max(0.35, min(timeout_seconds, 0.9)))
    initial_snapshot = page_render_snapshot(tab)
    if is_provisional_browser_document(body_text, initial_snapshot):
        provisional_resolution = resolve_provisional_document(tab, request, timeout_seconds)
        if provisional_resolution.get("result") is not None:
            return provisional_resolution.get("result")
        if provisional_resolution.get("retry"):
            return None
        body_text = provisional_resolution.get("body_text", body_text) or body_text
    result = build_current_html_result(
        tab,
        request,
        body_text,
        allow_challenge=allow_challenge,
        relaxed=True,
        min_body_len=48
    )
    if result is None:
        return None
    stop_page_loading(tab)
    return result


def final_stable_page_result(tab, request, timeout_seconds):
    try:
        wait_for_page_rendered(tab, max(0.35, min(timeout_seconds, 0.9)))
    except Exception:
        pass

    body_text = capture_page_html(tab, max(0.35, min(timeout_seconds, 0.9)))
    error_result = browser_error_result(tab, request, body_text)
    if error_result is not None:
        stop_page_loading(tab)
        return error_result
    result = observed_page_result(
        tab,
        request,
        body_text,
        min_body_len=48,
        reject_challenge=True,
        reject_provisional=False,
        reject_hidden_form=True
    )
    if result is None:
        return None
    stop_page_loading(tab)
    return result


def reload_challenge_page_result(tab, request, timeout_seconds):
    body_text = page_html(tab)
    if not page_looks_like_challenge(tab, body_text):
        return None
    try:
        reload_page(tab, timeout_seconds)
        wait_for_page_rendered(tab, timeout_seconds)
    except Exception:
        return None
    result = current_document_result(tab, request, timeout_seconds)
    if result is not None:
        return result
    result = relaxed_document_result(tab, request, timeout_seconds)
    if result is not None:
        return result
    return final_stable_page_result(tab, request, timeout_seconds)


def observed_page_result(tab, request, body_text, min_body_len=48,
                         reject_challenge=True, reject_provisional=False, reject_hidden_form=False):
    error_result = browser_error_result(tab, request, body_text)
    if error_result is not None:
        return error_result

    snapshot = page_render_snapshot(tab)
    current_tab = resolve_live_tab(tab)
    final_url = snapshot.get("href", "") or safe_tab_url(tab) or request["url"]
    title = (snapshot.get("title", "") or getattr(current_tab, "title", "") or "").strip()
    html_len = max(int(snapshot.get("html_len", 0) or 0), len(body_text or ""))
    text_len = int(snapshot.get("text_len", 0) or 0)
    child_count = int(snapshot.get("child_count", 0) or 0)

    if not is_http_url(final_url) or is_blank_like_url(final_url):
        return None
    if html_len < min_body_len and text_len < 4 and child_count == 0 and not title:
        return None

    lowered = (body_text or "").lower()
    if reject_challenge and page_looks_like_challenge(tab, body_text):
        return None
    if reject_provisional and is_provisional_browser_document(body_text, snapshot):
        return None
    if reject_hidden_form and looks_like_hidden_form_intermediate_html(body_text):
        return None
    if reject_hidden_form and hidden_form_intermediate_snapshot(tab, request).get("auto"):
        return None

    return {
        "status": 200,
        "reason": "OK",
        "headers": {
            "Content-Type": "text/html; charset=UTF-8",
            "Cache-Control": "no-store",
        },
        "body": (body_text or "").encode("utf-8", errors="replace"),
        "final_url": final_url,
        "title": title,
    }


def summarize_tab_state(tab, request, body_text=""):
    snapshot = page_render_snapshot(tab)
    current_tab = resolve_live_tab(tab)
    final_url = snapshot.get("href", "") or safe_tab_url(tab) or request["url"]
    title = (snapshot.get("title", "") or getattr(current_tab, "title", "") or "").strip()
    html_len = max(int(snapshot.get("html_len", 0) or 0), len(body_text or ""))
    text_len = int(snapshot.get("text_len", 0) or 0)
    child_count = int(snapshot.get("child_count", 0) or 0)
    hidden_form = bool(hidden_form_intermediate_snapshot(tab, request).get("auto"))
    pending = False
    captured_result = captured_browser_result(tab, request)
    if captured_result is not None:
        pending = bool(captured_result.get("navigation_pending"))
    lowered = (body_text or "").lower()
    challenge_like = page_looks_like_challenge(tab, body_text)
    return (
        f"url={final_url} | title={title[:80]} | html_len={html_len} | text_len={text_len} "
        f"| child_count={child_count} | hidden_form={hidden_form} | pending={pending} "
        f"| challenge_like={challenge_like}"
    )


def navigated_page_result(tab, request, body_text):
    error_result = browser_error_result(tab, request, body_text)
    if error_result is not None:
        return error_result
    if looks_like_hidden_form_intermediate_html(body_text):
        return None

    snapshot = page_render_snapshot(tab)
    final_url = snapshot.get("href", "") or safe_tab_url(tab) or request["url"]
    if not is_http_url(final_url) or is_blank_like_url(final_url):
        return None
    if normalized_document_url(final_url) == normalized_document_url(request["url"]):
        return None
    result = observed_page_result(
        tab,
        request,
        body_text,
        min_body_len=48,
        reject_challenge=True,
        reject_provisional=False,
        reject_hidden_form=True
    )
    if result is not None:
        return result

    current_tab = resolve_live_tab(tab)
    title = (snapshot.get("title", "") or getattr(current_tab, "title", "") or "").strip()
    html_len = max(int(snapshot.get("html_len", 0) or 0), len(body_text or ""))
    text_len = int(snapshot.get("text_len", 0) or 0)
    child_count = int(snapshot.get("child_count", 0) or 0)
    if html_len < 200 and text_len < 20 and child_count < 4 and not title:
        return None
    if hidden_form_intermediate_snapshot(tab, request).get("auto"):
        return None
    lowered = (body_text or "").lower()
    if page_looks_like_challenge(tab, body_text):
        return None
    return {
        "status": 200,
        "reason": "OK",
        "headers": {
            "Content-Type": "text/html; charset=UTF-8",
            "Cache-Control": "no-store",
        },
        "body": (body_text or "").encode("utf-8", errors="replace"),
        "final_url": final_url,
        "title": title,
    }


def wait_for_empty_body_navigation_result(tab, request, timeout_seconds):
    deadline = time.time() + max(1.5, timeout_seconds + 1.2)
    last_change_at = time.time()
    state_trace = []
    original_url = normalized_document_url(request["url"])
    last_url = normalized_document_url(safe_tab_url(tab))
    next_body_probe_at = time.time()
    hidden_form_seen_at = None
    hidden_form_submitted = False

    while time.time() < deadline:
        captured_result = captured_browser_result(tab, request)
        if captured_result is not None:
            if not captured_result.get("navigation_pending") and not is_post_challenge_result(captured_result):
                return captured_result
            last_change_at = time.time()

        current_url = normalized_document_url(safe_tab_url(tab))
        if current_url != last_url:
            last_url = current_url
            last_change_at = time.time()
            next_body_probe_at = time.time()

        should_probe_body = time.time() >= next_body_probe_at
        navigated_away = current_url and current_url != original_url and is_http_url(current_url) and not is_blank_like_url(current_url)

        if navigated_away:
            should_probe_body = True

        if should_probe_body:
            body_text = capture_page_html(tab, 0.2 if not navigated_away else 0.35)
            state_trace.append(summarize_tab_state(tab, request, body_text))
            if len(state_trace) > 10:
                state_trace.pop(0)
            next_body_probe_at = time.time() + (0.18 if navigated_away else 0.4)

            intermediate_snapshot = hidden_form_intermediate_snapshot(tab, request)
            if intermediate_snapshot.get("auto"):
                if hidden_form_seen_at is None:
                    hidden_form_seen_at = time.time()
                elif (not hidden_form_submitted
                      and time.time() - hidden_form_seen_at >= EMPTY_BODY_HIDDEN_FORM_STABLE_SECONDS):
                    if submit_hidden_form_intermediate(tab, request):
                        hidden_form_submitted = True
                        hidden_form_seen_at = None
                        last_change_at = time.time()
                        try:
                            wait_for_initial_load(tab, max(0.8, min(timeout_seconds, 2.0)))
                        except Exception:
                            pass
                        continue
            else:
                hidden_form_seen_at = None

            navigated_result = navigated_page_result(tab, request, body_text)
            if navigated_result is not None and time.time() - last_change_at >= EMPTY_BODY_SETTLE_SECONDS:
                stop_page_loading(tab)
                return navigated_result

            result = observed_page_result(
                tab,
                request,
                body_text,
                min_body_len=48,
                reject_challenge=True,
                reject_provisional=False,
                reject_hidden_form=True
            )
            if result is not None and time.time() - last_change_at >= EMPTY_BODY_SETTLE_SECONDS:
                stop_page_loading(tab)
                return result

        time.sleep(GET_POLL_INTERVAL_SECONDS)

    final_result = final_stable_page_result(tab, request, max(0.35, min(timeout_seconds, 1.2)))
    if final_result is not None and not hidden_form_intermediate_snapshot(tab, request).get("auto"):
        return final_result
    body_text = page_html(tab)
    navigated_result = navigated_page_result(tab, request, body_text)
    if navigated_result is not None:
        return navigated_result
    return {
        "error": "navigation post did not produce a stable browser result",
        "trace": state_trace,
        "final_state": summarize_tab_state(tab, request, body_text),
    }


def complete_navigation_post_challenge(tab, request, timeout_seconds):
    wait_for_post_challenge(tab, timeout_seconds)

    submitted_intermediate = False
    if can_auto_submit_challenge_intermediate(request):
        submitted_intermediate = submit_hidden_form_intermediate(tab, request)
    if submitted_intermediate:
        wait_for_initial_load(tab, timeout_seconds)
        navigation_result = current_document_result(tab, request, timeout_seconds)
        if navigation_result is not None:
            return navigation_result

    captured_result = wait_for_captured_browser_result(tab, request, timeout_seconds)
    if captured_result is not None:
        if captured_result.get("navigation_pending"):
            navigation_result = current_document_result(tab, request, timeout_seconds)
            if navigation_result is not None:
                return navigation_result
        elif not is_post_challenge_result(captured_result):
            return captured_result

    page_result = current_page_result(tab, request)
    if page_result is not None:
        return page_result

    relaxed_result = relaxed_document_result(tab, request, timeout_seconds)
    if relaxed_result is not None:
        return relaxed_result

    blank_snapshot = page_render_snapshot(tab)
    if is_blank_like_snapshot(blank_snapshot):
        navigation_result = current_document_result(tab, request, timeout_seconds)
        if navigation_result is not None:
            return navigation_result
        page_result = current_page_result(tab, request)
        if page_result is not None:
            return page_result
        relaxed_result = relaxed_document_result(tab, request, timeout_seconds)
        if relaxed_result is not None:
            return relaxed_result

    page_result = current_page_result(tab, request)
    if page_result is not None:
        return page_result
    relaxed_result = relaxed_document_result(tab, request, timeout_seconds)
    if relaxed_result is not None:
        return relaxed_result
    final_result = final_stable_page_result(tab, request, timeout_seconds)
    if final_result is not None:
        return final_result
    reload_result = reload_challenge_page_result(tab, request, timeout_seconds)
    if reload_result is not None:
        return reload_result
    return None


def execute_navigation_non_form_post_request(tab, request, timeout_seconds, allow_static_resources):
    configure_tab_network(tab, allow_static_resources)
    ensure_post_context(tab, request, timeout_seconds)
    set_request_cookies(tab, request)

    initial_result = execute_fetch_post_request(tab, request)
    if not is_post_challenge_result(initial_result):
        return initial_result

    load_challenge_page(tab, request, initial_result, timeout_seconds)
    challenge_result = complete_navigation_post_challenge(tab, request, timeout_seconds)
    if challenge_result is not None:
        return challenge_result

    page_result = current_page_result(tab, request)
    if page_result is not None:
        return page_result
    final_result = final_stable_page_result(tab, request, timeout_seconds)
    if final_result is not None:
        return final_result
    return initial_result


def execute_navigation_post_request(tab, request, timeout_seconds):
    ensure_post_context(tab, request, timeout_seconds)
    set_request_cookies(tab, request)
    if is_empty_body_post(request):
        submit_empty_post_request(tab, request)
        wait_for_initial_load(tab, timeout_seconds)
        result = wait_for_empty_body_navigation_result(tab, request, timeout_seconds)
        if result is not None:
            if isinstance(result, dict) and result.get("error"):
                trace = " || ".join(result.get("trace") or [])
                final_state = result.get("final_state") or ""
                raise RuntimeError(f"{result['error']} | final_state={final_state} | trace={trace}")
            return result
        raise RuntimeError("navigation post did not produce a stable browser result")
    elif is_form_urlencoded_post(request):
        submit_form_post_request(tab, request)
    else:
        submit_multipart_post_request(tab, request)
    wait_for_initial_load(tab, timeout_seconds)
    result = current_document_result(tab, request, timeout_seconds)
    if result is not None:
        return result
    challenge_result = complete_navigation_post_challenge(tab, request, timeout_seconds)
    if challenge_result is not None:
        return challenge_result
    relaxed_result = relaxed_document_result(tab, request, timeout_seconds)
    if relaxed_result is not None:
        return relaxed_result
    final_result = final_stable_page_result(tab, request, timeout_seconds)
    if final_result is not None:
        return final_result
    reload_result = reload_challenge_page_result(tab, request, timeout_seconds)
    if reload_result is not None:
        return reload_result
    raise RuntimeError("navigation post did not produce a stable browser result | final_state="
                       + summarize_tab_state(tab, request, page_html(tab)))


def execute_post_request(tab, request, timeout_seconds, allow_static_resources):
    if is_navigation_post(request) and can_submit_as_navigation_post(request):
        configure_tab_network(tab, allow_static_resources)
        return execute_navigation_post_request(tab, request, timeout_seconds)
    if is_navigation_non_form_post(request):
        return execute_navigation_non_form_post_request(tab, request, timeout_seconds, allow_static_resources)

    configure_tab_network(tab, allow_static_resources)
    ensure_post_context(tab, request, timeout_seconds)
    set_request_cookies(tab, request)
    result = execute_fetch_post_request(tab, request)
    if not is_post_challenge_result(result):
        return result

    last_result = result
    for _ in range(POST_RETRY_ATTEMPTS):
        load_challenge_page(tab, request, last_result, timeout_seconds)
        if is_navigation_post(request):
            navigation_result = complete_navigation_post_challenge(tab, request, timeout_seconds)
            if navigation_result is not None:
                return navigation_result
            return last_result
        wait_for_post_challenge(tab, timeout_seconds)
        captured_result = wait_for_captured_browser_result(tab, request, timeout_seconds)
        if captured_result is not None and not is_post_challenge_result(captured_result):
            return captured_result
        page_result = current_page_result(tab, request)
        if page_result is not None:
            return page_result
        ensure_post_context(tab, request, timeout_seconds)
        retry_result = execute_fetch_post_request(tab, request)
        if not is_post_challenge_result(retry_result):
            return retry_result
        last_result = retry_result
    return last_result


def execute_get_request(tab, request, timeout_seconds, allow_static_resources):
    configure_tab_network(tab, allow_static_resources)
    set_request_cookies(tab, request)
    if not is_navigation_get(request):
        ensure_fetch_context(tab, request, timeout_seconds)
        return execute_fetch_get_request(tab, request)
    current_tab = resolve_live_tab(tab)
    current_tab.get(request["url"], retry=0, interval=0, timeout=timeout_seconds)
    wait_for_initial_load(current_tab, timeout_seconds)
    # Some anti-bot pages only render the final document after one real reload.
    reload_page(current_tab, timeout_seconds)
    wait_for_page_rendered(current_tab, timeout_seconds)
    body_text = capture_page_html(current_tab, timeout_seconds)
    stop_page_loading(current_tab)
    body_bytes = body_text.encode("utf-8", errors="replace")
    return {
        "status": 200,
        "reason": "OK",
        "headers": {
            "Content-Type": "text/html; charset=UTF-8",
            "Cache-Control": "no-store",
        },
        "body": body_bytes,
        "final_url": safe_tab_url(current_tab) or request["url"],
        "title": getattr(current_tab, "title", ""),
    }


def close_browser(args):
    last_error = None
    for port in candidate_existing_ports(args):
        try:
            browser = Chromium(build_options(args, port, existing_only=True))
            restore_browser_hooks(browser)
            try:
                browser.quit(3, force=True)
            except TypeError:
                try:
                    browser.quit()
                except Exception:
                    pass
            except Exception:
                pass
            clear_state(args.state_file)
            return
        except Exception as exc:
            last_error = exc
    clear_state(args.state_file)
    if last_error is not None and candidate_existing_ports(args):
        raise last_error


def cleanup_browser(args):
    last_error = None
    cleaned = False
    for port in candidate_existing_ports(args):
        try:
            browser = Chromium(build_options(args, port, existing_only=True))
            restore_browser_hooks(browser)
            cleaned = True
        except Exception as exc:
            last_error = exc
    if not cleaned and last_error is not None and candidate_existing_ports(args):
        raise last_error


def navigate(args):
    request = read_request_file(args.request_file)
    timeout_seconds = max(float(args.timeout_ms) / 1000.0, 5.0)
    last_error = None

    for port in candidate_existing_ports(args):
        tab = None
        try:
            browser = Chromium(build_options(args, port, existing_only=True))
            save_state(args.state_file, port)
            tab = resolve_request_tab(browser, request)
        except Exception as exc:
            last_error = exc
            clear_state(args.state_file)
            continue
        try:
            if request["method"] == "POST":
                result = execute_post_request(tab, request, timeout_seconds, args.load_static_resources)
            else:
                result = execute_get_request(tab, request, timeout_seconds, args.load_static_resources)
            print_response(result)
            return
        except Exception as exc:
            last_error = exc
            try:
                if tab is not None:
                    tab.listen.stop()
            except Exception:
                pass
            raise last_error

    launch_port = next_launch_port(args)
    tab = None
    try:
        browser = Chromium(build_options(args, launch_port))
        save_state(args.state_file, launch_port)
        tab = resolve_request_tab(browser, request)
        if request["method"] == "POST":
            result = execute_post_request(tab, request, timeout_seconds, args.load_static_resources)
        else:
            result = execute_get_request(tab, request, timeout_seconds, args.load_static_resources)
        print_response(result)
        return
    except Exception as exc:
        last_error = exc
        try:
            if tab is not None:
                tab.listen.stop()
        except Exception:
            pass

    if last_error is not None:
        raise last_error
    raise RuntimeError("browser bridge start failed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", choices=("navigate", "close", "cleanup"), required=True)
    parser.add_argument("--request-file", default="")
    parser.add_argument("--browser-type", default="edge")
    parser.add_argument("--browser-path", default="")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--user-data-path", required=True)
    parser.add_argument("--state-file", default="")
    parser.add_argument("--timeout-ms", type=int, default=15000)
    parser.add_argument("--load-static-resources", action="store_true")
    args = parser.parse_args()

    try:
        if args.action == "close":
            close_browser(args)
            print("STATUS=0")
            print(f"REASON={b64_text('')}")
            print(f"FINAL_URL={b64_text('')}")
            print(f"TITLE={b64_text('')}")
            print("HEADER_COUNT=0")
            print("BODY=")
        elif args.action == "cleanup":
            cleanup_browser(args)
            print("STATUS=0")
            print(f"REASON={b64_text('')}")
            print(f"FINAL_URL={b64_text('')}")
            print(f"TITLE={b64_text('')}")
            print("HEADER_COUNT=0")
            print("BODY=")
        else:
            navigate(args)
        return 0
    except Exception as exc:
        message = str(exc) or repr(exc) or exc.__class__.__name__
        print(message, file=sys.stderr)
        print(traceback.format_exc(), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
