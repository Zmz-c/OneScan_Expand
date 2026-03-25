import argparse
import base64
import json
import os
import socket
import sys

from DrissionPage import Chromium, ChromiumOptions


def load_state(state_file):
    if not state_file:
        return {}
    try:
        if os.path.isfile(state_file):
            with open(state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
    except Exception:
        pass
    return {}


def save_state(state_file, port):
    if not state_file:
        return
    os.makedirs(os.path.dirname(state_file), exist_ok=True)
    with open(state_file, "w", encoding="utf-8") as f:
        json.dump({"port": port}, f)


def clear_state(state_file):
    if not state_file:
        return
    try:
        if os.path.isfile(state_file):
            os.remove(state_file)
    except Exception:
        pass


def find_free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def candidate_ports(args):
    result = []
    state = load_state(args.state_file)
    saved_port = state.get("port")
    if isinstance(saved_port, int) and saved_port > 0:
        result.append(saved_port)
    if args.port not in result:
        result.append(args.port)
    for _ in range(2):
        port = find_free_port()
        if port not in result:
            result.append(port)
    return result


def close_candidate_ports(args):
    result = []
    state = load_state(args.state_file)
    saved_port = state.get("port")
    if isinstance(saved_port, int) and saved_port > 0:
        result.append(saved_port)
    if args.port not in result:
        result.append(args.port)
    return result


def find_browser_path(browser_type, explicit_path=""):
    browser_type = (browser_type or "edge").lower()
    if browser_type == "firefox":
        raise RuntimeError("DrissionPage current bridge only supports Chromium browsers, Firefox is not supported")
    if explicit_path:
        explicit_path = os.path.abspath(os.path.expanduser(explicit_path))
        if os.path.isfile(explicit_path):
            return explicit_path
        raise RuntimeError(f"Browser executable not found: {explicit_path}")

    if browser_type == "chrome":
        candidates = [
            os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(os.environ.get("PROGRAMFILES", ""), "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "Application", "chrome.exe"),
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ]
    else:
        candidates = [
            os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join(os.environ.get("PROGRAMFILES", ""), "Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Edge", "Application", "msedge.exe"),
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        ]

    for path in candidates:
        if path and os.path.isfile(path):
            return path
    if browser_type == "chrome":
        raise RuntimeError("Chrome/Chromium not found, please configure browser executable path")
    raise RuntimeError("Edge not found, please configure browser executable path or switch browser type")


def build_options(args, port):
    browser_type = (args.browser_type or "edge").lower()
    if browser_type == "firefox":
        raise RuntimeError("DrissionPage current bridge only supports Chromium browsers, Firefox is not supported")

    options = ChromiumOptions()
    options.set_local_port(port)
    options.set_user_data_path(args.user_data_path)
    options.set_load_mode("eager")

    browser_path = find_browser_path(browser_type, args.browser_path)
    options.set_browser_path(browser_path)

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
    options.set_argument("--disable-features=AutofillServerCommunication,CertificateTransparencyComponentUpdater,OptimizationHints,MediaRouter")

    timeout_seconds = max(float(args.timeout_ms) / 1000.0, 5.0)
    options.set_timeouts(base=timeout_seconds, page_load=timeout_seconds)
    return options


def ensure_single_tab(browser):
    tab = browser.latest_tab
    if isinstance(tab, str):
        tab = browser.get_tab(tab)
    browser.close_tabs(tab, others=True)
    return tab


def encode_body(body):
    if body is None:
        return ""
    if isinstance(body, bytes):
        data = body
    elif isinstance(body, str):
        data = body.encode("utf-8", errors="replace")
    else:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8", errors="replace")
    return base64.b64encode(data).decode("ascii")


def response_headers(response):
    try:
        headers = response.headers
        if hasattr(headers, "items"):
            return dict(headers.items())
    except Exception:
        pass
    return {}


def close_browser(args):
    last_error = None
    for port in close_candidate_ports(args):
        try:
            options = build_options(args, port)
            options.existing_only()
            browser = Chromium(options)
            browser.quit()
            clear_state(args.state_file)
            return
        except Exception as exc:
            last_error = exc
    clear_state(args.state_file)
    if last_error is not None and close_candidate_ports(args):
        raise last_error


def navigate(args):
    timeout_seconds = max(float(args.timeout_ms) / 1000.0, 5.0)
    last_error = None

    for port in candidate_ports(args):
        browser = None
        tab = None
        try:
            save_state(args.state_file, port)
            browser = Chromium(build_options(args, port))
            tab = ensure_single_tab(browser)
            tab.listen.start(method="GET", res_type="Document")
            tab.get(args.url, retry=0, interval=0, timeout=timeout_seconds)
            packet = tab.listen.wait(timeout=timeout_seconds)
            tab.listen.stop()

            if packet is None or packet.response is None:
                raise RuntimeError("main document response not captured")

            response = packet.response
            result = {
                "status": getattr(response, "status", 0),
                "reason": getattr(response, "statusText", "") or getattr(response, "reason", ""),
                "headers": response_headers(response),
                "body_base64": encode_body(getattr(response, "body", b"")),
                "final_url": getattr(packet, "url", "") or getattr(response, "url", ""),
                "title": getattr(tab, "title", ""),
            }
            print(json.dumps(result, ensure_ascii=False))
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
    parser.add_argument("--action", choices=("navigate", "close"), required=True)
    parser.add_argument("--url", default="")
    parser.add_argument("--browser-type", default="edge")
    parser.add_argument("--browser-path", default="")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--user-data-path", required=True)
    parser.add_argument("--state-file", default="")
    parser.add_argument("--timeout-ms", type=int, default=15000)
    args = parser.parse_args()

    try:
        if args.action == "close":
            close_browser(args)
            print(json.dumps({"status": 0}))
        else:
            navigate(args)
        return 0
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
