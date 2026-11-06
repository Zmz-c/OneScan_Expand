package burp.vaycore.ost.browser;

import java.util.List;
import java.util.UUID;

public record BrowserRequest(String method, String url, List<String> headers, byte[] body,
                             boolean isolateCookies, String browserId) {

    public static final String DEFAULT_BROWSER_ID = "browser-request";
    public static final String PARAMETER_FUZZ_BROWSER_ID = "parameter-fuzz";

    public static String newParameterFuzzBrowserId() {
        // Keep the full UUID: this ID selects the browser profile, so shortening
        // it needlessly increases the chance of two fuzz runs sharing cookies.
        return PARAMETER_FUZZ_BROWSER_ID + "-" + UUID.randomUUID();
    }

    /** Backward-compatible constructor for existing callers. */
    public BrowserRequest(String method, String url, List<String> headers, byte[] body, boolean isolateCookies) {
        this(method, url, headers, body, isolateCookies, DEFAULT_BROWSER_ID);
    }

    public BrowserRequest {
        method = method == null ? "" : method.trim().toUpperCase();
        url = url == null ? "" : url.trim();
        headers = List.copyOf(headers == null ? List.of() : headers);
        body = body == null ? new byte[0] : body.clone();
        browserId = normalizeBrowserId(browserId);
    }

    public static BrowserRequest of(String method, String url, List<String> headers, byte[] body) {
        return of(method, url, headers, body, false);
    }

    public static BrowserRequest of(String method, String url, List<String> headers, byte[] body,
                                    boolean isolateCookies) {
        return of(method, url, headers, body, isolateCookies, DEFAULT_BROWSER_ID);
    }

    public static BrowserRequest of(String method, String url, List<String> headers, byte[] body,
                                    boolean isolateCookies, String browserId) {
        if (method == null || method.trim().isEmpty()) {
            throw new IllegalArgumentException("browser request method is empty");
        }
        if (url == null || url.trim().isEmpty()) {
            throw new IllegalArgumentException("browser request url is empty");
        }
        return new BrowserRequest(method, url, headers, body, isolateCookies, browserId);
    }

    private static String normalizeBrowserId(String browserId) {
        String normalized = browserId == null ? "" : browserId.trim();
        return normalized.isEmpty() ? DEFAULT_BROWSER_ID : normalized;
    }

    public String getMethod() {
        return method;
    }

    public String getUrl() {
        return url;
    }

    public String getBrowserId() {
        return browserId;
    }

    public List<String> getHeaders() {
        return headers;
    }

    @Override
    public byte[] body() {
        return body.clone();
    }

    public byte[] getBody() {
        return body.clone();
    }
}
