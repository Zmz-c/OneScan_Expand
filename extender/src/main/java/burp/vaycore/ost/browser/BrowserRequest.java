package burp.vaycore.ost.browser;

import java.util.List;

public record BrowserRequest(String method, String url, List<String> headers, byte[] body, boolean isolateCookies) {

    public BrowserRequest {
        method = method == null ? "" : method.trim().toUpperCase();
        url = url == null ? "" : url.trim();
        headers = List.copyOf(headers == null ? List.of() : headers);
        body = body == null ? new byte[0] : body.clone();
    }

    public static BrowserRequest of(String method, String url, List<String> headers, byte[] body) {
        return of(method, url, headers, body, false);
    }

    public static BrowserRequest of(String method, String url, List<String> headers, byte[] body,
                                    boolean isolateCookies) {
        if (method == null || method.trim().isEmpty()) {
            throw new IllegalArgumentException("browser request method is empty");
        }
        if (url == null || url.trim().isEmpty()) {
            throw new IllegalArgumentException("browser request url is empty");
        }
        return new BrowserRequest(method, url, headers, body, isolateCookies);
    }

    public String getMethod() {
        return method;
    }

    public String getUrl() {
        return url;
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
