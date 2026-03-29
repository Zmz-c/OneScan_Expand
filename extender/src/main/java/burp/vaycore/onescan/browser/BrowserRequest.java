package burp.vaycore.onescan.browser;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class BrowserRequest {

    private final String method;
    private final String url;
    private final List<String> headers;
    private final byte[] body;

    private BrowserRequest(String method, String url, List<String> headers, byte[] body) {
        this.method = method == null ? "" : method.trim().toUpperCase();
        this.url = url == null ? "" : url.trim();
        this.headers = Collections.unmodifiableList(new ArrayList<String>(headers == null
                ? Collections.<String>emptyList() : headers));
        this.body = body == null ? new byte[0] : body.clone();
    }

    public static BrowserRequest of(String method, String url, List<String> headers, byte[] body) {
        if (method == null || method.trim().isEmpty()) {
            throw new IllegalArgumentException("browser request method is empty");
        }
        if (url == null || url.trim().isEmpty()) {
            throw new IllegalArgumentException("browser request url is empty");
        }
        return new BrowserRequest(method, url, headers, body);
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

    public byte[] getBody() {
        return body.clone();
    }
}
