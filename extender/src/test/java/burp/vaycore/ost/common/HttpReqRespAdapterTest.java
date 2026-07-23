package burp.vaycore.ost.common;

import burp.IHttpService;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class HttpReqRespAdapterTest {

    private static final IHttpService REDIRECT_SERVICE = new IHttpService() {
        public String getHost() {
            return "redirect.test";
        }

        public int getPort() {
            return 443;
        }

        public String getProtocol() {
            return "https";
        }
    };

    @Test
    public void preservesMethodAndBinaryBodyFor307AndMergesCookies() {
        byte[] body = new byte[]{0, 1, (byte) 0xff};
        byte[] original = request(
                "POST /old HTTP/1.1\r\n"
                        + "host: old.test\r\n"
                        + "content-type: application/octet-stream\r\n"
                        + "content-length: 3\r\n"
                        + "cookie: sid=old; token=a=b==\r\n\r\n",
                body);

        HttpReqRespAdapter redirected = HttpReqRespAdapter.followRedirect(
                REDIRECT_SERVICE, "/next", original, List.of("sid=new=="), 307);

        String headers = headers(redirected.getRequest());
        assertTrue(headers.startsWith("POST /next HTTP/1.1\r\n"));
        assertTrue(headers.contains("Host: redirect.test\r\n"));
        assertTrue(headers.contains("Cookie: sid=new==; token=a=b=="));
        assertArrayEquals(body, body(redirected.getRequest()));
    }

    @Test
    public void rewritesPostToBodylessGetFor302() {
        byte[] original = request(
                "POST /old HTTP/1.1\r\n"
                        + "Host: old.test\r\n"
                        + "Content-Type: application/json\r\n"
                        + "Content-Length: 7\r\n\r\n",
                "{\"a\":1}".getBytes(StandardCharsets.UTF_8));

        HttpReqRespAdapter redirected = HttpReqRespAdapter.followRedirect(
                REDIRECT_SERVICE, "/next", original, null, 302);

        String headers = headers(redirected.getRequest());
        assertTrue(headers.startsWith("GET /next HTTP/1.1\r\n"));
        assertFalse(headers.toLowerCase().contains("content-length:"));
        assertArrayEquals(new byte[0], body(redirected.getRequest()));
    }

    @Test
    public void addsRedirectCookiesWhenOriginalRequestOnlyHasHostHeader() {
        HttpReqRespAdapter redirected = HttpReqRespAdapter.from(
                REDIRECT_SERVICE, "/next",
                List.of("GET /old HTTP/1.1", "Host: old.test"), List.of("sid=new=="));

        String headers = headers(redirected.getRequest());
        assertTrue(headers.contains("Cookie: sid=new=="));
    }

    @Test
    public void neverSendsUrlFragmentsInRequestTargets() {
        HttpReqRespAdapter direct = HttpReqRespAdapter.from(
                "https://redirect.test/path?q=1#client-only");
        assertTrue(headers(direct.getRequest()).startsWith("GET /path?q=1 HTTP/1.1\r\n"));
        assertFalse(headers(direct.getRequest()).contains("#client-only"));

        HttpReqRespAdapter redirected = HttpReqRespAdapter.followRedirect(
                REDIRECT_SERVICE, "/next#client-only",
                "GET /old HTTP/1.1\r\nHost: old.test\r\n\r\n"
                        .getBytes(StandardCharsets.ISO_8859_1), null, 302);
        assertTrue(headers(redirected.getRequest()).startsWith("GET /next HTTP/1.1\r\n"));
        assertFalse(headers(redirected.getRequest()).contains("#client-only"));
    }

    private static byte[] request(String headers, byte[] body) {
        byte[] headerBytes = headers.getBytes(StandardCharsets.ISO_8859_1);
        byte[] result = Arrays.copyOf(headerBytes, headerBytes.length + body.length);
        System.arraycopy(body, 0, result, headerBytes.length, body.length);
        return result;
    }

    private static String headers(byte[] request) {
        int separator = separator(request);
        return new String(request, 0, separator, StandardCharsets.ISO_8859_1);
    }

    private static byte[] body(byte[] request) {
        int separator = separator(request);
        return Arrays.copyOfRange(request, separator + 4, request.length);
    }

    private static int separator(byte[] request) {
        for (int i = 0; i <= request.length - 4; i++) {
            if (request[i] == '\r' && request[i + 1] == '\n'
                    && request[i + 2] == '\r' && request[i + 3] == '\n') {
                return i;
            }
        }
        throw new AssertionError("request has no header separator");
    }
}