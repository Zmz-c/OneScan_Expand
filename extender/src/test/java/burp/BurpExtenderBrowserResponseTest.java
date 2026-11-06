package burp;

import burp.vaycore.ost.browser.BrowserRequestManager.BrowserResult;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.Assert.*;

public class BurpExtenderBrowserResponseTest {
    private byte[] build(BrowserResult result) throws Exception {
        var method = BurpExtender.class.getDeclaredMethod("buildBrowserResponseBytes", BrowserResult.class);
        method.setAccessible(true);
        return (byte[]) method.invoke(new BurpExtender(), result);
    }

    @Test public void finalNetworkErrorRemainsOneResponseWithExactBodyAndLength() throws Exception {
        byte[] body = "最终响应，不附加浏览器错误页".getBytes(StandardCharsets.UTF_8);
        for (int status : new int[]{401, 412, 413}) {
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("Content-Type", "text/plain; charset=UTF-8");
            headers.put("content-length", "999999");
            headers.put("Content-Encoding", "gzip");
            headers.put("Transfer-Encoding", "chunked");
            byte[] raw = build(new BrowserResult(status, "Rejected", headers, body, "", ""));
            String text = new String(raw, StandardCharsets.UTF_8);
            int offset = text.indexOf("\r\n\r\n") + 4;
            String head = text.substring(0, offset);
            assertTrue(head.startsWith("HTTP/1.1 " + status + " Rejected\r\n"));
            assertEquals(1, text.split("HTTP/1.1", -1).length - 1);
            assertEquals(1, head.toLowerCase().split("content-length:", -1).length - 1);
            assertTrue(head.contains("Content-Length: " + body.length + "\r\n"));
            assertFalse(head.toLowerCase().contains("content-encoding:"));
            assertFalse(head.toLowerCase().contains("transfer-encoding:"));
            int byteOffset = head.getBytes(StandardCharsets.UTF_8).length;
            assertArrayEquals(body, Arrays.copyOfRange(raw, byteOffset, raw.length));
        }
    }

    @Test public void unavailableBodyIsNotReplacedWithBrowserMarkup() throws Exception {
        byte[] raw = build(new BrowserResult(401, "Unauthorized",
                Map.of("X-OST-Body-Unavailable", "true"), new byte[0], "", ""));
        String text = new String(raw, StandardCharsets.UTF_8);
        assertTrue(text.startsWith("HTTP/1.1 401 Unauthorized\r\n"));
        assertTrue(text.contains("X-OST-Body-Unavailable: true\r\n"));
        assertTrue(text.endsWith("Content-Length: 0\r\n\r\n"));
    }
}
