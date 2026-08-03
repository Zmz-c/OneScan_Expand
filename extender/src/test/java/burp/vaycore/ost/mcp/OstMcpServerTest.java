package burp.vaycore.ost.mcp;

import burp.vaycore.common.utils.GsonUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class OstMcpServerTest {

    private OstMcpServer server;

    @Before
    public void setUp() throws Exception {
        server = new OstMcpServer(new OstMcpToolProvider() {
            @Override
            public List<OstMcpTool> listTools() {
                return List.of(new OstMcpTool("echo", "Echo input", Map.of("type", "object")));
            }

            @Override
            public Object callTool(String name, Map<String, Object> arguments) throws Exception {
                if ("fail".equals(name)) {
                    throw new IllegalArgumentException("expected failure");
                }
                if (!"echo".equals(name)) {
                    throw new IllegalArgumentException("Unknown tool: " + name);
                }
                return Map.of("arguments", arguments);
            }
        }, 0);
        server.start();
    }

    @After
    public void tearDown() {
        if (server != null) {
            server.stop();
        }
    }

    @Test
    public void initializesAndReturnsProtocolHeader() throws Exception {
        HttpResult result = request("POST", "/mcp", Map.of("Content-Type", "application/json"), """
                {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}
                """);

        assertEquals(200, result.status());
        assertEquals("2025-11-25", result.header("mcp-protocol-version"));
        Map<String, Object> json = GsonUtils.toMap(result.body());
        Map<String, Object> payload = map(json.get("result"));
        assertEquals("2025-11-25", payload.get("protocolVersion"));
        assertEquals("ost-burp-mcp", map(payload.get("serverInfo")).get("name"));
        assertEquals("0.1.0", map(payload.get("serverInfo")).get("version"));
    }

    @Test
    public void acceptsCaseInsensitiveJsonMediaTypesWithParameters() throws Exception {
        HttpResult result = request("POST", "/mcp",
                Map.of("Content-Type", "Application/Json; Charset=UTF-8"),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{}}");

        assertEquals(200, result.status());
        assertEquals("ok", map(GsonUtils.toMap(result.body()).get("result")).get("status"));
    }

    @Test
    public void rejectsMissingOrUnsupportedJsonMediaTypesAndAcceptHeaders() throws Exception {
        String ping = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{}}";
        HttpResult missingType = request("POST", "/mcp", Map.of(), ping);
        assertEquals(415, missingType.status());

        HttpResult unsupportedType = request("POST", "/mcp",
                Map.of("Content-Type", "text/plain"), ping);
        assertEquals(415, unsupportedType.status());

        HttpResult rejectedAccept = request("POST", "/mcp",
                Map.of("Content-Type", "application/json", "Accept", "text/event-stream"), ping);
        assertEquals(406, rejectedAccept.status());

        HttpResult acceptedWildcard = request("POST", "/mcp",
                Map.of("Content-Type", "application/json", "Accept", "application/*;q=0.5"), ping);
        assertEquals(200, acceptedWildcard.status());

        HttpResult explicitRejection = request("POST", "/mcp",
                Map.of("Content-Type", "application/json", "Accept", "*/*;q=1, application/json;q=0"), ping);
        assertEquals(406, explicitRejection.status());
    }

    @Test
    public void validatesJsonRpcStringMembersAndUsesInitializeVersionOverHeader() throws Exception {
        HttpResult numericMethod = request("POST", "/mcp", Map.of("Content-Type", "application/json"),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":1,\"params\":{}}");
        assertEquals(-32600, ((Number) map(GsonUtils.toMap(numericMethod.body()).get("error")).get("code")).intValue());

        HttpResult initialized = request("POST", "/mcp", Map.of(
                "Content-Type", "application/json", "MCP-Protocol-Version", "2025-11-25"),
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\"}}");
        assertEquals(200, initialized.status());
        assertEquals("2024-11-05", initialized.header("mcp-protocol-version"));
        assertEquals("2024-11-05", map(GsonUtils.toMap(initialized.body()).get("result")).get("protocolVersion"));
    }

    @Test
    public void rejectsNonLoopbackOriginsAndEchoesAllowedOrigin() throws Exception {
        String ping = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{}}";
        HttpResult rejected = request("POST", "/mcp", Map.of(
                "Content-Type", "application/json", "Origin", "https://attacker.example"), ping);
        assertEquals(403, rejected.status());
        assertNull(rejected.header("access-control-allow-origin"));

        String localOrigin = "http://127.0.0.1:3000";
        HttpResult allowed = request("POST", "/mcp", Map.of(
                "Content-Type", "application/json", "Origin", localOrigin), ping);
        assertEquals(200, allowed.status());
        assertEquals(localOrigin, allowed.header("access-control-allow-origin"));
        assertEquals("Origin", allowed.header("vary"));
    }

    @Test
    public void rejectsUnsupportedProtocolAndInvalidToolParameters() throws Exception {
        HttpResult unsupported = request("POST", "/mcp", Map.of("Content-Type", "application/json",
                "MCP-Protocol-Version", "2026-01-01"),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{}}");
        assertEquals(400, unsupported.status());
        assertEquals("2025-11-25", unsupported.header("mcp-protocol-version"));
        Map<String, Object> unsupportedError = map(GsonUtils.toMap(unsupported.body()).get("error"));
        assertEquals(-32602, ((Number) unsupportedError.get("code")).intValue());

        HttpResult invalidCall = request("POST", "/mcp", Map.of("Content-Type", "application/json"),
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":[]}}");
        Map<String, Object> callResult = map(GsonUtils.toMap(invalidCall.body()).get("result"));
        assertEquals(Boolean.TRUE, callResult.get("isError"));
        assertTrue(String.valueOf(map(((List<?>) callResult.get("content")).get(0)).get("text"))
                .contains("arguments must be an object"));
    }

    @Test
    public void listsToolsAndUsesCallToolResultForFailures() throws Exception {
        HttpResult listed = request("POST", "/mcp", Map.of("Content-Type", "application/json",
                "MCP-Protocol-Version", "2025-11-25"),
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}");
        assertEquals(200, listed.status());
        Map<String, Object> listPayload = map(GsonUtils.toMap(listed.body()).get("result"));
        assertEquals("echo", map(((List<?>) listPayload.get("tools")).get(0)).get("name"));

        HttpResult failed = request("POST", "/mcp", Map.of("Content-Type", "application/json"),
                "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"fail\",\"arguments\":{}}}");
        Map<String, Object> failedPayload = map(GsonUtils.toMap(failed.body()).get("result"));
        assertEquals(Boolean.TRUE, failedPayload.get("isError"));
        assertTrue(String.valueOf(map(((List<?>) failedPayload.get("content")).get(0)).get("text"))
                .contains("expected failure"));
    }

    @Test
    public void validatesJsonRpcAndAcceptsNotifications() throws Exception {
        HttpResult invalid = request("POST", "/mcp", Map.of("Content-Type", "application/json"),
                "{\"jsonrpc\":\"1.0\",\"id\":4,\"method\":\"ping\",\"params\":{}}");
        Map<String, Object> error = map(GsonUtils.toMap(invalid.body()).get("error"));
        assertEquals(-32600, ((Number) error.get("code")).intValue());

        HttpResult notification = request("POST", "/mcp", Map.of("Content-Type", "application/json"),
                "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}");
        assertEquals(202, notification.status());
        assertEquals("", notification.body());
    }

    @Test
    public void exposesHealthAndRejectsMalformedHttpBodies() throws Exception {
        HttpResult health = request("GET", "/health", Map.of(), "");
        assertEquals(200, health.status());
        assertEquals("ok", GsonUtils.toMap(health.body()).get("status"));

        URI endpoint = URI.create(server.getEndpoint());
        try (Socket socket = new Socket(endpoint.getHost(), endpoint.getPort())) {
            OutputStream output = socket.getOutputStream();
            output.write(("POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 8\r\n\r\n{}")
                    .getBytes(StandardCharsets.ISO_8859_1));
            output.flush();
            socket.shutdownOutput();
            HttpResult truncated = readResponse(socket.getInputStream());
            assertEquals(400, truncated.status());
        }
    }

    private HttpResult request(String method, String path, Map<String, String> headers, String body) throws Exception {
        URI endpoint = URI.create(server.getEndpoint());
        try (Socket socket = new Socket(endpoint.getHost(), endpoint.getPort())) {
            byte[] payload = body.getBytes(StandardCharsets.UTF_8);
            StringBuilder request = new StringBuilder();
            request.append(method).append(' ').append(path).append(" HTTP/1.1\r\n");
            request.append("Host: 127.0.0.1\r\n");
            for (Map.Entry<String, String> header : headers.entrySet()) {
                request.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
            }
            request.append("Content-Length: ").append(payload.length).append("\r\n\r\n");
            OutputStream output = socket.getOutputStream();
            output.write(request.toString().getBytes(StandardCharsets.ISO_8859_1));
            output.write(payload);
            output.flush();
            socket.shutdownOutput();
            return readResponse(socket.getInputStream());
        }
    }

    private HttpResult readResponse(InputStream input) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int read;
        while ((read = input.read(buffer)) >= 0) {
            bytes.write(buffer, 0, read);
        }
        String raw = bytes.toString(StandardCharsets.UTF_8);
        int separator = raw.indexOf("\r\n\r\n");
        String head = raw.substring(0, separator);
        String body = raw.substring(separator + 4);
        String[] lines = head.split("\r\n");
        int status = Integer.parseInt(lines[0].split(" ")[1]);
        java.util.LinkedHashMap<String, String> headers = new java.util.LinkedHashMap<>();
        for (int index = 1; index < lines.length; index++) {
            int colon = lines[index].indexOf(':');
            if (colon > 0) {
                headers.put(lines[index].substring(0, colon).toLowerCase(), lines[index].substring(colon + 1).trim());
            }
        }
        return new HttpResult(status, headers, body);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object value) {
        return (Map<String, Object>) value;
    }

    private record HttpResult(int status, Map<String, String> headers, String body) {
        String header(String name) {
            return headers.get(name);
        }
    }
}
