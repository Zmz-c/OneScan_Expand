package burp.zm.mcp;

import com.google.gson.Gson;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class McpServerTest {

    private static final Gson GSON = new Gson();
    private McpServer server;

    @Before
    public void setUp() throws Exception {
        server = new McpServer(new McpToolProvider() {
            @Override
            public List<McpTool> listTools() {
                return List.of(new McpTool("echo", "Echo input", Map.of(
                        "type", "object",
                        "required", List.of("value"),
                        "properties", Map.of("value", Map.of("type", "string")))));
            }

            @Override
            public Object callTool(String name, Map<String, Object> arguments) {
                if (!"echo".equals(name)) {
                    throw new IllegalArgumentException("unknown tool");
                }
                return Map.of("arguments", arguments);
            }
        }, "test-mcp", "1.0.0", 0);
        server.start();
    }

    @After
    public void tearDown() {
        server.stop();
    }

    @Test
    public void servesInitializeAndToolCalls() throws Exception {
        HttpResult initialize = request("POST", "/mcp",
                Map.of("Content-Type", "application/json"),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\","
                        + "\"params\":{\"protocolVersion\":\"2025-11-25\"}}");
        assertEquals(200, initialize.status());
        assertEquals("2025-11-25", initialize.header("mcp-protocol-version"));
        Map<?, ?> initResult = map(map(initialize.json()).get("result"));
        assertEquals("test-mcp", map(initResult.get("serverInfo")).get("name"));

        HttpResult call = request("POST", "/mcp",
                Map.of("Content-Type", "application/json"),
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\","
                        + "\"params\":{\"name\":\"echo\",\"arguments\":{\"value\":\"ok\"}}}");
        Map<?, ?> callResult = map(map(call.json()).get("result"));
        assertEquals(Boolean.FALSE, callResult.get("isError"));
        assertTrue(String.valueOf(map(callResult.get("structuredContent")).get("arguments"))
                .contains("value=ok"));
    }

    @Test
    public void enforcesLoopbackOriginAndJsonContentType() throws Exception {
        String ping = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{}}";
        HttpResult origin = request("POST", "/mcp",
                Map.of("Content-Type", "application/json", "Origin", "https://attacker.example"), ping);
        assertEquals(403, origin.status());

        HttpResult contentType = request("POST", "/mcp", Map.of("Content-Type", "text/plain"), ping);
        assertEquals(415, contentType.status());
    }

    @Test
    public void createsValidatesAndClosesSession() throws Exception {
        HttpResult initialize = request("POST", "/mcp",
                Map.of("Content-Type", "application/json"),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\","
                        + "\"params\":{\"protocolVersion\":\"2025-11-25\"}}");
        assertEquals(200, initialize.status());
        String sessionId = initialize.header("mcp-session-id");
        assertNotNull(sessionId);
        assertTrue(sessionId.length() >= 20);

        Map<String, String> sessionHeaders = Map.of(
                "Content-Type", "application/json",
                "MCP-Protocol-Version", "2025-11-25",
                "Mcp-Session-Id", sessionId);
        HttpResult beforeInitialized = request("POST", "/mcp", sessionHeaders,
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}");
        assertEquals(-32600, ((Number) map(beforeInitialized.json().get("error")).get("code")).intValue());

        HttpResult initialized = request("POST", "/mcp", sessionHeaders,
                "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}");
        assertEquals(202, initialized.status());
        assertEquals(sessionId, initialized.header("mcp-session-id"));

        HttpResult invalidArguments = request("POST", "/mcp", sessionHeaders,
                "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\","
                        + "\"params\":{\"name\":\"echo\",\"arguments\":{\"value\":1}}}");
        Map<?, ?> invalidResult = map(map(invalidArguments.json()).get("result"));
        assertEquals(Boolean.TRUE, invalidResult.get("isError"));
        assertTrue(String.valueOf(map(((List<?>) invalidResult.get("content")).get(0)).get("text"))
                .contains("$.value must be a string"));

        HttpResult deleted = request("DELETE", "/mcp",
                Map.of("Mcp-Session-Id", sessionId), "");
        assertEquals(204, deleted.status());
        assertEquals("", deleted.body());

        HttpResult afterDelete = request("POST", "/mcp", sessionHeaders,
                "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\",\"params\":{}}");
        assertEquals(404, afterDelete.status());
    }

    @Test
    public void rejectsUnknownSessionAndProtocolMismatch() throws Exception {
        String ping = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{}}";
        HttpResult unknown = request("POST", "/mcp", Map.of(
                "Content-Type", "application/json", "Mcp-Session-Id", "missing-session"), ping);
        assertEquals(404, unknown.status());

        HttpResult initialize = request("POST", "/mcp", Map.of("Content-Type", "application/json"),
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"initialize\","
                        + "\"params\":{\"protocolVersion\":\"2024-11-05\"}}");
        String sessionId = initialize.header("mcp-session-id");
        HttpResult mismatch = request("POST", "/mcp", Map.of(
                "Content-Type", "application/json",
                "Mcp-Session-Id", sessionId,
                "MCP-Protocol-Version", "2025-11-25"), ping);
        assertEquals(400, mismatch.status());
    }

    @Test
    public void servesOfflineSwaggerUiAndRejectsTraversal() throws Exception {
        HttpResult index = request("GET", "/docs/", Map.of(), "");
        assertEquals(200, index.status());
        assertTrue(index.header("content-type").startsWith("text/html"));
        assertTrue(index.body().contains("Offline documentation"));
        assertTrue(index.body().contains("swagger-ui-bundle.js"));

        HttpResult specification = request("GET", "/docs/openapi.yaml", Map.of(), "");
        assertEquals(200, specification.status());
        assertTrue(specification.header("content-type").startsWith("text/yaml"));
        assertTrue(specification.body().contains("openapi: 3.1.0"));

        HttpResult traversal = request("GET", "/docs/../openapi.yaml", Map.of(), "");
        assertEquals(400, traversal.status());
    }

    @Test
    public void joinsExistingHostAndForwardsProviderCalls() throws Exception {
        int sharedPort;
        try (ServerSocket probe = new ServerSocket(0)) {
            sharedPort = probe.getLocalPort();
        }
        McpServer host = new McpServer(new McpToolProvider() {
            @Override
            public List<McpTool> listTools() {
                return List.of(new McpTool("host.status", "Host status", Map.of("type", "object")));
            }

            @Override
            public Object callTool(String name, Map<String, Object> arguments) {
                return Map.of("owner", "host");
            }
        }, "host", "1.0.0", sharedPort);
        McpServer client = new McpServer(new McpToolProvider() {
            @Override
            public List<McpTool> listTools() {
                return List.of(new McpTool("remote.echo", "Remote echo", Map.of(
                        "type", "object", "properties", Map.of("value", Map.of("type", "string")))));
            }

            @Override
            public Object callTool(String name, Map<String, Object> arguments) {
                return Map.of("owner", "client", "arguments", arguments);
            }
        }, "client", "1.0.0", sharedPort);
        host.start();
        try {
            client.start();
            assertEquals(McpServer.Role.HOST, host.getRole());
            assertEquals(McpServer.Role.CLIENT, client.getRole());
            long deadline = System.currentTimeMillis() + 2000;
            HttpResult list;
            do {
                list = requestAt(URI.create(host.getEndpoint()), "POST", "/mcp",
                        Map.of("Content-Type", "application/json"),
                        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}");
                if (list.body().contains("remote.echo")) {
                    break;
                }
                Thread.sleep(20);
            } while (System.currentTimeMillis() < deadline);
            assertTrue(list.body().contains("host.status"));
            assertTrue(list.body().contains("remote.echo"));

            HttpResult call = requestAt(URI.create(host.getEndpoint()), "POST", "/mcp",
                    Map.of("Content-Type", "application/json"),
                    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\","
                            + "\"params\":{\"name\":\"remote.echo\",\"arguments\":{\"value\":\"ok\"}}}");
            assertTrue(call.body().contains("\"owner\":\"client\""));
        } finally {
            client.stop();
            host.stop();
        }
    }

    private HttpResult request(String method, String path, Map<String, String> headers, String body) throws Exception {
        return requestAt(URI.create(server.getEndpoint()), method, path, headers, body);
    }

    private HttpResult requestAt(URI endpoint, String method, String path,
                                 Map<String, String> headers, String body) throws Exception {
        try (Socket socket = new Socket(endpoint.getHost(), endpoint.getPort())) {
            byte[] payload = body.getBytes(StandardCharsets.UTF_8);
            StringBuilder request = new StringBuilder(method).append(' ').append(path)
                    .append(" HTTP/1.1\r\nHost: 127.0.0.1\r\n");
            headers.forEach((name, value) -> request.append(name).append(": ").append(value).append("\r\n"));
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
        String[] lines = raw.substring(0, separator).split("\r\n");
        int status = Integer.parseInt(lines[0].split(" ")[1]);
        java.util.LinkedHashMap<String, String> headers = new java.util.LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon > 0) {
                headers.put(lines[i].substring(0, colon).toLowerCase(), lines[i].substring(colon + 1).trim());
            }
        }
        return new HttpResult(status, headers, raw.substring(separator + 4));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object value) {
        return (Map<String, Object>) value;
    }

    private record HttpResult(int status, Map<String, String> headers, String body) {
        String header(String name) {
            return headers.get(name.toLowerCase());
        }

        Map<String, Object> json() {
            return GSON.fromJson(body, Map.class);
        }
    }
}
