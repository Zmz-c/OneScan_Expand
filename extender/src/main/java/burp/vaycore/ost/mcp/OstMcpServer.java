package burp.vaycore.ost.mcp;

import burp.vaycore.common.utils.GsonUtils;
import com.google.gson.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class OstMcpServer {

    public static final int DEFAULT_PORT = 8765;
    private static final String JSON_RPC_VERSION = "2.0";
    private static final String SERVER_NAME = "ost-burp-mcp";
    private static final String SERVER_VERSION = "0.1.0";
    private static final int MAX_HEADER_BYTES = 64 * 1024;
    private static final int MAX_BODY_BYTES = 50 * 1024 * 1024;

    private final OstMcpToolProvider toolProvider;
    private ServerSocket serverSocket;
    private ExecutorService executor;
    private Thread acceptThread;
    private volatile boolean running;
    private int port;

    public OstMcpServer(OstMcpToolProvider toolProvider) {
        if (toolProvider == null) {
            throw new IllegalArgumentException("toolProvider is null");
        }
        this.toolProvider = toolProvider;
    }

    private static HttpRequest readRequest(InputStream input) throws IOException {
        byte[] headerBytes = readHeaderBytes(input);
        String header = new String(headerBytes, StandardCharsets.ISO_8859_1);
        String[] lines = header.split("\\r?\\n");
        if (lines.length == 0 || lines[0].trim().isEmpty()) {
            throw new IOException("empty request");
        }
        String[] requestLine = lines[0].split("\\s+", 3);
        if (requestLine.length < 2) {
            throw new IOException("invalid request line");
        }
        LinkedHashMap<String, String> headers = new LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            int colon = line.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            headers.put(line.substring(0, colon).trim().toLowerCase(Locale.ROOT), line.substring(colon + 1).trim());
        }
        int contentLength = parseContentLength(headers.get("content-length"));
        if (contentLength > MAX_BODY_BYTES) {
            throw new IOException("request body too large");
        }
        byte[] bodyBytes = contentLength <= 0 ? new byte[0] : input.readNBytes(contentLength);
        String body = new String(bodyBytes, StandardCharsets.UTF_8);
        return new HttpRequest(requestLine[0], requestLine[1], headers, body);
    }

    private static byte[] readHeaderBytes(InputStream input) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] delimiter = new byte[]{'\r', '\n', '\r', '\n'};
        int matched = 0;
        while (buffer.size() < MAX_HEADER_BYTES) {
            int value = input.read();
            if (value < 0) {
                throw new IOException("unexpected end of stream");
            }
            buffer.write(value);
            if ((byte) value == delimiter[matched]) {
                matched++;
                if (matched == delimiter.length) {
                    return buffer.toByteArray();
                }
            } else {
                matched = (byte) value == delimiter[0] ? 1 : 0;
            }
        }
        throw new IOException("request header too large");
    }

    private static int parseContentLength(String value) {
        if (value == null || value.isEmpty()) {
            return 0;
        }
        try {
            return Math.max(0, Integer.parseInt(value));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static void writeResponse(OutputStream output, HttpResponse response) throws IOException {
        byte[] body = response.body();
        StringBuilder header = new StringBuilder();
        header.append("HTTP/1.1 ").append(response.status()).append(" ").append(reasonPhrase(response.status()))
                .append("\r\n");
        header.append("Content-Type: application/json; charset=utf-8\r\n");
        header.append("Content-Length: ").append(body.length).append("\r\n");
        header.append("Connection: close\r\n");
        header.append("Access-Control-Allow-Origin: http://127.0.0.1\r\n");
        header.append("Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n");
        header.append("Access-Control-Allow-Headers: Content-Type\r\n");
        header.append("\r\n");
        output.write(header.toString().getBytes(StandardCharsets.ISO_8859_1));
        output.write(body);
        output.flush();
    }

    private static HttpResponse jsonResponse(int statusCode, Object body) {
        byte[] bytes = body == null || "".equals(body)
                ? new byte[0]
                : GsonUtils.toJson(body).getBytes(StandardCharsets.UTF_8);
        return new HttpResponse(statusCode, bytes);
    }

    private static String reasonPhrase(int statusCode) {
        return switch (statusCode) {
            case 200 -> "OK";
            case 204 -> "No Content";
            case 400 -> "Bad Request";
            case 404 -> "Not Found";
            case 405 -> "Method Not Allowed";
            case 500 -> "Internal Server Error";
            default -> "OK";
        };
    }

    private static Map<String, Object> rpcResult(Object id, Object result) {
        return mapOf("jsonrpc", JSON_RPC_VERSION, "id", id, "result", result);
    }

    private static Map<String, Object> rpcError(Object id, int code, String message) {
        return mapOf(
                "jsonrpc", JSON_RPC_VERSION,
                "id", id,
                "error", mapOf("code", code, "message", message == null ? "" : message)
        );
    }

    private static String stringArg(Map<String, Object> map, String key) {
        if (map == null) {
            return null;
        }
        Object value = map.get(key);
        return value == null ? null : String.valueOf(value);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mapArg(Map<String, Object> map, String key) {
        if (map == null) {
            return new LinkedHashMap<>();
        }
        Object value = map.get(key);
        if (value instanceof Map<?, ?> rawMap) {
            return (Map<String, Object>) rawMap;
        }
        return new LinkedHashMap<>();
    }

    private static String stringValue(JsonElement element) {
        if (element == null || element.isJsonNull()) {
            return null;
        }
        return element.getAsString();
    }

    private static Object jsonValue(JsonElement element) {
        if (element == null || element.isJsonNull()) {
            return null;
        }
        if (element instanceof JsonPrimitive primitive) {
            if (primitive.isString()) {
                return primitive.getAsString();
            }
            if (primitive.isBoolean()) {
                return primitive.getAsBoolean();
            }
            if (primitive.isNumber()) {
                Number number = primitive.getAsNumber();
                double doubleValue = number.doubleValue();
                long longValue = number.longValue();
                if (doubleValue == longValue) {
                    return longValue;
                }
                return doubleValue;
            }
        }
        if (element instanceof JsonNull) {
            return null;
        }
        return GsonUtils.toObject(element.toString(), Object.class);
    }

    private static Map<String, Object> mapOf(Object... values) {
        LinkedHashMap<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i + 1 < values.length; i += 2) {
            map.put(String.valueOf(values[i]), values[i + 1]);
        }
        return map;
    }

    private static void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public synchronized void start() throws IOException {
        if (serverSocket != null) {
            return;
        }
        IOException lastException = null;
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        for (int candidate = DEFAULT_PORT; candidate <= DEFAULT_PORT + 20; candidate++) {
            try {
                ServerSocket socket = new ServerSocket();
                socket.setReuseAddress(true);
                socket.bind(new InetSocketAddress(loopback, candidate), 50);
                serverSocket = socket;
                port = candidate;
                break;
            } catch (IOException e) {
                lastException = e;
            }
        }
        if (serverSocket == null) {
            throw lastException == null ? new IOException("MCP server failed to bind") : lastException;
        }
        executor = Executors.newCachedThreadPool(r -> {
            Thread thread = new Thread(r, "OST-mcp");
            thread.setDaemon(true);
            return thread;
        });
        running = true;
        acceptThread = new Thread(this::acceptLoop, "OST-mcp-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    public synchronized void stop() {
        running = false;
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException ignored) {
                // ignored
            }
            serverSocket = null;
        }
        if (acceptThread != null) {
            acceptThread.interrupt();
            acceptThread = null;
        }
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }
    }

    public String getEndpoint() {
        if (port <= 0) {
            return "";
        }
        return "http://127.0.0.1:" + port + "/mcp";
    }

    private void acceptLoop() {
        while (running && serverSocket != null && !serverSocket.isClosed()) {
            try {
                Socket socket = serverSocket.accept();
                ExecutorService currentExecutor = executor;
                if (currentExecutor != null) {
                    currentExecutor.execute(() -> handleSocket(socket));
                } else {
                    socket.close();
                }
            } catch (IOException e) {
                if (running) {
                    sleepQuietly(100);
                }
            }
        }
    }

    private void handleSocket(Socket socket) {
        try (Socket closeableSocket = socket) {
            closeableSocket.setSoTimeout(30000);
            HttpRequest request = readRequest(closeableSocket.getInputStream());
            HttpResponse response = handleHttpRequest(request);
            writeResponse(closeableSocket.getOutputStream(), response);
        } catch (Exception e) {
            try {
                writeResponse(socket.getOutputStream(),
                        jsonResponse(500, mapOf("error", e.getMessage() == null ? "server error" : e.getMessage())));
            } catch (Exception ignored) {
                // ignored
            }
        }
    }

    private HttpResponse handleHttpRequest(HttpRequest request) {
        String path = request.path();
        int queryIndex = path.indexOf('?');
        if (queryIndex >= 0) {
            path = path.substring(0, queryIndex);
        }
        if ("/health".equals(path)) {
            return handleHealth(request);
        }
        if ("/mcp".equals(path)) {
            return handleMcp(request);
        }
        return jsonResponse(404, mapOf("error", "not found"));
    }

    private HttpResponse handleHealth(HttpRequest request) {
        if (!"GET".equalsIgnoreCase(request.method())) {
            return jsonResponse(405, mapOf("error", "method not allowed"));
        }
        return jsonResponse(200, mapOf("status", "ok", "endpoint", getEndpoint()));
    }

    private HttpResponse handleMcp(HttpRequest request) {
        if ("OPTIONS".equalsIgnoreCase(request.method())) {
            return jsonResponse(204, "");
        }
        if (!"POST".equalsIgnoreCase(request.method())) {
            return jsonResponse(405, rpcError(null, -32600, "Only POST is supported"));
        }
        try {
            JsonElement root = JsonParser.parseString(request.body());
            if (root.isJsonArray()) {
                List<Object> responses = new ArrayList<>();
                for (JsonElement item : root.getAsJsonArray()) {
                    Object response = handleRpcObject(item);
                    if (response != null) {
                        responses.add(response);
                    }
                }
                return jsonResponse(200, responses);
            }
            Object response = handleRpcObject(root);
            if (response == null) {
                return jsonResponse(204, "");
            }
            return jsonResponse(200, response);
        } catch (Exception e) {
            return jsonResponse(200, rpcError(null, -32700, "Parse error: " + e.getMessage()));
        }
    }

    private Object handleRpcObject(JsonElement item) {
        if (item == null || !item.isJsonObject()) {
            return rpcError(null, -32600, "Invalid Request");
        }
        JsonObject request = item.getAsJsonObject();
        Object id = jsonValue(request.get("id"));
        String method = stringValue(request.get("method"));
        if (method == null || method.isEmpty()) {
            return rpcError(id, -32600, "Invalid Request");
        }
        try {
            Object result = switch (method) {
                case "initialize" -> initializeResult();
                case "initialized", "notifications/initialized" -> mapOf();
                case "ping" -> mapOf("status", "ok");
                case "tools/list" -> toolsListResult();
                case "tools/call" -> toolsCallResult(request.get("params"));
                default -> {
                    if (id == null) {
                        yield null;
                    }
                    yield rpcError(id, -32601, "Method not found: " + method);
                }
            };
            if (id == null) {
                return null;
            }
            return rpcResult(id, result);
        } catch (Exception e) {
            if (id == null) {
                return null;
            }
            return rpcError(id, -32000, e.getMessage());
        }
    }

    private Map<String, Object> initializeResult() {
        return mapOf(
                "protocolVersion", "2024-11-05",
                "capabilities", mapOf("tools", mapOf()),
                "serverInfo", mapOf("name", SERVER_NAME, "version", SERVER_VERSION)
        );
    }

    private Map<String, Object> toolsListResult() {
        return mapOf("tools", toolProvider.listTools());
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> toolsCallResult(JsonElement paramsElement) throws Exception {
        Map<String, Object> params = paramsElement == null || paramsElement.isJsonNull()
                ? new LinkedHashMap<>()
                : (Map<String, Object>) GsonUtils.toObject(paramsElement.toString(), Object.class);
        String name = stringArg(params, "name");
        Map<String, Object> arguments = mapArg(params, "arguments");
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("tools/call requires params.name");
        }
        Object result = toolProvider.callTool(name, arguments);
        return mapOf(
                "content", List.of(mapOf("type", "text", "text", GsonUtils.toJson(result))),
                "structuredContent", result,
                "isError", false
        );
    }

    private record HttpRequest(String method, String path, Map<String, String> headers, String body) {
    }

    private record HttpResponse(int status, byte[] body) {
    }
}
