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
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class OstMcpServer {

    public static final int DEFAULT_PORT = 8765;
    private static final String JSON_RPC_VERSION = "2.0";
    private static final String SERVER_NAME = "ost-burp-mcp";
    private static final String DEFAULT_SERVER_VERSION = "0.1.0";
    public static final String CURRENT_PROTOCOL_VERSION = "2025-11-25";
    private static final Set<String> SUPPORTED_PROTOCOL_VERSIONS = Set.of(
            "2024-11-05", "2025-03-26", "2025-06-18", CURRENT_PROTOCOL_VERSION);
    private static final int MAX_HEADER_BYTES = 64 * 1024;
    private static final int MAX_BODY_BYTES = 50 * 1024 * 1024;

    private final OstMcpToolProvider toolProvider;
    private final String serverVersion;
    private final int firstPort;
    private final int lastPort;
    private ServerSocket serverSocket;
    private ExecutorService executor;
    private Thread acceptThread;
    private volatile boolean running;
    private int port;

    public OstMcpServer(OstMcpToolProvider toolProvider) {
        this(toolProvider, DEFAULT_SERVER_VERSION);
    }

    public OstMcpServer(OstMcpToolProvider toolProvider, String serverVersion) {
        this(toolProvider, serverVersion, DEFAULT_PORT, DEFAULT_PORT + 20);
    }

    OstMcpServer(OstMcpToolProvider toolProvider, int port) {
        this(toolProvider, DEFAULT_SERVER_VERSION, port, port);
    }

    private OstMcpServer(OstMcpToolProvider toolProvider, String serverVersion, int firstPort, int lastPort) {
        if (toolProvider == null) {
            throw new IllegalArgumentException("toolProvider is null");
        }
        this.toolProvider = toolProvider;
        if (firstPort < 0 || lastPort < firstPort || lastPort > 65535) {
            throw new IllegalArgumentException("invalid MCP port range");
        }
        this.serverVersion = serverVersion == null || serverVersion.isBlank()
                ? DEFAULT_SERVER_VERSION : serverVersion;
        this.firstPort = firstPort;
        this.lastPort = lastPort;
    }

    private static HttpRequest readRequest(InputStream input) throws IOException {
        byte[] headerBytes = readHeaderBytes(input);
        String header = new String(headerBytes, StandardCharsets.ISO_8859_1);
        String[] lines = header.split("\\r?\\n");
        if (lines.length == 0 || lines[0].trim().isEmpty()) {
            throw new HttpParseException(400, "empty request");
        }
        String[] requestLine = lines[0].split("\\s+", 3);
        if (requestLine.length != 3 || !requestLine[2].startsWith("HTTP/")) {
            throw new HttpParseException(400, "invalid request line");
        }
        LinkedHashMap<String, String> headers = new LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            int colon = line.indexOf(':');
            if (colon <= 0) {
                throw new HttpParseException(400, "invalid request header");
            }
            String name = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
            if (name.isEmpty() || headers.putIfAbsent(name, line.substring(colon + 1).trim()) != null) {
                throw new HttpParseException(400, "duplicate or invalid request header");
            }
        }
        if (headers.containsKey("transfer-encoding")) {
            throw new HttpParseException(400, "chunked request bodies are not supported");
        }
        int contentLength = parseContentLength(headers.get("content-length"));
        if (contentLength > MAX_BODY_BYTES) {
            throw new HttpParseException(413, "request body too large");
        }
        byte[] bodyBytes = contentLength <= 0 ? new byte[0] : input.readNBytes(contentLength);
        if (bodyBytes.length != contentLength) {
            throw new HttpParseException(400, "unexpected end of request body");
        }
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
                throw new HttpParseException(400, "unexpected end of stream");
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
        throw new HttpParseException(413, "request header too large");
    }

    private static int parseContentLength(String value) throws IOException {
        if (value == null || value.isEmpty()) {
            return 0;
        }
        if (!value.matches("[0-9]+")) {
            throw new HttpParseException(400, "invalid content length");
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new HttpParseException(400, "invalid content length", e);
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
        header.append("Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n");
        header.append("Access-Control-Allow-Headers: Content-Type, Accept, MCP-Protocol-Version\r\n");
        header.append("Access-Control-Expose-Headers: MCP-Protocol-Version\r\n");
        for (Map.Entry<String, String> item : response.headers().entrySet()) {
            header.append(item.getKey()).append(": ").append(item.getValue()).append("\r\n");
        }
        header.append("\r\n");
        output.write(header.toString().getBytes(StandardCharsets.ISO_8859_1));
        output.write(body);
        output.flush();
    }

    private static HttpResponse jsonResponse(int statusCode, Object body) {
        byte[] bytes = body == null || "".equals(body)
                ? new byte[0]
                : GsonUtils.toJson(body).getBytes(StandardCharsets.UTF_8);
        return new HttpResponse(statusCode, bytes, new LinkedHashMap<>());
    }

    private static HttpResponse mcpResponse(int statusCode, Object body, String protocolVersion) {
        HttpResponse response = jsonResponse(statusCode, body);
        if (protocolVersion != null && !protocolVersion.isBlank()) {
            response.headers().put("MCP-Protocol-Version", protocolVersion);
        }
        return response;
    }

    private static String reasonPhrase(int statusCode) {
        return switch (statusCode) {
            case 200 -> "OK";
            case 202 -> "Accepted";
            case 204 -> "No Content";
            case 400 -> "Bad Request";
            case 403 -> "Forbidden";
            case 404 -> "Not Found";
            case 405 -> "Method Not Allowed";
            case 406 -> "Not Acceptable";
            case 413 -> "Payload Too Large";
            case 415 -> "Unsupported Media Type";
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
        if (map == null || !(map.get(key) instanceof String value)) {
            return null;
        }
        return value;
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
        if (!(element instanceof JsonPrimitive primitive) || !primitive.isString()) {
            return null;
        }
        return primitive.getAsString();
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
        for (int candidate = firstPort; candidate <= lastPort; candidate++) {
            try {
                ServerSocket socket = new ServerSocket();
                socket.setReuseAddress(true);
                socket.bind(new InetSocketAddress(loopback, candidate), 50);
                serverSocket = socket;
                port = socket.getLocalPort();
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
            HttpResponse response;
            try {
                HttpRequest request = readRequest(closeableSocket.getInputStream());
                response = handleHttpRequest(request);
                applyCorsHeaders(request, response);
            } catch (HttpParseException e) {
                response = jsonResponse(e.statusCode(), mapOf("error", e.getMessage()));
            } catch (IOException e) {
                response = jsonResponse(400, mapOf("error", "invalid HTTP request"));
            } catch (Exception e) {
                response = jsonResponse(500, mapOf("error", "server error"));
            }
            writeResponse(closeableSocket.getOutputStream(), response);
        } catch (Exception ignored) {
            // The peer may close before an error response can be written.
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
        if (!isAllowedOrigin(request.headers().get("origin"))) {
            return jsonResponse(403, mapOf("error", "origin not allowed"));
        }
        if (!"GET".equalsIgnoreCase(request.method())) {
            return jsonResponse(405, mapOf("error", "method not allowed"));
        }
        return jsonResponse(200, mapOf("status", "ok", "endpoint", getEndpoint()));
    }

    private HttpResponse handleMcp(HttpRequest request) {
        String headerProtocolVersion = protocolVersionFromHeader(request);
        if (!isAllowedOrigin(request.headers().get("origin"))) {
            return mcpResponse(403, rpcError(null, -32600, "Origin is not allowed"), headerProtocolVersion);
        }
        if ("OPTIONS".equalsIgnoreCase(request.method())) {
            return mcpResponse(204, "", headerProtocolVersion);
        }
        if (!"POST".equalsIgnoreCase(request.method())) {
            return mcpResponse(405, rpcError(null, -32600, "Only POST is supported"), headerProtocolVersion);
        }
        if (!acceptsJsonResponse(request.headers().get("accept"))) {
            return mcpResponse(406, rpcError(null, -32600, "Accept must allow application/json"),
                    headerProtocolVersion);
        }
        String contentType = request.headers().get("content-type");
        if (!isJsonContentType(contentType)) {
            return mcpResponse(415, rpcError(null, -32600, "Content-Type must be application/json"),
                    headerProtocolVersion);
        }
        String requestProtocolVersion = request.headers().get("mcp-protocol-version");
        if (requestProtocolVersion != null && !SUPPORTED_PROTOCOL_VERSIONS.contains(requestProtocolVersion)) {
            return mcpResponse(400, rpcError(null, -32602,
                    "Unsupported MCP protocol version: " + requestProtocolVersion), CURRENT_PROTOCOL_VERSION);
        }
        try {
            JsonElement root = JsonParser.parseString(request.body());
            String protocolVersion = resolveResponseProtocolVersion(request, root);
            if (root.isJsonArray()) {
                if (root.getAsJsonArray().isEmpty()) {
                    return mcpResponse(200, rpcError(null, -32600, "Invalid Request"), protocolVersion);
                }
                List<Object> responses = new ArrayList<>();
                for (JsonElement item : root.getAsJsonArray()) {
                    Object response = handleRpcObject(item);
                    if (response != null) {
                        responses.add(response);
                    }
                }
                return responses.isEmpty()
                        ? mcpResponse(202, "", protocolVersion)
                        : mcpResponse(200, responses, protocolVersion);
            }
            Object response = handleRpcObject(root);
            return response == null
                    ? mcpResponse(202, "", protocolVersion)
                    : mcpResponse(200, response, protocolVersion);
        } catch (JsonParseException e) {
            return mcpResponse(200, rpcError(null, -32700, "Parse error"), headerProtocolVersion);
        } catch (Exception e) {
            return mcpResponse(200, rpcError(null, -32600, "Invalid Request"), headerProtocolVersion);
        }
    }


    private Object handleRpcObject(JsonElement item) {
        if (item == null || !item.isJsonObject()) {
            return rpcError(null, -32600, "Invalid Request");
        }
        JsonObject request = item.getAsJsonObject();
        if (!JSON_RPC_VERSION.equals(stringValue(request.get("jsonrpc")))) {
            return rpcError(null, -32600, "Invalid Request");
        }
        boolean notification = !request.has("id");
        JsonElement idElement = request.get("id");
        if (!notification && !validId(idElement)) {
            return rpcError(null, -32600, "Invalid Request");
        }
        Object id = notification ? null : jsonValue(idElement);
        String method = stringValue(request.get("method"));
        if (method == null || method.isEmpty()) {
            return rpcError(id, -32600, "Invalid Request");
        }
        try {
            Object result = switch (method) {
                case "initialize" -> initializeResult(request.get("params"));
                case "initialized", "notifications/initialized", "notifications/cancelled" -> mapOf();
                case "ping" -> mapOf("status", "ok");
                case "tools/list" -> toolsListResult(request.get("params"));
                case "tools/call" -> toolsCallResult(request.get("params"));
                default -> throw new McpRpcException(-32601, "Method not found: " + method);
            };
            return notification ? null : rpcResult(id, result);
        } catch (McpRpcException e) {
            return notification ? null : rpcError(id, e.code(), e.getMessage());
        } catch (Exception e) {
            return notification ? null : rpcError(id, -32603, "Internal error");
        }
    }

    private Map<String, Object> initializeResult(JsonElement paramsElement) throws McpRpcException {
        Map<String, Object> params = requiredObjectParams(paramsElement, "initialize");
        String protocolVersion = stringArg(params, "protocolVersion");
        if (protocolVersion == null || protocolVersion.isBlank()) {
            throw new McpRpcException(-32602, "initialize requires params.protocolVersion");
        }
        if (!SUPPORTED_PROTOCOL_VERSIONS.contains(protocolVersion)) {
            throw new McpRpcException(-32602, "Unsupported MCP protocol version: " + protocolVersion);
        }
        return mapOf(
                "protocolVersion", protocolVersion,
                "capabilities", mapOf("tools", mapOf("listChanged", false)),
                "serverInfo", mapOf("name", SERVER_NAME, "version", serverVersion)
        );
    }

    private Map<String, Object> toolsListResult(JsonElement paramsElement) throws McpRpcException {
        if (paramsElement != null && !paramsElement.isJsonNull() && !paramsElement.isJsonObject()) {
            throw new McpRpcException(-32602, "tools/list params must be an object");
        }
        return mapOf("tools", toolProvider.listTools());
    }

    private Map<String, Object> toolsCallResult(JsonElement paramsElement) throws McpRpcException {
        Map<String, Object> params = requiredObjectParams(paramsElement, "tools/call");
        String name = stringArg(params, "name");
        if (name == null || name.isBlank()) {
            return toolErrorResult("tools/call requires params.name");
        }
        if (params.containsKey("arguments") && !(params.get("arguments") instanceof Map<?, ?>)) {
            return toolErrorResult("tools/call params.arguments must be an object");
        }
        Map<String, Object> arguments = mapArg(params, "arguments");
        try {
            Object result = toolProvider.callTool(name, arguments);
            return mapOf(
                    "content", List.of(mapOf("type", "text", "text", GsonUtils.toJson(result))),
                    "structuredContent", result,
                    "isError", false
            );
        } catch (Exception e) {
            return toolErrorResult(safeToolErrorMessage(e));
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> requiredObjectParams(JsonElement paramsElement, String method) throws McpRpcException {
        if (paramsElement == null || paramsElement.isJsonNull() || !paramsElement.isJsonObject()) {
            throw new McpRpcException(-32602, method + " requires object params");
        }
        Object parsed = GsonUtils.toObject(paramsElement.toString(), Object.class);
        if (!(parsed instanceof Map<?, ?> rawMap)) {
            throw new McpRpcException(-32602, method + " requires object params");
        }
        return (Map<String, Object>) rawMap;
    }

    private Map<String, Object> toolErrorResult(String message) {
        return mapOf(
                "content", List.of(mapOf("type", "text", "text", message)),
                "isError", true
        );
    }

    private String safeToolErrorMessage(Exception error) {
        String message = error.getMessage();
        return message == null || message.isBlank() ? "Tool execution failed" : message;
    }

    private String resolveResponseProtocolVersion(HttpRequest request, JsonElement root) {
        if (root != null && root.isJsonObject()) {
            JsonObject rpc = root.getAsJsonObject();
            if ("initialize".equals(stringValue(rpc.get("method"))) && rpc.get("params") instanceof JsonObject params) {
                String requestedVersion = stringValue(params.get("protocolVersion"));
                if (SUPPORTED_PROTOCOL_VERSIONS.contains(requestedVersion)) {
                    return requestedVersion;
                }
            }
        }
        String headerVersion = request.headers().get("mcp-protocol-version");
        if (headerVersion != null && SUPPORTED_PROTOCOL_VERSIONS.contains(headerVersion)) {
            return headerVersion;
        }
        return CURRENT_PROTOCOL_VERSION;
    }

    private String protocolVersionFromHeader(HttpRequest request) {
        String headerVersion = request.headers().get("mcp-protocol-version");
        return headerVersion != null && SUPPORTED_PROTOCOL_VERSIONS.contains(headerVersion)
                ? headerVersion : CURRENT_PROTOCOL_VERSION;
    }

    private static boolean isJsonContentType(String contentType) {
        if (contentType == null) {
            return false;
        }
        int separator = contentType.indexOf(';');
        String mediaType = (separator < 0 ? contentType : contentType.substring(0, separator)).trim();
        return "application/json".equalsIgnoreCase(mediaType);
    }

    private static boolean acceptsJsonResponse(String accept) {
        if (accept == null || accept.isBlank()) {
            return true;
        }
        int bestSpecificity = -1;
        double selectedQuality = 0;
        for (String mediaRange : accept.split(",")) {
            String[] components = mediaRange.split(";");
            String type = components[0].trim();
            int specificity = "application/json".equalsIgnoreCase(type) ? 2
                    : "application/*".equalsIgnoreCase(type) ? 1
                    : "*/*".equals(type) ? 0 : -1;
            if (specificity < 0 || specificity < bestSpecificity) {
                continue;
            }
            double quality = 1.0;
            for (int index = 1; index < components.length; index++) {
                String parameter = components[index].trim();
                int equals = parameter.indexOf('=');
                if (equals > 0 && "q".equalsIgnoreCase(parameter.substring(0, equals).trim())) {
                    try {
                        quality = Double.parseDouble(parameter.substring(equals + 1).trim());
                    } catch (NumberFormatException ignored) {
                        quality = 0;
                    }
                }
            }
            if (specificity > bestSpecificity) {
                bestSpecificity = specificity;
                selectedQuality = quality;
            } else {
                selectedQuality = Math.max(selectedQuality, quality);
            }
        }
        return selectedQuality > 0;
    }

    private static void applyCorsHeaders(HttpRequest request, HttpResponse response) {
        String origin = request.headers().get("origin");
        if (origin != null && isAllowedOrigin(origin)) {
            response.headers().put("Access-Control-Allow-Origin", origin);
            response.headers().put("Vary", "Origin");
        }
    }

    private static boolean isAllowedOrigin(String origin) {
        if (origin == null || origin.isBlank()) {
            return true;
        }
        try {
            URI uri = URI.create(origin);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            String path = uri.getPath();
            if (!("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))
                    || host == null || uri.getUserInfo() != null || uri.getQuery() != null
                    || uri.getFragment() != null || (path != null && !path.isEmpty())) {
                return false;
            }
            return "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host)
                    || "::1".equals(host) || "[::1]".equals(host);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static boolean validId(JsonElement id) {
        return id == null || id.isJsonNull() || (id.isJsonPrimitive()
                && (id.getAsJsonPrimitive().isString() || id.getAsJsonPrimitive().isNumber()));
    }


    private static final class HttpParseException extends IOException {
        private final int statusCode;

        private HttpParseException(int statusCode, String message) {
            super(message);
            this.statusCode = statusCode;
        }

        private HttpParseException(int statusCode, String message, Throwable cause) {
            super(message, cause);
            this.statusCode = statusCode;
        }

        private int statusCode() {
            return statusCode;
        }
    }

    private static final class McpRpcException extends Exception {
        private final int code;

        private McpRpcException(int code, String message) {
            super(message);
            this.code = code;
        }

        private int code() {
            return code;
        }
    }


    private record HttpRequest(String method, String path, Map<String, String> headers, String body) {
    }

    private record HttpResponse(int status, byte[] body, Map<String, String> headers) {
    }
}
