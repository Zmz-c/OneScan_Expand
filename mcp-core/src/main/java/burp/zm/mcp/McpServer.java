package burp.zm.mcp;

import com.google.gson.*;

import java.io.ByteArrayOutputStream;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.BufferedWriter;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class McpServer {

    public static final int DEFAULT_PORT = 8765;
    /** Retained for source compatibility; default constructors use only {@link #DEFAULT_PORT}. */
    public static final int DEFAULT_PORT_RANGE = 20;
    private static final String JSON_RPC_VERSION = "2.0";
    private static final String DEFAULT_SERVER_NAME = "burp-mcp";
    private static final String DEFAULT_SERVER_VERSION = "0.1.0";
    private static final Gson GSON = new Gson();
    public static final String CURRENT_PROTOCOL_VERSION = "2025-11-25";
    private static final Set<String> SUPPORTED_PROTOCOL_VERSIONS = Set.of(
            "2024-11-05", "2025-03-26", "2025-06-18", CURRENT_PROTOCOL_VERSION);
    private static final int MAX_HEADER_BYTES = 64 * 1024;
    private static final int MAX_BODY_BYTES = 50 * 1024 * 1024;
    private static final String SESSION_HEADER = "mcp-session-id";
    private static final int MAX_SESSION_ID_LENGTH = 128;
    private static final int MAX_SESSIONS = 128;
    private static final int MAX_WORKER_THREADS = 16;
    private static final long SESSION_IDLE_TIMEOUT_MILLIS = 30 * 60 * 1000L;
    private static final String PROVIDER_REGISTER_PATH = "/__mcp/providers/register";
    private static final String PROVIDER_UNREGISTER_PATH = "/__mcp/providers/unregister";
    private static final String PROVIDER_PREFACE = "MCP-PROVIDER/1 ";
    private static final int MAX_PROVIDER_FRAME_BYTES = 4 * 1024 * 1024;
    private static final long PROVIDER_LEASE_MILLIS = 45_000L;
    private static final long PROVIDER_HEARTBEAT_MILLIS = 10_000L;
    private static final long PROVIDER_CALL_TIMEOUT_MILLIS = 30_000L;
    private static final int PROVIDER_CONNECT_TIMEOUT_MILLIS = 2_000;
    private static final String PROVIDER_ID_PATTERN = "[A-Za-z0-9._~-]{1,128}";

    private final McpToolProvider toolProvider;
    private final String serverName;
    private final String serverVersion;
    private final int firstPort;
    private final int lastPort;
    private final boolean joinOnBindFailure;
    private final String providerId = UUID.randomUUID().toString();
    private ServerSocket serverSocket;
    private ExecutorService executor;
    private Thread acceptThread;
    private volatile boolean running;
    private int port;
    private volatile Role role;
    private volatile Socket providerSocket;
    private volatile BufferedWriter providerWriter;
    private volatile long lastProviderHeartbeatAck = System.currentTimeMillis();
    private ScheduledExecutorService providerMaintenance;
    private final AtomicLong providerRequestSequence = new AtomicLong();
    private final Map<String, RemoteProvider> remoteProviders = new ConcurrentHashMap<>();
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    public McpServer(McpToolProvider toolProvider) {
        this(toolProvider, DEFAULT_SERVER_NAME, DEFAULT_SERVER_VERSION);
    }

    public McpServer(McpToolProvider toolProvider, String serverVersion) {
        this(toolProvider, DEFAULT_SERVER_NAME, serverVersion);
    }

    public McpServer(McpToolProvider toolProvider, String serverName, String serverVersion) {
        this(toolProvider, serverName, serverVersion, DEFAULT_PORT, DEFAULT_PORT);
    }

    public McpServer(McpToolProvider toolProvider, String serverName, String serverVersion, int port) {
        this(toolProvider, serverName, serverVersion, port, port);
    }

    public McpServer(McpToolProvider toolProvider, String serverName, String serverVersion,
                     int firstPort, int lastPort) {
        if (toolProvider == null) {
            throw new IllegalArgumentException("toolProvider is null");
        }
        this.toolProvider = toolProvider;
        if (firstPort < 0 || lastPort < firstPort || lastPort > 65535) {
            throw new IllegalArgumentException("invalid MCP port range");
        }
        this.serverName = serverName == null || serverName.isBlank() ? DEFAULT_SERVER_NAME : serverName;
        this.serverVersion = serverVersion == null || serverVersion.isBlank()
                ? DEFAULT_SERVER_VERSION : serverVersion;
        this.firstPort = firstPort;
        this.lastPort = lastPort;
        this.joinOnBindFailure = firstPort == lastPort && firstPort > 0;
    }

    /** The role of this instance in the shared single-port transport. */
    public enum Role { HOST, CLIENT }

    /** Returns HOST when this instance owns the shared port, or CLIENT when registered with another host. */
    public Role getRole() {
        return role;
    }

    /** Stable id used by a client provider registration. */
    public String getProviderId() {
        return providerId;
    }

    /** Number of local plus remotely registered providers visible to this host. */
    public int getProviderCount() {
        return 1 + remoteProviders.size();
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
        header.append("Content-Type: ").append(response.contentType()).append("\r\n");
        header.append("Content-Length: ").append(body.length).append("\r\n");
        header.append("Connection: close\r\n");
        header.append("Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n");
        header.append("Access-Control-Allow-Headers: Content-Type, Accept, MCP-Protocol-Version, Mcp-Session-Id\r\n");
        header.append("Access-Control-Expose-Headers: MCP-Protocol-Version, Mcp-Session-Id\r\n");
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
                : GSON.toJson(body).getBytes(StandardCharsets.UTF_8);
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
        return GSON.fromJson(element.toString(), Object.class);
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
        if (serverSocket != null || role != null) {
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
                role = Role.HOST;
                break;
            } catch (IOException e) {
                lastException = e;
            }
        }
        if (serverSocket == null) {
            if (joinOnBindFailure && tryJoinExistingHost()) {
                role = Role.CLIENT;
                port = firstPort;
                startProviderMaintenance();
                return;
            }
            throw lastException == null ? new IOException("MCP server failed to bind") : lastException;
        }
        startHostRuntime();
    }

    private void startHostRuntime() {
        executor = Executors.newFixedThreadPool(MAX_WORKER_THREADS, r -> {
            Thread thread = new Thread(r, "MCP-server");
            thread.setDaemon(true);
            return thread;
        });
        running = true;
        acceptThread = new Thread(this::acceptLoop, "MCP-server-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
        if (providerMaintenance == null || providerMaintenance.isShutdown()) {
            startProviderMaintenance();
        }
    }

    public synchronized void stop() {
        running = false;
        if (role == Role.CLIENT) {
            closeProviderChannel();
            unregisterFromHost();
        }
        sessions.clear();
        for (RemoteProvider provider : remoteProviders.values()) {
            provider.close();
        }
        remoteProviders.clear();
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
        if (providerMaintenance != null) {
            providerMaintenance.shutdownNow();
            providerMaintenance = null;
        }
        providerSocket = null;
        providerWriter = null;
        role = null;
    }

    public String getEndpoint() {
        if (port <= 0 || role == null) {
            return "";
        }
        return "http://127.0.0.1:" + port + "/mcp";
    }

    private void startProviderMaintenance() {
        providerMaintenance = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "MCP-provider-maintenance");
            thread.setDaemon(true);
            return thread;
        });
        providerMaintenance.scheduleAtFixedRate(this::maintainProviderConnection,
                PROVIDER_HEARTBEAT_MILLIS, PROVIDER_HEARTBEAT_MILLIS, TimeUnit.MILLISECONDS);
    }

    private void maintainProviderConnection() {
        try {
            if (role == Role.HOST) {
                long now = System.currentTimeMillis();
                remoteProviders.values().removeIf(provider -> {
                    if (now - provider.lastHeartbeat > PROVIDER_LEASE_MILLIS) {
                        provider.close();
                        return true;
                    }
                    return false;
                });
            } else if (role == Role.CLIENT) {
                if (isProviderChannelAlive()) {
                    sendProviderFrame(mapOf("type", "heartbeat"));
                } else {
                    synchronized (this) {
                        if (role != Role.CLIENT || isProviderChannelAlive()) {
                            return;
                        }
                        if (tryBecomeHost()) {
                            role = Role.HOST;
                            startHostRuntime();
                        } else {
                            closeProviderChannel();
                            tryJoinExistingHost();
                        }
                    }
                }
            }
        } catch (Exception ignored) {
            // Maintenance is best-effort; the next tick retries registration or cleanup.
        }
    }

    private boolean tryBecomeHost() {
        try {
            InetAddress loopback = InetAddress.getByName("127.0.0.1");
            ServerSocket socket = new ServerSocket();
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(loopback, firstPort), 50);
            serverSocket = socket;
            port = socket.getLocalPort();
            return true;
        } catch (IOException ignored) {
            return false;
        }
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
        boolean handedToProviderChannel = false;
        try {
            socket.setSoTimeout(30000);
            BufferedInputStream input = new BufferedInputStream(socket.getInputStream());
            if (looksLikeProviderPreface(input)) {
                handedToProviderChannel = handleProviderChannel(socket, input);
                return;
            }
            HttpResponse response;
            try {
                HttpRequest request = readRequest(input);
                response = handleHttpRequest(request);
                applyCorsHeaders(request, response);
            } catch (HttpParseException e) {
                response = jsonResponse(e.statusCode(), mapOf("error", e.getMessage()));
            } catch (IOException e) {
                response = jsonResponse(400, mapOf("error", "invalid HTTP request"));
            } catch (Exception e) {
                response = jsonResponse(500, mapOf("error", "server error"));
            }
            writeResponse(socket.getOutputStream(), response);
        } catch (Exception ignored) {
            // The peer may close before an error response can be written.
        } finally {
            if (!handedToProviderChannel) {
                try {
                    socket.close();
                } catch (IOException ignored) {
                    // ignored
                }
            }
        }
    }

    private static boolean looksLikeProviderPreface(BufferedInputStream input) throws IOException {
        input.mark(PROVIDER_PREFACE.length());
        int first = input.read();
        if (first != PROVIDER_PREFACE.charAt(0)) {
            input.reset();
            return false;
        }
        byte[] rest = input.readNBytes(PROVIDER_PREFACE.length() - 1);
        byte[] probe = new byte[1 + rest.length];
        probe[0] = (byte) first;
        System.arraycopy(rest, 0, probe, 1, rest.length);
        input.reset();
        return probe.length == PROVIDER_PREFACE.length()
                && Arrays.equals(probe, PROVIDER_PREFACE.getBytes(StandardCharsets.US_ASCII));
    }

    private boolean handleProviderChannel(Socket socket, BufferedInputStream input) throws IOException {
        socket.setSoTimeout(0);
        String preface = readProviderLine(input, 512);
        if (preface == null || !preface.startsWith(PROVIDER_PREFACE)) {
            return false;
        }
        String[] parts = preface.substring(PROVIDER_PREFACE.length()).trim().split("\\s+", 2);
        if (parts.length != 2) {
            return false;
        }
        RemoteProvider provider = remoteProviders.get(parts[0]);
        if (provider == null || !constantTimeEquals(provider.channelToken, parts[1])) {
            return false;
        }
        provider.attach(socket, input);
        return true;
    }

    private static String readProviderLine(InputStream input, int maxBytes) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        while (bytes.size() < maxBytes) {
            int value = input.read();
            if (value < 0) {
                return bytes.size() == 0 ? null : bytes.toString(StandardCharsets.UTF_8);
            }
            if (value == '\n') {
                return bytes.toString(StandardCharsets.UTF_8).replaceFirst("\\r$", "");
            }
            bytes.write(value);
        }
        throw new IOException("provider preface too large");
    }

    private static boolean constantTimeEquals(String left, String right) {
        return left != null && right != null
                && java.security.MessageDigest.isEqual(left.getBytes(StandardCharsets.US_ASCII),
                right.getBytes(StandardCharsets.US_ASCII));
    }

    private boolean tryJoinExistingHost() {
        try {
            URL url = new URL("http://127.0.0.1:" + firstPort + PROVIDER_REGISTER_PATH);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(PROVIDER_CONNECT_TIMEOUT_MILLIS);
            connection.setReadTimeout(PROVIDER_CONNECT_TIMEOUT_MILLIS);
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            Map<String, Object> registration = mapOf("providerId", providerId, "name", serverName,
                    "version", serverVersion, "tools", toolProvider.listTools());
            byte[] body = GSON.toJson(registration).getBytes(StandardCharsets.UTF_8);
            connection.setFixedLengthStreamingMode(body.length);
            try (OutputStream output = connection.getOutputStream()) {
                output.write(body);
            }
            if (connection.getResponseCode() != 200) {
                connection.disconnect();
                return false;
            }
            JsonElement response = JsonParser.parseString(new String(connection.getInputStream().readAllBytes(),
                    StandardCharsets.UTF_8));
            connection.disconnect();
            if (!response.isJsonObject()) {
                return false;
            }
            String token = stringValue(response.getAsJsonObject().get("channelToken"));
            if (token == null || token.isBlank()) {
                return false;
            }
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress("127.0.0.1", firstPort), PROVIDER_CONNECT_TIMEOUT_MILLIS);
            socket.setTcpNoDelay(true);
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));
            writer.write(PROVIDER_PREFACE + providerId + " " + token + "\n");
            writer.flush();
            providerSocket = socket;
            providerWriter = writer;
            lastProviderHeartbeatAck = System.currentTimeMillis();
            Thread reader = new Thread(() -> providerClientReadLoop(socket), "MCP-provider-client");
            reader.setDaemon(true);
            reader.start();
            return true;
        } catch (Exception ignored) {
            closeProviderChannel();
            return false;
        }
    }

    private void providerClientReadLoop(Socket socket) {
        try {
            BufferedInputStream input = new BufferedInputStream(socket.getInputStream());
            String frame;
            while ((frame = readProviderLine(input, MAX_PROVIDER_FRAME_BYTES)) != null) {
                JsonElement element = JsonParser.parseString(frame);
                if (!element.isJsonObject()) {
                    continue;
                }
                JsonObject object = element.getAsJsonObject();
                String type = stringValue(object.get("type"));
                if ("call".equals(type)) {
                    handleProviderCall(object);
                } else if ("heartbeat_ack".equals(type) || "pong".equals(type)) {
                    lastProviderHeartbeatAck = System.currentTimeMillis();
                    // Keep the channel alive; no action is required.
                }
            }
        } catch (Exception ignored) {
            // The maintenance loop will reconnect or take over the host port.
        } finally {
            if (providerSocket == socket) {
                closeProviderChannel();
            }
        }
    }

    private void handleProviderCall(JsonObject object) {
        String requestId = stringValue(object.get("requestId"));
        String name = stringValue(object.get("name"));
        Map<String, Object> arguments = new LinkedHashMap<>();
        if (object.has("arguments") && object.get("arguments").isJsonObject()) {
            Map<?, ?> parsed = GSON.fromJson(object.get("arguments"), Map.class);
            if (parsed != null) {
                parsed.forEach((key, value) -> arguments.put(String.valueOf(key), value));
            }
        }
        if (requestId == null || name == null) {
            return;
        }
        try {
            Object result = toolProvider.callTool(name, arguments);
            sendProviderFrame(mapOf("type", "result", "requestId", requestId, "result", result));
        } catch (Exception error) {
            sendProviderFrame(mapOf("type", "error", "requestId", requestId,
                    "error", safeToolErrorMessage(error)));
        }
    }

    private void sendProviderFrame(Map<String, Object> frame) {
        BufferedWriter writer = providerWriter;
        if (writer == null) {
            return;
        }
        synchronized (writer) {
            try {
                writer.write(GSON.toJson(frame));
                writer.write('\n');
                writer.flush();
            } catch (IOException ignored) {
                closeProviderChannel();
            }
        }
    }

    private boolean isProviderChannelAlive() {
        Socket socket = providerSocket;
        return socket != null && socket.isConnected() && !socket.isClosed()
                && System.currentTimeMillis() - lastProviderHeartbeatAck <= PROVIDER_LEASE_MILLIS;
    }

    private void closeProviderChannel() {
        Socket socket = providerSocket;
        providerSocket = null;
        providerWriter = null;
        lastProviderHeartbeatAck = 0;
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // ignored
            }
        }
    }

    private void unregisterFromHost() {
        try {
            URL url = new URL("http://127.0.0.1:" + firstPort + PROVIDER_UNREGISTER_PATH);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(PROVIDER_CONNECT_TIMEOUT_MILLIS);
            connection.setReadTimeout(PROVIDER_CONNECT_TIMEOUT_MILLIS);
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            byte[] body = GSON.toJson(mapOf("providerId", providerId)).getBytes(StandardCharsets.UTF_8);
            connection.setFixedLengthStreamingMode(body.length);
            try (OutputStream output = connection.getOutputStream()) {
                output.write(body);
            }
            connection.getResponseCode();
            connection.disconnect();
        } catch (Exception ignored) {
            // Host may already be gone.
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
        if (PROVIDER_REGISTER_PATH.equals(path)) {
            return handleProviderRegister(request);
        }
        if (PROVIDER_UNREGISTER_PATH.equals(path)) {
            return handleProviderUnregister(request);
        }
        if ("/docs".equals(path) || "/docs/".equals(path) || path.startsWith("/docs/")) {
            return handleDocs(request, path);
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
        return jsonResponse(200, mapOf("status", "ok", "endpoint", getEndpoint(),
                "role", role == null ? "stopped" : role.name().toLowerCase(Locale.ROOT),
                "providerId", providerId, "providers", getProviderCount()));
    }

    private HttpResponse handleProviderRegister(HttpRequest request) {
        if (role != Role.HOST) {
            return jsonResponse(503, mapOf("error", "MCP host is not available"));
        }
        if (!isAllowedOrigin(request.headers().get("origin"))) {
            return jsonResponse(403, mapOf("error", "origin not allowed"));
        }
        if (!"POST".equalsIgnoreCase(request.method())) {
            HttpResponse response = jsonResponse(405, mapOf("error", "method not allowed"));
            response.headers().put("Allow", "POST");
            return response;
        }
        try {
            JsonElement root = JsonParser.parseString(request.body());
            if (!root.isJsonObject()) {
                return jsonResponse(400, mapOf("error", "registration body must be an object"));
            }
            JsonObject object = root.getAsJsonObject();
            String id = stringValue(object.get("providerId"));
            String name = stringValue(object.get("name"));
            String version = stringValue(object.get("version"));
            JsonElement toolsValue = object.get("tools");
            JsonArray toolsElement = toolsValue != null && toolsValue.isJsonArray()
                    ? toolsValue.getAsJsonArray() : null;
            if (id == null || !id.matches(PROVIDER_ID_PATTERN) || name == null || name.isBlank()
                    || version == null || version.isBlank() || toolsElement == null) {
                return jsonResponse(400, mapOf("error", "providerId, name, version and tools are required"));
            }
            RemoteProvider existing = remoteProviders.get(id);
            List<McpTool> tools = new ArrayList<>();
            Set<String> names = new HashSet<>();
            for (JsonElement toolElement : toolsElement) {
                McpTool tool = GSON.fromJson(toolElement, McpTool.class);
                if (tool == null || tool.getName() == null || tool.getName().isBlank()
                        || !names.add(tool.getName())
                        || (findTool(tool.getName()) != null
                        && (existing == null || existing.tools.stream().noneMatch(existingTool ->
                        existingTool != null && tool.getName().equals(existingTool.getName()))))) {
                    return jsonResponse(409, mapOf("error", "provider tool name is missing or already registered"));
                }
                tools.add(tool);
            }
            RemoteProvider provider = new RemoteProvider(id, name, version, tools, UUID.randomUUID().toString());
            RemoteProvider previous = remoteProviders.put(id, provider);
            if (previous != null) {
                previous.close();
            }
            return jsonResponse(200, mapOf("status", "registered", "providerId", id,
                    "channelToken", provider.channelToken, "leaseSeconds", PROVIDER_LEASE_MILLIS / 1000,
                    "protocol", "mcp-provider/1"));
        } catch (JsonParseException | IllegalStateException | UnsupportedOperationException e) {
            return jsonResponse(400, mapOf("error", "invalid registration body"));
        }
    }

    private HttpResponse handleProviderUnregister(HttpRequest request) {
        if (role != Role.HOST) {
            return jsonResponse(503, mapOf("error", "MCP host is not available"));
        }
        if (!isAllowedOrigin(request.headers().get("origin"))) {
            return jsonResponse(403, mapOf("error", "origin not allowed"));
        }
        if (!"POST".equalsIgnoreCase(request.method())) {
            HttpResponse response = jsonResponse(405, mapOf("error", "method not allowed"));
            response.headers().put("Allow", "POST");
            return response;
        }
        try {
            JsonElement root = JsonParser.parseString(request.body());
            String id = root.isJsonObject() ? stringValue(root.getAsJsonObject().get("providerId")) : null;
            if (id == null || !id.matches(PROVIDER_ID_PATTERN)) {
                return jsonResponse(400, mapOf("error", "valid providerId is required"));
            }
            RemoteProvider provider = remoteProviders.remove(id);
            if (provider != null) {
                provider.close();
            }
            return jsonResponse(200, mapOf("status", provider == null ? "not-found" : "unregistered"));
        } catch (JsonParseException | IllegalStateException | UnsupportedOperationException e) {
            return jsonResponse(400, mapOf("error", "invalid unregistration body"));
        }
    }

    private HttpResponse handleDocs(HttpRequest request, String path) {
        if (!isAllowedOrigin(request.headers().get("origin"))) {
            return jsonResponse(403, mapOf("error", "origin not allowed"));
        }
        if (!"GET".equalsIgnoreCase(request.method())) {
            HttpResponse response = jsonResponse(405, mapOf("error", "method not allowed"));
            response.headers().put("Allow", "GET");
            return response;
        }
        String resourcePath = "/docs".equals(path) || "/docs/".equals(path)
                ? "docs/index.html" : path.substring(1);
        if (resourcePath.contains("..") || resourcePath.contains("\\") || resourcePath.contains("%")
                || resourcePath.contains(":") || resourcePath.startsWith("/")) {
            return jsonResponse(400, mapOf("error", "invalid documentation path"));
        }
        try (InputStream resource = McpServer.class.getClassLoader().getResourceAsStream(resourcePath)) {
            if (resource == null) {
                return jsonResponse(404, mapOf("error", "documentation resource not found"));
            }
            byte[] body = resource.readNBytes(MAX_BODY_BYTES + 1);
            if (body.length > MAX_BODY_BYTES) {
                return jsonResponse(413, mapOf("error", "documentation resource too large"));
            }
            return resourceResponse(body, resourceContentType(resourcePath));
        } catch (IOException e) {
            return jsonResponse(500, mapOf("error", "documentation resource unavailable"));
        }
    }

    private static HttpResponse resourceResponse(byte[] body, String contentType) {
        return new HttpResponse(200, body, new LinkedHashMap<>(), contentType);
    }

    private static String resourceContentType(String resourcePath) {
        String lowerPath = resourcePath.toLowerCase(Locale.ROOT);
        if (lowerPath.endsWith(".html")) {
            return "text/html; charset=utf-8";
        }
        if (lowerPath.endsWith(".css")) {
            return "text/css; charset=utf-8";
        }
        if (lowerPath.endsWith(".js")) {
            return "application/javascript; charset=utf-8";
        }
        if (lowerPath.endsWith(".yaml") || lowerPath.endsWith(".yml")) {
            return "text/yaml; charset=utf-8";
        }
        if (lowerPath.endsWith(".png")) {
            return "image/png";
        }
        return "application/octet-stream";
    }

    private HttpResponse handleMcp(HttpRequest request) {
        String requestSessionId = request.headers().get(SESSION_HEADER);
        String headerProtocolVersion = protocolVersionFromHeader(request);
        if (!isAllowedOrigin(request.headers().get("origin"))) {
            return mcpResponse(403, rpcError(null, -32600, "Origin is not allowed"), headerProtocolVersion);
        }
        if (requestSessionId != null && !validSessionId(requestSessionId)) {
            return mcpResponse(400, rpcError(null, -32600, "Invalid MCP session id"), headerProtocolVersion);
        }
        if ("OPTIONS".equalsIgnoreCase(request.method())) {
            return mcpResponse(204, "", headerProtocolVersion);
        }
        if ("DELETE".equalsIgnoreCase(request.method())) {
            return handleSessionDelete(requestSessionId, headerProtocolVersion);
        }
        if (!"POST".equalsIgnoreCase(request.method())) {
            HttpResponse response = mcpResponse(405,
                    rpcError(null, -32600, "Only POST or DELETE is supported"), headerProtocolVersion);
            response.headers().put("Allow", "POST, DELETE, OPTIONS");
            return response;
        }
        String requestProtocolVersion = request.headers().get("mcp-protocol-version");
        if (requestProtocolVersion != null && !SUPPORTED_PROTOCOL_VERSIONS.contains(requestProtocolVersion)) {
            return mcpResponse(400, rpcError(null, -32602,
                    "Unsupported MCP protocol version: " + requestProtocolVersion), CURRENT_PROTOCOL_VERSION);
        }
        Session session = findSession(requestSessionId);
        if (requestSessionId != null && session == null) {
            return mcpResponse(404, rpcError(null, -32600, "MCP session not found"), headerProtocolVersion);
        }
        if (session != null) {
            headerProtocolVersion = session.protocolVersion;
            if (requestProtocolVersion != null && !session.protocolVersion.equals(requestProtocolVersion)) {
                return withSession(mcpResponse(400, rpcError(null, -32602,
                        "MCP protocol version does not match the session"), headerProtocolVersion), requestSessionId);
            }
        }
        if (!acceptsJsonResponse(request.headers().get("accept"))) {
            return withSession(mcpResponse(406, rpcError(null, -32600, "Accept must allow application/json"),
                    headerProtocolVersion), requestSessionId);
        }
        String contentType = request.headers().get("content-type");
        if (!isJsonContentType(contentType)) {
            return withSession(mcpResponse(415, rpcError(null, -32600, "Content-Type must be application/json"),
                    headerProtocolVersion), requestSessionId);
        }
        try {
            JsonElement root = JsonParser.parseString(request.body());
            String responseProtocol = session != null
                    ? session.protocolVersion : resolveResponseProtocolVersion(request, root);
            RpcContext context = new RpcContext(requestSessionId, session, responseProtocol);
            if (root.isJsonArray()) {
                if (root.getAsJsonArray().isEmpty()) {
                    return withSession(mcpResponse(200, rpcError(null, -32600, "Invalid Request"),
                            context.protocolVersion), context);
                }
                List<Object> responses = new ArrayList<>();
                for (JsonElement item : root.getAsJsonArray()) {
                    Object response = handleRpcObject(item, context);
                    if (response != null) {
                        responses.add(response);
                    }
                }
                return withSession(responses.isEmpty()
                        ? mcpResponse(202, "", context.protocolVersion)
                        : mcpResponse(200, responses, context.protocolVersion), context);
            }
            Object response = handleRpcObject(root, context);
            return withSession(response == null
                    ? mcpResponse(202, "", context.protocolVersion)
                    : mcpResponse(200, response, context.protocolVersion), context);
        } catch (JsonParseException e) {
            return withSession(mcpResponse(200, rpcError(null, -32700, "Parse error"), headerProtocolVersion),
                    requestSessionId);
        } catch (Exception e) {
            return withSession(mcpResponse(200, rpcError(null, -32600, "Invalid Request"), headerProtocolVersion),
                    requestSessionId);
        }
    }


    private HttpResponse handleSessionDelete(String sessionId, String protocolVersion) {
        if (sessionId == null) {
            return mcpResponse(400, rpcError(null, -32600, "Mcp-Session-Id is required"), protocolVersion);
        }
        Session removed = sessions.remove(sessionId);
        if (removed == null) {
            return mcpResponse(404, rpcError(null, -32600, "MCP session not found"), protocolVersion);
        }
        return mcpResponse(204, "", removed.protocolVersion);
    }

    private Object handleRpcObject(JsonElement item, RpcContext context) {
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
            if (context.session != null && !context.session.initialized
                    && ("tools/list".equals(method) || "tools/call".equals(method))) {
                throw new McpRpcException(-32600,
                        "MCP session is not initialized; send notifications/initialized first");
            }
            Object result = switch (method) {
                case "initialize" -> initializeResult(request.get("params"), context);
                case "initialized", "notifications/initialized" -> markInitialized(context);
                case "notifications/cancelled" -> mapOf();
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

    private Map<String, Object> initializeResult(JsonElement paramsElement, RpcContext context)
            throws McpRpcException {
        if (context.session != null || context.requestSessionId != null) {
            throw new McpRpcException(-32600, "initialize must not include an MCP session id");
        }
        Map<String, Object> params = requiredObjectParams(paramsElement, "initialize");
        String protocolVersion = stringArg(params, "protocolVersion");
        if (protocolVersion == null || protocolVersion.isBlank()) {
            throw new McpRpcException(-32602, "initialize requires params.protocolVersion");
        }
        if (!SUPPORTED_PROTOCOL_VERSIONS.contains(protocolVersion)) {
            throw new McpRpcException(-32602, "Unsupported MCP protocol version: " + protocolVersion);
        }
        String sessionId = newSessionId();
        Session session = new Session(sessionId, protocolVersion);
        registerSession(session);
        context.session = session;
        context.responseSessionId = sessionId;
        context.protocolVersion = protocolVersion;
        return mapOf(
                "protocolVersion", protocolVersion,
                "capabilities", mapOf("tools", mapOf("listChanged", false)),
                "serverInfo", mapOf("name", serverName, "version", serverVersion)
        );
    }

    private Map<String, Object> markInitialized(RpcContext context) {
        if (context.session != null) {
            context.session.initialized = true;
            context.session.touch();
        }
        return mapOf();
    }

    private Map<String, Object> toolsListResult(JsonElement paramsElement) throws McpRpcException {
        if (paramsElement != null && !paramsElement.isJsonNull() && !paramsElement.isJsonObject()) {
            throw new McpRpcException(-32602, "tools/list params must be an object");
        }
        List<McpTool> tools = new ArrayList<>();
        List<McpTool> localTools = toolProvider.listTools();
        if (localTools != null) {
            tools.addAll(localTools);
        }
        remoteProviders.values().stream()
                .sorted(Comparator.comparing(provider -> provider.providerId))
                .forEach(provider -> tools.addAll(provider.tools));
        return mapOf("tools", tools);
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
        McpTool tool = findTool(name);
        if (tool != null) {
            String validationError = validateArguments(tool.getInputSchema(), arguments, "$");
            if (validationError != null) {
                return toolErrorResult(validationError);
            }
        }
        try {
            RemoteProvider remoteProvider = findRemoteProvider(name);
            Object result = remoteProvider == null
                    ? toolProvider.callTool(name, arguments)
                    : remoteProvider.callTool(name, arguments);
            return mapOf(
                    "content", List.of(mapOf("type", "text", "text", GSON.toJson(result))),
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
        Object parsed = GSON.fromJson(paramsElement.toString(), Object.class);
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

    private HttpResponse withSession(HttpResponse response, RpcContext context) {
        String sessionId = context.responseSessionId != null
                ? context.responseSessionId : context.requestSessionId;
        return withSession(response, sessionId);
    }

    private HttpResponse withSession(HttpResponse response, String sessionId) {
        if (sessionId != null) {
            response.headers().put("Mcp-Session-Id", sessionId);
        }
        return response;
    }

    private Session findSession(String sessionId) {
        if (sessionId == null) {
            return null;
        }
        Session session = sessions.get(sessionId);
        if (session == null) {
            return null;
        }
        if (System.currentTimeMillis() - session.lastAccess > SESSION_IDLE_TIMEOUT_MILLIS) {
            sessions.remove(sessionId, session);
            return null;
        }
        session.touch();
        return session;
    }

    private void registerSession(Session session) {
        cleanupExpiredSessions();
        if (sessions.size() >= MAX_SESSIONS) {
            sessions.entrySet().stream()
                    .min(Comparator.comparingLong(entry -> entry.getValue().lastAccess))
                    .ifPresent(entry -> sessions.remove(entry.getKey(), entry.getValue()));
        }
        sessions.put(session.id, session);
    }

    private void cleanupExpiredSessions() {
        long now = System.currentTimeMillis();
        sessions.entrySet().removeIf(entry -> now - entry.getValue().lastAccess > SESSION_IDLE_TIMEOUT_MILLIS);
    }

    private static String newSessionId() {
        return UUID.randomUUID().toString();
    }

    private static boolean validSessionId(String sessionId) {
        return sessionId != null && !sessionId.isBlank() && sessionId.length() <= MAX_SESSION_ID_LENGTH
                && sessionId.chars().allMatch(value -> value >= 0x21 && value <= 0x7e
                && value != ',' && value != ';');
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

    private static final class Session {
        private final String id;
        private final String protocolVersion;
        private volatile long lastAccess = System.currentTimeMillis();
        private volatile boolean initialized;

        private Session(String id, String protocolVersion) {
            this.id = id;
            this.protocolVersion = protocolVersion;
        }

        private void touch() {
            lastAccess = System.currentTimeMillis();
        }
    }

    private final class RemoteProvider {
        private final String providerId;
        private final String name;
        private final String version;
        private final List<McpTool> tools;
        private final String channelToken;
        private final Map<String, CompletableFuture<Object>> pending = new ConcurrentHashMap<>();
        private volatile long lastHeartbeat = System.currentTimeMillis();
        private volatile Socket socket;
        private volatile BufferedWriter writer;

        private RemoteProvider(String providerId, String name, String version, List<McpTool> tools,
                               String channelToken) {
            this.providerId = providerId;
            this.name = name;
            this.version = version;
            this.tools = List.copyOf(tools);
            this.channelToken = channelToken;
        }

        private synchronized void attach(Socket newSocket, InputStream input) throws IOException {
            closeChannel();
            newSocket.setSoTimeout(0);
            socket = newSocket;
            writer = new BufferedWriter(new OutputStreamWriter(newSocket.getOutputStream(), StandardCharsets.UTF_8));
            lastHeartbeat = System.currentTimeMillis();
            Thread reader = new Thread(() -> readLoop(newSocket, input), "MCP-provider-" + providerId);
            reader.setDaemon(true);
            reader.start();
        }

        private void readLoop(Socket channel, InputStream input) {
            try {
                String frame;
                while ((frame = readProviderLine(input, MAX_PROVIDER_FRAME_BYTES)) != null) {
                    JsonElement element = JsonParser.parseString(frame);
                    if (!element.isJsonObject()) {
                        continue;
                    }
                    JsonObject object = element.getAsJsonObject();
                    lastHeartbeat = System.currentTimeMillis();
                    String type = stringValue(object.get("type"));
                    if ("heartbeat".equals(type)) {
                        send(mapOf("type", "heartbeat_ack"));
                    } else if ("pong".equals(type)) {
                        // Host-to-client liveness probe acknowledgement.
                    } else if ("result".equals(type) || "error".equals(type)) {
                        String requestId = stringValue(object.get("requestId"));
                        CompletableFuture<Object> future = requestId == null ? null : pending.remove(requestId);
                        if (future != null) {
                            if ("error".equals(type)) {
                                future.completeExceptionally(new IOException(stringValue(object.get("error"))));
                            } else {
                                future.complete(object.has("result") ? jsonValue(object.get("result")) : null);
                            }
                        }
                    }
                }
            } catch (Exception ignored) {
                // The lease cleanup below removes disconnected providers.
            } finally {
                synchronized (this) {
                    if (socket == channel) {
                        closeChannel();
                    }
                }
                remoteProviders.remove(providerId, this);
                pending.values().forEach(future -> future.completeExceptionally(
                        new IOException("provider channel disconnected")));
                pending.clear();
            }
        }

        private Object callTool(String name, Map<String, Object> arguments) throws Exception {
            if (writer == null || socket == null || socket.isClosed()) {
                throw new IOException("provider is disconnected: " + providerId);
            }
            String requestId = providerId + "-" + providerRequestSequence.incrementAndGet();
            CompletableFuture<Object> future = new CompletableFuture<>();
            pending.put(requestId, future);
            try {
                send(mapOf("type", "call", "requestId", requestId, "name", name,
                        "arguments", arguments == null ? Map.of() : arguments));
                return future.get(PROVIDER_CALL_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
            } finally {
                pending.remove(requestId);
            }
        }

        private synchronized void send(Map<String, Object> frame) {
            if (writer == null) {
                return;
            }
            try {
                writer.write(GSON.toJson(frame));
                writer.write('\n');
                writer.flush();
            } catch (IOException ignored) {
                closeChannel();
            }
        }

        private synchronized void close() {
            closeChannel();
            pending.values().forEach(future -> future.completeExceptionally(
                    new IOException("provider channel closed")));
            pending.clear();
        }

        private synchronized void closeChannel() {
            Socket oldSocket = socket;
            socket = null;
            writer = null;
            if (oldSocket != null) {
                try {
                    oldSocket.close();
                } catch (IOException ignored) {
                    // ignored
                }
            }
        }
    }

    private McpTool findTool(String name) {
        List<McpTool> tools = toolProvider.listTools();
        if (tools == null) {
            return null;
        }
        for (McpTool tool : tools) {
            if (tool != null && name.equals(tool.getName())) {
                return tool;
            }
        }
        for (RemoteProvider provider : remoteProviders.values()) {
            for (McpTool tool : provider.tools) {
                if (tool != null && name.equals(tool.getName())) {
                    return tool;
                }
            }
        }
        return null;
    }

    private RemoteProvider findRemoteProvider(String name) {
        for (RemoteProvider provider : remoteProviders.values()) {
            if (provider.tools.stream().anyMatch(tool -> tool != null && name.equals(tool.getName()))) {
                return provider;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private String validateArguments(Map<String, Object> schema, Map<String, Object> arguments, String path) {
        if (schema == null || schema.isEmpty()) {
            return null;
        }
        Object type = schema.get("type");
        if (type instanceof String typeName && !matchesJsonType(arguments, typeName)) {
            return path + " must be a " + typeName;
        }
        Object required = schema.get("required");
        if (required instanceof Collection<?> requiredNames) {
            for (Object requiredName : requiredNames) {
                if (requiredName instanceof String key && !arguments.containsKey(key)) {
                    return path + "." + key + " is required";
                }
            }
        }
        Object properties = schema.get("properties");
        if (properties instanceof Map<?, ?> rawProperties) {
            for (Map.Entry<?, ?> entry : rawProperties.entrySet()) {
                if (!(entry.getKey() instanceof String key) || !arguments.containsKey(key)
                        || !(entry.getValue() instanceof Map<?, ?> rawSchema)) {
                    continue;
                }
                Map<String, Object> propertySchema = (Map<String, Object>) rawSchema;
                String error = validateValue(arguments.get(key), propertySchema, path + "." + key);
                if (error != null) {
                    return error;
                }
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private String validateValue(Object value, Map<String, Object> schema, String path) {
        if (schema == null || schema.isEmpty()) {
            return null;
        }
        Object type = schema.get("type");
        if (value == null) {
            if ("null".equals(type)) {
                return null;
            }
            return type instanceof String typeName ? path + " must be a " + typeName : null;
        }
        if (type instanceof String typeName && !matchesJsonType(value, typeName)) {
            return path + " must be a " + typeName;
        }
        Object enumValues = schema.get("enum");
        if (enumValues instanceof Collection<?> values && !values.isEmpty()
                && values.stream().noneMatch(candidate -> jsonValuesEqual(candidate, value))) {
            return path + " must be one of " + GSON.toJson(values);
        }
        if (value instanceof Map<?, ?> rawMap && schema.get("properties") instanceof Map<?, ?> rawProperties) {
            Map<String, Object> objectValue = (Map<String, Object>) rawMap;
            Map<String, Object> objectSchema = new LinkedHashMap<>();
            objectSchema.put("required", schema.get("required"));
            objectSchema.put("properties", rawProperties);
            String error = validateArguments(objectSchema, objectValue, path);
            if (error != null) {
                return error;
            }
        }
        if (value instanceof Collection<?> collection && schema.get("items") instanceof Map<?, ?> rawItems) {
            Map<String, Object> itemSchema = (Map<String, Object>) rawItems;
            for (int index = 0; index < collection.size(); index++) {
                Object item = collection instanceof List<?> list ? list.get(index) : collection.toArray()[index];
                String error = validateValue(item, itemSchema, path + "[" + index + "]");
                if (error != null) {
                    return error;
                }
            }
        }
        return null;
    }

    private static boolean matchesJsonType(Object value, String type) {
        return switch (type) {
            case "object" -> value instanceof Map<?, ?>;
            case "array" -> value instanceof Collection<?>;
            case "string" -> value instanceof String;
            case "boolean" -> value instanceof Boolean;
            case "integer" -> value instanceof Number number
                    && Double.isFinite(number.doubleValue())
                    && number.doubleValue() == Math.rint(number.doubleValue());
            case "number" -> value instanceof Number number && Double.isFinite(number.doubleValue());
            case "null" -> value == null;
            default -> true;
        };
    }

    private static boolean jsonValuesEqual(Object left, Object right) {
        if (left instanceof Number leftNumber && right instanceof Number rightNumber) {
            return Double.compare(leftNumber.doubleValue(), rightNumber.doubleValue()) == 0;
        }
        return Objects.equals(left, right);
    }

    private static final class RpcContext {
        private final String requestSessionId;
        private Session session;
        private String protocolVersion;
        private String responseSessionId;

        private RpcContext(String requestSessionId, Session session, String protocolVersion) {
            this.requestSessionId = requestSessionId;
            this.session = session;
            this.protocolVersion = protocolVersion;
        }
    }


    private record HttpRequest(String method, String path, Map<String, String> headers, String body) {
    }

    private record HttpResponse(int status, byte[] body, Map<String, String> headers, String contentType) {
        private HttpResponse(int status, byte[] body, Map<String, String> headers) {
            this(status, body, headers, "application/json; charset=utf-8");
        }
    }
}
