package burp.vaycore.ost.mcp;

import burp.zm.mcp.McpServer;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * Backwards-compatible OST facade for the reusable MCP core server.
 *
 * <p>OST keeps this type so existing integrations do not need to change their
 * imports. New Burp extensions should depend on {@link McpServer} directly.</p>
 */
@Deprecated(forRemoval = false)
public class OstMcpServer {

    public static final int DEFAULT_PORT = McpServer.DEFAULT_PORT;
    public static final String CURRENT_PROTOCOL_VERSION = McpServer.CURRENT_PROTOCOL_VERSION;

    private final McpServer delegate;

    public OstMcpServer(OstMcpToolProvider toolProvider) {
        this(toolProvider, "0.1.0");
    }

    public OstMcpServer(OstMcpToolProvider toolProvider, String serverVersion) {
        this.delegate = new McpServer(adapt(toolProvider), "ost-burp-mcp", serverVersion);
    }

    OstMcpServer(OstMcpToolProvider toolProvider, int port) {
        this.delegate = new McpServer(adapt(toolProvider), "ost-burp-mcp", "0.1.0", port);
    }

    public void start() throws IOException {
        delegate.start();
    }

    public void stop() {
        delegate.stop();
    }

    public String getEndpoint() {
        return delegate.getEndpoint();
    }

    private static burp.zm.mcp.McpToolProvider adapt(OstMcpToolProvider provider) {
        if (provider == null) {
            throw new IllegalArgumentException("toolProvider is null");
        }
        return new burp.zm.mcp.McpToolProvider() {
            @Override
            public List<burp.zm.mcp.McpTool> listTools() {
                return provider.listTools().stream()
                        .map(tool -> (burp.zm.mcp.McpTool) tool)
                        .toList();
            }

            @Override
            public Object callTool(String name, Map<String, Object> arguments) throws Exception {
                return provider.callTool(name, arguments);
            }
        };
    }
}
