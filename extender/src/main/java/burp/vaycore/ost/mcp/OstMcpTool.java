package burp.vaycore.ost.mcp;

import java.util.Map;

/**
 * Compatibility name for the generic {@link burp.zm.mcp.McpTool} model.
 */
@Deprecated(forRemoval = false)
public class OstMcpTool extends burp.zm.mcp.McpTool {

    public OstMcpTool(String name, String description, Map<String, Object> inputSchema) {
        super(name, description, inputSchema);
    }

    public OstMcpTool(String name, String description, Map<String, Object> inputSchema,
                      Map<String, Object> annotations) {
        super(name, description, inputSchema, annotations);
    }
}
