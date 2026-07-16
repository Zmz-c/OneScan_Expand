package burp.vaycore.ost.mcp;

import java.util.Map;

public class OstMcpTool {

    private final String name;
    private final String description;
    private final Map<String, Object> inputSchema;

    public OstMcpTool(String name, String description, Map<String, Object> inputSchema) {
        this.name = name;
        this.description = description;
        this.inputSchema = inputSchema;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public Map<String, Object> getInputSchema() {
        return inputSchema;
    }
}
