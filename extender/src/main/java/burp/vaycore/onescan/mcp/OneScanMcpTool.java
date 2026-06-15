package burp.vaycore.onescan.mcp;

import java.util.Map;

public class OneScanMcpTool {

    private final String name;
    private final String description;
    private final Map<String, Object> inputSchema;

    public OneScanMcpTool(String name, String description, Map<String, Object> inputSchema) {
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
