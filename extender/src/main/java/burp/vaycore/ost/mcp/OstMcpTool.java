package burp.vaycore.ost.mcp;

import java.util.Map;
import java.util.LinkedHashMap;

public class OstMcpTool {

    private final String name;
    private final String description;
    private final Map<String, Object> inputSchema;
    private final Map<String, Object> annotations;

    public OstMcpTool(String name, String description, Map<String, Object> inputSchema) {
        this(name, description, inputSchema, new LinkedHashMap<>());
    }

    public OstMcpTool(String name, String description, Map<String, Object> inputSchema,
                      Map<String, Object> annotations) {
        this.name = name;
        this.description = description;
        this.inputSchema = inputSchema;
        this.annotations = annotations == null ? new LinkedHashMap<>() : new LinkedHashMap<>(annotations);
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

    public Map<String, Object> getAnnotations() {
        return annotations;
    }
}
