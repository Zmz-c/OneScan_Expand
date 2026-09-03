package burp.zm.mcp;

import java.util.List;
import java.util.Map;

public interface McpToolProvider {

    List<McpTool> listTools();

    Object callTool(String name, Map<String, Object> arguments) throws Exception;
}
