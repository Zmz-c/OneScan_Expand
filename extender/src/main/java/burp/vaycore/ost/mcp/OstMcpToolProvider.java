package burp.vaycore.ost.mcp;

import java.util.List;
import java.util.Map;

public interface OstMcpToolProvider {

    List<OstMcpTool> listTools();

    Object callTool(String name, Map<String, Object> arguments) throws Exception;
}
