package burp.vaycore.onescan.mcp;

import java.util.List;
import java.util.Map;

public interface OneScanMcpToolProvider {

    List<OneScanMcpTool> listTools();

    Object callTool(String name, Map<String, Object> arguments) throws Exception;
}
