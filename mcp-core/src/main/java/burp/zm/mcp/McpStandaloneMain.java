package burp.zm.mcp;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

/**
 * Command-line launcher for the reusable MCP core.
 *
 * <p>The standalone jar intentionally exposes only small diagnostic tools by
 * default. Applications can provide their own {@link McpToolProvider} through
 * {@code --provider-class}; the class must have a public no-argument
 * constructor.</p>
 */
public final class McpStandaloneMain {

    private static final String DEFAULT_NAME = "mcp-core-standalone";
    private static final String DEFAULT_VERSION = "1.1.2";

    private McpStandaloneMain() {
    }

    public static void main(String[] args) throws Exception {
        Options options;
        try {
            options = Options.parse(args);
        } catch (IllegalArgumentException error) {
            System.err.println("Error: " + error.getMessage());
            printUsage();
            return;
        }
        if (options.help()) {
            printUsage();
            return;
        }

        McpToolProvider provider = options.providerClass() == null
                ? new DemoToolProvider() : loadProvider(options.providerClass());
        McpServer server = options.port() == null
                ? new McpServer(provider, options.name(), options.version())
                : new McpServer(provider, options.name(), options.version(), options.port());
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop, "MCP-server-shutdown"));
        server.start();
        System.out.println("MCP provider started as " + server.getRole().name().toLowerCase()
                + " on " + server.getEndpoint());
        if (server.getRole() == McpServer.Role.CLIENT) {
            System.out.println("Provider registered with the existing shared host on port " + server.getEndpoint());
        }
        System.out.println("Health check: " + server.getEndpoint().replace("/mcp", "/health"));
        System.out.println("Press Ctrl+C to stop.");
        new CountDownLatch(1).await();
    }

    private static McpToolProvider loadProvider(String className) throws Exception {
        Class<?> providerType = Class.forName(className);
        if (!McpToolProvider.class.isAssignableFrom(providerType)) {
            throw new IllegalArgumentException(className + " does not implement McpToolProvider");
        }
        Object instance = providerType.getDeclaredConstructor().newInstance();
        return (McpToolProvider) instance;
    }

    private static void printUsage() {
        System.out.println("Usage: java -jar mcp-core-<version>-standalone.jar [options]");
        System.out.println("Options:");
        System.out.println("  --port <number>             Bind an exact port (default shared host port: 8765)");
        System.out.println("  --name <name>               Server name (default: " + DEFAULT_NAME + ")");
        System.out.println("  --version <version>         Server version (default: " + DEFAULT_VERSION + ")");
        System.out.println("  --provider-class <class>    Load a provider with a public no-arg constructor");
        System.out.println("  --help                      Show this help");
    }

    private record Options(Integer port, String name, String version, String providerClass, boolean help) {

        private static Options parse(String[] args) {
            Integer port = null;
            String name = DEFAULT_NAME;
            String version = DEFAULT_VERSION;
            String providerClass = null;
            boolean help = false;
            for (int index = 0; index < args.length; index++) {
                String argument = args[index];
                switch (argument) {
                    case "--help", "-h" -> help = true;
                    case "--port" -> {
                        String value = nextValue(args, ++index, argument);
                        try {
                            port = Integer.parseInt(value);
                        } catch (NumberFormatException error) {
                            throw new IllegalArgumentException("--port must be an integer");
                        }
                        if (port < 0 || port > 65535) {
                            throw new IllegalArgumentException("--port must be between 0 and 65535");
                        }
                    }
                    case "--name" -> name = nonBlank(nextValue(args, ++index, argument), argument);
                    case "--version" -> version = nonBlank(nextValue(args, ++index, argument), argument);
                    case "--provider-class" -> {
                        providerClass = nonBlank(nextValue(args, ++index, argument), argument);
                    }
                    default -> throw new IllegalArgumentException("unknown option: " + argument);
                }
            }
            return new Options(port, name, version, providerClass, help);
        }

        private static String nextValue(String[] args, int index, String option) {
            if (index >= args.length || args[index].isBlank()) {
                throw new IllegalArgumentException(option + " requires a value");
            }
            return args[index];
        }

        private static String nonBlank(String value, String option) {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException(option + " requires a non-empty value");
            }
            return value;
        }
    }

    private static final class DemoToolProvider implements McpToolProvider {

        @Override
        public List<McpTool> listTools() {
            Map<String, Object> echoSchema = new LinkedHashMap<>();
            echoSchema.put("type", "object");
            echoSchema.put("properties", Map.of("message", Map.of("type", "string")));
            return List.of(
                    new McpTool("standalone.status", "Return standalone server status.",
                            Map.of("type", "object")),
                    new McpTool("standalone.echo", "Echo a message.", echoSchema)
            );
        }

        @Override
        public Object callTool(String name, Map<String, Object> arguments) {
            return switch (name) {
                case "standalone.status" -> Map.of("status", "ok", "runtime", "mcp-core");
                case "standalone.echo" -> Map.of("arguments", arguments == null ? Map.of() : arguments);
                default -> throw new IllegalArgumentException("Unknown tool: " + name);
            };
        }
    }
}
