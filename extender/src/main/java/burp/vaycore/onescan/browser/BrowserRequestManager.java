package burp.vaycore.onescan.browser;

import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.FileUtils;
import burp.vaycore.common.utils.IOUtils;
import burp.vaycore.common.utils.StringUtils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class BrowserRequestManager {

    private static final String SCRIPT_RESOURCE_PATH = "browser/drission_request.py";
    private static final String SCRIPT_DIR_NAME = "browser";
    private static final String SCRIPT_FILE_NAME = "drission_request.py";
    private static final String PROFILE_DIR_NAME = "profile";
    private static final String STATE_FILE_NAME = "state.txt";
    private static final String REQUEST_FILE_PREFIX = "request-";
    private static final int DEBUG_PORT = 9777;
    private static final long DISCOVERY_COMMAND_TIMEOUT_MILLIS = 1500L;
    private static final long DEFAULT_BRIDGE_TIMEOUT_EXTRA_MILLIS = 5000L;
    private static final long NAVIGATION_POST_BRIDGE_TIMEOUT_EXTRA_MILLIS = 20000L;
    private static final String OS_NAME = System.getProperty("os.name", "").toLowerCase();

    private final String mSessionId = "session-" + Long.toHexString(System.currentTimeMillis())
            + "-" + Integer.toHexString(System.identityHashCode(this));
    private final Object mProcessLock = new Object();
    private volatile Process mActiveProcess;

    public synchronized BrowserResult navigate(String url, String browserType, String browserBinaryPath,
                                               long timeoutMillis, String workDir, String pythonPath) {
        BrowserRequest request = BrowserRequest.of("GET", url, Collections.<String>emptyList(), new byte[0]);
        return navigate(request, browserType, browserBinaryPath, timeoutMillis, workDir, pythonPath, false);
    }

    public synchronized BrowserResult navigate(BrowserRequest request, String browserType, String browserBinaryPath,
                                               long timeoutMillis, String workDir, String pythonPath,
                                               boolean loadStaticResources) {
        if (request == null) {
            throw new IllegalArgumentException("browser request is null");
        }
        if (StringUtils.isEmpty(request.getUrl())) {
            throw new IllegalArgumentException("browser request url is empty");
        }
        if (StringUtils.isEmpty(workDir)) {
            throw new IllegalArgumentException("browser request workdir is empty");
        }

        File scriptFile = ensureScriptFile(workDir);
        File browserWorkDir = new File(workDir, SCRIPT_DIR_NAME);
        File sessionDir = new File(browserWorkDir, mSessionId);
        File profileDir = new File(sessionDir, PROFILE_DIR_NAME);
        File stateFile = new File(sessionDir, STATE_FILE_NAME);
        if (!sessionDir.exists()) {
            //noinspection ResultOfMethodCallIgnored
            sessionDir.mkdirs();
        }
        if (!profileDir.exists()) {
            //noinspection ResultOfMethodCallIgnored
            profileDir.mkdirs();
        }

        File requestFile = null;
        try {
            requestFile = File.createTempFile(REQUEST_FILE_PREFIX, ".txt", sessionDir);
            writeRequestFile(requestFile, request);

            List<String> arguments = new ArrayList<String>();
            arguments.add("--action");
            arguments.add("navigate");
            arguments.add("--request-file");
            arguments.add(requestFile.getAbsolutePath());
            arguments.add("--browser-type");
            arguments.add(StringUtils.isEmpty(browserType) ? "edge" : browserType);
            if (StringUtils.isNotEmpty(browserBinaryPath)) {
                arguments.add("--browser-path");
                arguments.add(browserBinaryPath);
            }
            arguments.add("--timeout-ms");
            arguments.add(String.valueOf(timeoutMillis));
            if (loadStaticResources) {
                arguments.add("--load-static-resources");
            }

            String output = execute(arguments, timeoutMillis + bridgeTimeoutExtraMillis(request), workDir, pythonPath,
                    scriptFile, profileDir, stateFile);
            return parseBrowserResult(output);
        } catch (IOException e) {
            throw new IllegalStateException("browser bridge prepare failed: " + e.getMessage(), e);
        } finally {
            if (requestFile != null && requestFile.exists()) {
                //noinspection ResultOfMethodCallIgnored
                requestFile.delete();
            }
        }
    }

    public synchronized void close(String workDir, String pythonPath, String browserType, String browserBinaryPath) {
        if (StringUtils.isEmpty(workDir)) {
            return;
        }
        try {
            File scriptFile = ensureScriptFile(workDir);
            File browserWorkDir = new File(workDir, SCRIPT_DIR_NAME);
            File sessionDir = new File(browserWorkDir, mSessionId);
            File profileDir = new File(sessionDir, PROFILE_DIR_NAME);
            File stateFile = new File(sessionDir, STATE_FILE_NAME);
            if (!profileDir.exists()) {
                return;
            }

            List<String> arguments = new ArrayList<String>();
            arguments.add("--action");
            arguments.add("cleanup");
            arguments.add("--browser-type");
            arguments.add(StringUtils.isEmpty(browserType) ? "edge" : browserType);
            if (StringUtils.isNotEmpty(browserBinaryPath)) {
                arguments.add("--browser-path");
                arguments.add(browserBinaryPath);
            }
            execute(arguments, 8000L, workDir, pythonPath, scriptFile, profileDir, stateFile);

            arguments = new ArrayList<String>();
            arguments.add("--action");
            arguments.add("close");
            arguments.add("--browser-type");
            arguments.add(StringUtils.isEmpty(browserType) ? "edge" : browserType);
            if (StringUtils.isNotEmpty(browserBinaryPath)) {
                arguments.add("--browser-path");
                arguments.add(browserBinaryPath);
            }
            execute(arguments, 10000L, workDir, pythonPath, scriptFile, profileDir, stateFile);
        } catch (Exception e) {
            Logger.debug("Close browser bridge error: %s", e.getMessage());
        }
    }

    public void cancelCurrentProcess() {
        Process process = mActiveProcess;
        if (process == null) {
            return;
        }
        try {
            process.destroy();
            if (!process.waitFor(800L, TimeUnit.MILLISECONDS)) {
                process.destroyForcibly();
            }
        } catch (Exception e) {
            process.destroyForcibly();
        }
    }

    public void cleanupSessionWorkspace(String workDir) {
        if (StringUtils.isEmpty(workDir)) {
            return;
        }
        File sessionDir = new File(new File(workDir, SCRIPT_DIR_NAME), mSessionId);
        if (sessionDir.exists()) {
            FileUtils.deleteFile(sessionDir);
        }
    }

    private void writeRequestFile(File requestFile, BrowserRequest request) throws IOException {
        BufferedWriter writer = null;
        try {
            writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(requestFile),
                    StandardCharsets.UTF_8));
            writeLine(writer, "METHOD", encodeString(request.getMethod()));
            writeLine(writer, "URL", encodeString(request.getUrl()));
            writeLine(writer, "HEADER_COUNT", String.valueOf(request.getHeaders().size()));
            for (int i = 0; i < request.getHeaders().size(); i++) {
                writeLine(writer, "HEADER_" + i, encodeString(request.getHeaders().get(i)));
            }
            writeLine(writer, "BODY", encodeBytes(request.getBody()));
        } finally {
            IOUtils.closeIO(writer);
        }
    }

    private void writeLine(BufferedWriter writer, String key, String value) throws IOException {
        writer.write(key);
        writer.write('=');
        writer.write(value == null ? "" : value);
        writer.newLine();
    }

    private String execute(List<String> arguments, long timeoutMillis, String workDir, String pythonPath,
                           File scriptFile, File profileDir, File stateFile) {
        List<List<String>> commands = buildPythonCommands(scriptFile, profileDir, stateFile, arguments, pythonPath);
        Exception lastError = null;
        for (List<String> command : commands) {
            try {
                return runCommand(command, timeoutMillis, workDir);
            } catch (Exception e) {
                lastError = e;
                Logger.debug("Run python browser bridge error: %s", e.getMessage());
            }
        }
        throw new IllegalStateException(lastError == null
                ? "python browser bridge execute failed"
                : lastError.getMessage(), lastError);
    }

    private File ensureScriptFile(String workDir) {
        File scriptDir = new File(workDir, SCRIPT_DIR_NAME);
        if (!scriptDir.exists()) {
            //noinspection ResultOfMethodCallIgnored
            scriptDir.mkdirs();
        }
        File scriptFile = new File(scriptDir, SCRIPT_FILE_NAME);
        InputStream is = BrowserRequestManager.class.getClassLoader().getResourceAsStream(SCRIPT_RESOURCE_PATH);
        if (is == null) {
            throw new IllegalStateException("browser bridge script resource not found");
        }
        if (!FileUtils.writeFile(is, scriptFile)) {
            throw new IllegalStateException("write browser bridge script failed");
        }
        return scriptFile;
    }

    private List<List<String>> buildPythonCommands(File scriptFile, File profileDir, File stateFile,
                                                   List<String> arguments, String pythonPath) {
        List<List<String>> commands = new ArrayList<List<String>>();
        Set<String> added = new HashSet<String>();
        if (StringUtils.isNotEmpty(pythonPath)) {
            addWindowsPythonCommand(commands, added, normalizePythonCommand(pythonPath),
                    scriptFile, profileDir, stateFile, arguments);
        }
        if (isMac()) {
            addCommand(commands, added,
                    buildCommand(Arrays.asList("python3"), scriptFile, profileDir, stateFile, arguments));
            addCommand(commands, added,
                    buildCommand(Arrays.asList("python"), scriptFile, profileDir, stateFile, arguments));
        } else if (isWindows()) {
            for (String candidate : findWindowsPythonExecutables()) {
                addWindowsPythonCommand(commands, added, normalizePythonCommand(candidate),
                        scriptFile, profileDir, stateFile, arguments);
            }
            addWindowsPythonCommand(commands, added, Arrays.asList("py", "-3"),
                    scriptFile, profileDir, stateFile, arguments);
            addWindowsPythonCommand(commands, added, Arrays.asList("python"),
                    scriptFile, profileDir, stateFile, arguments);
            addWindowsPythonCommand(commands, added, Arrays.asList("python3"),
                    scriptFile, profileDir, stateFile, arguments);
        } else {
            addCommand(commands, added,
                    buildCommand(Arrays.asList("python3"), scriptFile, profileDir, stateFile, arguments));
            addCommand(commands, added,
                    buildCommand(Arrays.asList("python"), scriptFile, profileDir, stateFile, arguments));
            addCommand(commands, added,
                    buildCommand(Arrays.asList("py", "-3"), scriptFile, profileDir, stateFile, arguments));
        }
        return commands;
    }

    private void addCommand(List<List<String>> commands, Set<String> added, List<String> command) {
        if (command == null || command.isEmpty()) {
            return;
        }
        String key = String.join("\u0000", command);
        if (added.add(key)) {
            commands.add(command);
        }
    }

    private void addWindowsPythonCommand(List<List<String>> commands, Set<String> added, List<String> pythonCommand,
                                         File scriptFile, File profileDir, File stateFile, List<String> arguments) {
        if (pythonCommand == null || pythonCommand.isEmpty()) {
            return;
        }
        addCommand(commands, added, buildCommand(pythonCommand, scriptFile, profileDir, stateFile, arguments));
        String executable = pythonCommand.get(0);
        if (pythonCommand.size() == 1 && isPythonLauncher(executable)) {
            List<String> launcherCommand = new ArrayList<String>(pythonCommand);
            launcherCommand.add("-3");
            addCommand(commands, added, buildCommand(launcherCommand, scriptFile, profileDir, stateFile, arguments));
        }
    }

    private List<String> findWindowsPythonExecutables() {
        Set<String> result = new LinkedHashSet<String>();
        addProcessOutputCandidates(result, "where.exe", "python.exe");
        addProcessOutputCandidates(result, "where.exe", "python3.exe");
        addProcessOutputCandidates(result, "where.exe", "py.exe");
        addPythonLauncherCandidates(result);
        addPathCandidates(result);

        List<File> searchRoots = new ArrayList<File>();
        addSearchRoot(searchRoots, System.getenv("LOCALAPPDATA"), "Programs", "Python");
        addSearchRoot(searchRoots, System.getenv("PROGRAMFILES"), "Python");
        addSearchRoot(searchRoots, System.getenv("PROGRAMFILES(X86)"), "Python");
        for (File root : searchRoots) {
            File[] subDirs = root.listFiles(File::isDirectory);
            if (subDirs == null) {
                continue;
            }
            Arrays.sort(subDirs, (a, b) -> b.getName().compareToIgnoreCase(a.getName()));
            for (File dir : subDirs) {
                addFileIfExists(result, new File(dir, "python.exe"));
                addFileIfExists(result, new File(dir, "python3.exe"));
                addFileIfExists(result, new File(dir, "py.exe"));
            }
        }
        return new ArrayList<String>(result);
    }

    private void addSearchRoot(List<File> roots, String parentPath, String... children) {
        if (StringUtils.isEmpty(parentPath)) {
            return;
        }
        File root = new File(parentPath);
        for (String child : children) {
            root = new File(root, child);
        }
        if (root.isDirectory()) {
            roots.add(root);
        }
    }

    private void addPythonLauncherCandidates(Set<String> result) {
        for (String line : runProcessAndCollectOutput(Arrays.asList("py", "-0p"))) {
            String candidate = line.trim();
            if (candidate.startsWith("-")) {
                int separator = candidate.indexOf('-');
                candidate = separator >= 0 ? candidate.substring(separator + 1).trim() : candidate;
            }
            int separator = candidate.indexOf(" *");
            if (separator >= 0) {
                candidate = candidate.substring(separator + 2).trim();
            }
            separator = candidate.indexOf("  ");
            if (separator >= 0) {
                candidate = candidate.substring(separator).trim();
            }
            addCandidate(result, candidate);
        }
    }

    private void addPathCandidates(Set<String> result) {
        String pathValue = System.getenv("Path");
        if (StringUtils.isEmpty(pathValue)) {
            return;
        }
        for (String item : pathValue.split(File.pathSeparator)) {
            if (StringUtils.isEmpty(item)) {
                continue;
            }
            File dir = new File(stripWrappingQuotes(item.trim()));
            addFileIfExists(result, new File(dir, "python.exe"));
            addFileIfExists(result, new File(dir, "python3.exe"));
            addFileIfExists(result, new File(dir, "py.exe"));
        }
    }

    private void addProcessOutputCandidates(Set<String> result, String... command) {
        for (String line : runProcessAndCollectOutput(Arrays.asList(command))) {
            addCandidate(result, line);
        }
    }

    private List<String> runProcessAndCollectOutput(List<String> command) {
        List<String> lines = new ArrayList<String>();
        Process process = null;
        try {
            process = new ProcessBuilder(command).redirectErrorStream(true).start();
            BufferedReader reader = null;
            try {
                reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    if (StringUtils.isNotEmpty(line)) {
                        lines.add(line.trim());
                    }
                }
            } finally {
                IOUtils.closeIO(reader);
            }
            if (!process.waitFor(DISCOVERY_COMMAND_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)) {
                process.destroyForcibly();
            }
        } catch (Exception ignored) {
            if (process != null) {
                process.destroyForcibly();
            }
        }
        return lines;
    }

    private void addCandidate(Set<String> result, String candidate) {
        String normalized = normalizeCandidatePath(candidate);
        if (StringUtils.isEmpty(normalized)) {
            return;
        }
        File file = new File(normalized);
        if (file.isFile()) {
            result.add(file.getAbsolutePath());
        }
    }

    private void addFileIfExists(Set<String> result, File file) {
        if (file != null && file.isFile()) {
            result.add(file.getAbsolutePath());
        }
    }

    private List<String> normalizePythonCommand(String pythonPath) {
        String normalized = normalizeCandidatePath(pythonPath);
        if (StringUtils.isEmpty(normalized)) {
            return Arrays.asList(pythonPath);
        }
        File file = new File(normalized);
        if (file.isDirectory() && isWindows()) {
            File pythonExe = new File(file, "python.exe");
            if (pythonExe.isFile()) {
                return Arrays.asList(pythonExe.getAbsolutePath());
            }
            File python3Exe = new File(file, "python3.exe");
            if (python3Exe.isFile()) {
                return Arrays.asList(python3Exe.getAbsolutePath());
            }
            File launcherExe = new File(file, "py.exe");
            if (launcherExe.isFile()) {
                return Arrays.asList(launcherExe.getAbsolutePath());
            }
        }
        return Arrays.asList(normalized);
    }

    private String normalizeCandidatePath(String candidate) {
        if (StringUtils.isEmpty(candidate)) {
            return null;
        }
        String normalized = stripWrappingQuotes(candidate.trim());
        if (StringUtils.isEmpty(normalized)) {
            return null;
        }
        if (normalized.startsWith("*")) {
            normalized = normalized.substring(1).trim();
        }
        if (normalized.startsWith("-")) {
            int index = normalized.indexOf('\\');
            if (index > 0) {
                normalized = normalized.substring(index);
            }
        }
        return stripWrappingQuotes(normalized);
    }

    private String stripWrappingQuotes(String value) {
        if (StringUtils.isEmpty(value)) {
            return value;
        }
        String result = value;
        if ((result.startsWith("\"") && result.endsWith("\""))
                || (result.startsWith("'") && result.endsWith("'"))) {
            result = result.substring(1, result.length() - 1);
        }
        return result.trim();
    }

    private boolean isPythonLauncher(String executable) {
        if (StringUtils.isEmpty(executable)) {
            return false;
        }
        String lower = executable.toLowerCase();
        return "py".equals(lower) || "py.exe".equals(lower) || lower.endsWith("\\py.exe");
    }

    private boolean isWindows() {
        return OS_NAME.contains("win");
    }

    private boolean isMac() {
        return OS_NAME.contains("mac");
    }

    private List<String> buildCommand(List<String> pythonCommand, File scriptFile,
                                      File profileDir, File stateFile, List<String> arguments) {
        List<String> command = new ArrayList<String>(pythonCommand);
        command.add(scriptFile.getAbsolutePath());
        command.add("--port");
        command.add(String.valueOf(DEBUG_PORT));
        command.add("--user-data-path");
        command.add(profileDir.getAbsolutePath());
        command.add("--state-file");
        command.add(stateFile.getAbsolutePath());
        command.addAll(arguments);
        return command;
    }

    private String runCommand(List<String> command, long timeoutMillis, String workDir) throws Exception {
        if (Thread.currentThread().isInterrupted()) {
            throw new IllegalStateException("python browser bridge cancelled");
        }
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);
        builder.directory(new File(workDir));
        Process process = builder.start();
        StringBuilder output = new StringBuilder();
        Thread outputReader = startOutputReader(process.getInputStream(), output);
        synchronized (mProcessLock) {
            mActiveProcess = process;
        }
        try {
            boolean completed;
            try {
                completed = process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                process.destroyForcibly();
                Thread.currentThread().interrupt();
                throw new IllegalStateException("python browser bridge cancelled", e);
            }
            if (!completed) {
                process.destroyForcibly();
                joinOutputReader(outputReader);
                throw new IllegalStateException("python browser bridge timeout");
            }
            joinOutputReader(outputReader);
            String outputText = output.toString();
            int exitCode = process.exitValue();
            if (Thread.currentThread().isInterrupted()) {
                throw new IllegalStateException("python browser bridge cancelled");
            }
            if (exitCode != 0) {
                throw new IllegalStateException(String.format("python browser bridge exit=%d output=%s",
                        exitCode, outputText));
            }
            return outputText;
        } finally {
            synchronized (mProcessLock) {
                if (mActiveProcess == process) {
                    mActiveProcess = null;
                }
            }
        }
    }

    private Thread startOutputReader(InputStream is, StringBuilder output) {
        Thread thread = new Thread(() -> {
            BufferedReader reader = null;
            try {
                reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
                String line;
                while ((line = reader.readLine()) != null) {
                    synchronized (output) {
                        if (output.length() > 0) {
                            output.append('\n');
                        }
                        output.append(line);
                    }
                }
            } catch (IOException ignored) {
            } finally {
                IOUtils.closeIO(reader);
                IOUtils.closeIO(is);
            }
        }, "OneScan-browser-output");
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    private void joinOutputReader(Thread outputReader) {
        if (outputReader == null) {
            return;
        }
        try {
            outputReader.join(1000L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private BrowserResult parseBrowserResult(String output) {
        if (StringUtils.isEmpty(output)) {
            throw new IllegalStateException("python browser bridge output is empty");
        }
        Map<String, String> lines = parseKeyValueLines(output);
        int headerCount = parseInt(lines.get("HEADER_COUNT"), 0);
        Map<String, String> headers = new LinkedHashMap<String, String>();
        for (int i = 0; i < headerCount; i++) {
            String header = decodeString(lines.get("HEADER_" + i));
            int index = header.indexOf(':');
            if (index <= 0) {
                continue;
            }
            headers.put(header.substring(0, index).trim(), header.substring(index + 1).trim());
        }
        return new BrowserResult(
                parseInt(lines.get("STATUS"), -1),
                decodeString(lines.get("REASON")),
                headers,
                decodeBytes(lines.get("BODY")),
                decodeString(lines.get("FINAL_URL")),
                decodeString(lines.get("TITLE"))
        );
    }

    private Map<String, String> parseKeyValueLines(String output) {
        Map<String, String> result = new LinkedHashMap<String, String>();
        String[] lines = output.split("\\r?\\n");
        for (String line : lines) {
            int index = line.indexOf('=');
            if (index <= 0) {
                continue;
            }
            result.put(line.substring(0, index), line.substring(index + 1));
        }
        return result;
    }

    private String encodeString(String value) {
        return Base64.getEncoder().encodeToString((value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
    }

    private String encodeBytes(byte[] value) {
        return Base64.getEncoder().encodeToString(value == null ? new byte[0] : value);
    }

    private String decodeString(String value) {
        if (StringUtils.isEmpty(value)) {
            return "";
        }
        try {
            return new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8);
        } catch (Exception ignored) {
            return "";
        }
    }

    private byte[] decodeBytes(String value) {
        if (StringUtils.isEmpty(value)) {
            return new byte[0];
        }
        try {
            return Base64.getDecoder().decode(value);
        } catch (Exception ignored) {
            return new byte[0];
        }
    }

    private int parseInt(String value, int defValue) {
        if (StringUtils.isEmpty(value)) {
            return defValue;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (Exception ignored) {
            return defValue;
        }
    }

    private long bridgeTimeoutExtraMillis(BrowserRequest request) {
        if (request == null) {
            return DEFAULT_BRIDGE_TIMEOUT_EXTRA_MILLIS;
        }
        String method = request.getMethod();
        if ("POST".equalsIgnoreCase(method) || request.getBody().length > 0) {
            return NAVIGATION_POST_BRIDGE_TIMEOUT_EXTRA_MILLIS;
        }
        return DEFAULT_BRIDGE_TIMEOUT_EXTRA_MILLIS;
    }

    public static class BrowserResult {
        private final int status;
        private final String reason;
        private final Map<String, String> headers;
        private final byte[] bodyBytes;
        private final String finalUrl;
        private final String title;

        private BrowserResult(int status, String reason, Map<String, String> headers,
                              byte[] bodyBytes, String finalUrl, String title) {
            this.status = status;
            this.reason = reason == null ? "" : reason;
            this.headers = headers == null ? new LinkedHashMap<String, String>() : headers;
            this.bodyBytes = bodyBytes == null ? new byte[0] : bodyBytes;
            this.finalUrl = finalUrl == null ? "" : finalUrl;
            this.title = title == null ? "" : title;
        }

        public int getStatus() {
            return status;
        }

        public String getReason() {
            return reason;
        }

        public Map<String, String> getHeaders() {
            return headers;
        }

        public byte[] getBodyBytes() {
            return bodyBytes;
        }

        public String getFinalUrl() {
            return finalUrl;
        }

        public String getTitle() {
            return title;
        }
    }
}
