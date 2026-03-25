package burp.vaycore.onescan.browser;

import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.FileUtils;
import burp.vaycore.common.utils.IOUtils;
import burp.vaycore.common.utils.StringUtils;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public class BrowserRequestManager {

    private static final String SCRIPT_RESOURCE_PATH = "browser/drission_request.py";
    private static final String SCRIPT_DIR_NAME = "browser";
    private static final String SCRIPT_FILE_NAME = "drission_request.py";
    private static final String PROFILE_DIR_NAME = "profile";
    private static final String STATE_FILE_NAME = "state.json";
    private static final int DEBUG_PORT = 9777;
    private static final String OS_NAME = System.getProperty("os.name", "").toLowerCase();
    private final String mSessionId = "session-" + Long.toHexString(System.currentTimeMillis())
            + "-" + Integer.toHexString(System.identityHashCode(this));
    private final Object mProcessLock = new Object();
    private volatile Process mActiveProcess;

    public synchronized BrowserResult navigate(String url, String browserType, String browserBinaryPath,
                                               long timeoutMillis, String workDir, String pythonPath) {
        if (StringUtils.isEmpty(url)) {
            throw new IllegalArgumentException("browser request url is empty");
        }
        if (StringUtils.isEmpty(workDir)) {
            throw new IllegalArgumentException("browser request workdir is empty");
        }
        List<String> arguments = new ArrayList<>();
        arguments.add("--action");
        arguments.add("navigate");
        arguments.add("--url");
        arguments.add(url);
        arguments.add("--browser-type");
        arguments.add(StringUtils.isEmpty(browserType) ? "edge" : browserType);
        if (StringUtils.isNotEmpty(browserBinaryPath)) {
            arguments.add("--browser-path");
            arguments.add(browserBinaryPath);
        }
        arguments.add("--timeout-ms");
        arguments.add(String.valueOf(timeoutMillis));
        String output = execute(arguments, timeoutMillis + 5000L, workDir, pythonPath);
        return parseBrowserResult(output);
    }

    public synchronized void close(String workDir, String pythonPath, String browserType, String browserBinaryPath) {
        if (StringUtils.isEmpty(workDir)) {
            return;
        }
        try {
            List<String> arguments = new ArrayList<>();
            arguments.add("--action");
            arguments.add("close");
            arguments.add("--browser-type");
            arguments.add(StringUtils.isEmpty(browserType) ? "edge" : browserType);
            if (StringUtils.isNotEmpty(browserBinaryPath)) {
                arguments.add("--browser-path");
                arguments.add(browserBinaryPath);
            }
            execute(arguments, 10000L, workDir, pythonPath);
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

    private String execute(List<String> arguments, long timeoutMillis, String workDir, String pythonPath) {
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
        List<List<String>> commands = new ArrayList<>();
        Set<String> added = new HashSet<>();
        if (StringUtils.isNotEmpty(pythonPath)) {
            addCommand(commands, added,
                    buildCommand(Arrays.asList(pythonPath), scriptFile, profileDir, stateFile, arguments));
        }
        if (isMac()) {
            addCommand(commands, added,
                    buildCommand(Arrays.asList("python3"), scriptFile, profileDir, stateFile, arguments));
            addCommand(commands, added,
                    buildCommand(Arrays.asList("python"), scriptFile, profileDir, stateFile, arguments));
        } else if (isWindows()) {
            for (String candidate : findWindowsPythonExecutables()) {
                addCommand(commands, added,
                        buildCommand(Arrays.asList(candidate), scriptFile, profileDir, stateFile, arguments));
            }
            addCommand(commands, added,
                    buildCommand(Arrays.asList("py", "-3"), scriptFile, profileDir, stateFile, arguments));
            addCommand(commands, added,
                    buildCommand(Arrays.asList("python"), scriptFile, profileDir, stateFile, arguments));
            addCommand(commands, added,
                    buildCommand(Arrays.asList("python3"), scriptFile, profileDir, stateFile, arguments));
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

    private List<String> findWindowsPythonExecutables() {
        List<String> result = new ArrayList<>();
        List<File> searchRoots = new ArrayList<>();
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
                File pythonExe = new File(dir, "python.exe");
                if (pythonExe.isFile()) {
                    result.add(pythonExe.getAbsolutePath());
                }
            }
        }
        return result;
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

    private boolean isWindows() {
        return OS_NAME.contains("win");
    }

    private boolean isMac() {
        return OS_NAME.contains("mac");
    }

    private List<String> buildCommand(List<String> pythonCommand, File scriptFile,
                                      File profileDir, File stateFile, List<String> arguments) {
        List<String> command = new ArrayList<>(pythonCommand);
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
                completed = process.waitFor(timeoutMillis, java.util.concurrent.TimeUnit.MILLISECONDS);
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
                reader = new BufferedReader(new InputStreamReader(is));
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
        JsonObject object = JsonParser.parseString(output).getAsJsonObject();
        int status = getAsInt(object, "status", -1);
        String reason = getAsString(object, "reason");
        String finalUrl = getAsString(object, "final_url");
        String title = getAsString(object, "title");
        byte[] bodyBytes = decodeBody(object.get("body_base64"));
        Map<String, String> headers = parseHeaders(object.get("headers"));
        return new BrowserResult(status, reason, headers, bodyBytes, finalUrl, title);
    }

    private int getAsInt(JsonObject object, String key, int defValue) {
        if (object == null || !object.has(key) || object.get(key).isJsonNull()) {
            return defValue;
        }
        try {
            return object.get(key).getAsInt();
        } catch (Exception e) {
            return defValue;
        }
    }

    private String getAsString(JsonObject object, String key) {
        if (object == null || !object.has(key) || object.get(key).isJsonNull()) {
            return "";
        }
        try {
            return object.get(key).getAsString();
        } catch (Exception e) {
            return "";
        }
    }

    private byte[] decodeBody(JsonElement element) {
        if (element == null || element.isJsonNull()) {
            return new byte[0];
        }
        try {
            String value = element.getAsString();
            if (StringUtils.isEmpty(value)) {
                return new byte[0];
            }
            return Base64.getDecoder().decode(value);
        } catch (Exception e) {
            return new byte[0];
        }
    }

    private Map<String, String> parseHeaders(JsonElement element) {
        Map<String, String> headers = new LinkedHashMap<>();
        if (element == null || element.isJsonNull()) {
            return headers;
        }
        if (element.isJsonArray()) {
            JsonArray array = element.getAsJsonArray();
            for (JsonElement item : array) {
                if (item == null || item.isJsonNull()) {
                    continue;
                }
                String header = item.getAsString();
                int index = header.indexOf(':');
                if (index <= 0) {
                    continue;
                }
                headers.put(header.substring(0, index).trim(), header.substring(index + 1).trim());
            }
            return headers;
        }
        if (!element.isJsonObject()) {
            return headers;
        }
        JsonObject object = element.getAsJsonObject();
        for (Map.Entry<String, JsonElement> entry : object.entrySet()) {
            headers.put(entry.getKey(), entry.getValue().isJsonNull() ? "" : entry.getValue().getAsString());
        }
        return headers;
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
            this.reason = reason;
            this.headers = headers;
            this.bodyBytes = bodyBytes == null ? new byte[0] : bodyBytes;
            this.finalUrl = finalUrl;
            this.title = title;
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
