package burp.vaycore.ost.browser;

import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.FileUtils;
import burp.vaycore.common.utils.IOUtils;
import burp.vaycore.common.utils.StringUtils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.AtomicMoveNotSupportedException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;

public class BrowserRequestManager {

    private static final String SCRIPT_RESOURCE_PATH = "browser/drission_request.py";
    private static final String SCRIPT_DIR_NAME = "browser";
    private static final String SCRIPT_FILE_NAME = "drission_request.py";
    private static final String PROFILE_DIR_NAME = "profile";
    private static final String STATE_FILE_NAME = "state.txt";
    private static final String REQUEST_FILE_PREFIX = "request-";
    private static final int FIRST_DEBUG_PORT = 9777;
    private static final int LAST_DEBUG_PORT = 30000;
    private static final long DISCOVERY_COMMAND_TIMEOUT_MILLIS = 1500L;
    private static final long DEFAULT_BRIDGE_TIMEOUT_EXTRA_MILLIS = 5000L;
    private static final long NAVIGATION_POST_BRIDGE_TIMEOUT_EXTRA_MILLIS = 20000L;
    private static final String OS_NAME = System.getProperty("os.name", "").toLowerCase();

    private static final Object DEBUG_PORT_LOCK = new Object();
    private static final Set<Integer> RESERVED_DEBUG_PORTS = new HashSet<Integer>();
    private static int sNextDebugPort = FIRST_DEBUG_PORT;

    private final ConcurrentMap<String, BrowserSession> mSessions = new ConcurrentHashMap<String, BrowserSession>();
    private final Set<BrowserSession> mRetiredSessions = ConcurrentHashMap.newKeySet();
    private final java.util.concurrent.atomic.AtomicLong mSessionSequence = new java.util.concurrent.atomic.AtomicLong();

    public BrowserResult navigate(String url, String browserType, String browserBinaryPath,
                                  long timeoutMillis, String workDir, String pythonPath) {
        BrowserRequest request = BrowserRequest.of("GET", url, List.of(), new byte[0]);
        return navigate(request, browserType, browserBinaryPath, timeoutMillis, workDir, pythonPath, false);
    }

    public BrowserResult navigate(BrowserRequest request, String browserType, String browserBinaryPath,
                                  long timeoutMillis, String workDir, String pythonPath,
                                  boolean loadStaticResources) {
        return navigate(request, browserType, browserBinaryPath, timeoutMillis, workDir, pythonPath,
                loadStaticResources, null);
    }

    public BrowserResult navigate(BrowserRequest request, String browserType, String browserBinaryPath,
                                  long timeoutMillis, String workDir, String pythonPath,
                                  boolean loadStaticResources, Predicate<String> scopeCheck) {
        if (request == null) {
            throw new IllegalArgumentException("browser request is null");
        }
        if (StringUtils.isEmpty(request.getUrl())) {
            throw new IllegalArgumentException("browser request url is empty");
        }
        if (StringUtils.isEmpty(workDir)) {
            throw new IllegalArgumentException("browser request workdir is empty");
        }

        BrowserSession session = getSession(request.getBrowserId());
        synchronized (session) {
            session.scopeCheck = scopeCheck;
            try {
                return navigateInSession(session, request, browserType, browserBinaryPath, timeoutMillis,
                        workDir, pythonPath, loadStaticResources);
            } finally {
                session.scopeCheck = null;
            }
        }
    }

    private BrowserResult navigateInSession(BrowserSession session, BrowserRequest request, String browserType,
                                             String browserBinaryPath, long timeoutMillis, String workDir,
                                             String pythonPath, boolean loadStaticResources) {

        File scriptFile = ensureScriptFile(workDir);
        File browserWorkDir = new File(workDir, SCRIPT_DIR_NAME);
        File sessionDir = new File(browserWorkDir, session.sessionId);
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
            writeRequestFile(requestFile, request, session.scopeCheck != null);

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

            String output = execute(session, arguments, timeoutMillis + bridgeTimeoutExtraMillis(request), workDir,
                    pythonPath, scriptFile, profileDir, stateFile);
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

    public void close(String workDir, String pythonPath, String browserType, String browserBinaryPath) {
        closeSessions(allSessions(), workDir, pythonPath, browserType, browserBinaryPath);
    }

    /** Capture and retire old profiles before workers for the next scan are opened. */
    public Runnable detachSessionsForClose(String workDir, String pythonPath, String browserType, String browserBinaryPath) {
        List<BrowserSession> retired;
        synchronized (mSessions) {
            retired = new ArrayList<>(mSessions.values());
            mSessions.clear();
            mRetiredSessions.addAll(retired);
        }
        return () -> closeSessions(retired, workDir, pythonPath, browserType, browserBinaryPath);
    }

    private List<BrowserSession> allSessions() {
        synchronized (mSessions) {
            List<BrowserSession> result = new ArrayList<>(mSessions.values());
            result.addAll(mRetiredSessions);
            return result;
        }
    }

    private void closeSessions(List<BrowserSession> sessions, String workDir, String pythonPath,
                               String browserType, String browserBinaryPath) {
        if (StringUtils.isEmpty(workDir)) return;
        for (BrowserSession session : sessions) {
            synchronized (session) {
                closeSession(session, workDir, pythonPath, browserType, browserBinaryPath);
            }
        }
    }

    private void closeSession(BrowserSession session, String workDir, String pythonPath,
                              String browserType, String browserBinaryPath) {
        if (session.closed) return;
        try {
            File scriptFile = ensureScriptFile(workDir);
            File browserWorkDir = new File(workDir, SCRIPT_DIR_NAME);
            File sessionDir = new File(browserWorkDir, session.sessionId);
            File profileDir = new File(sessionDir, PROFILE_DIR_NAME);
            File stateFile = new File(sessionDir, STATE_FILE_NAME);
            if (!profileDir.exists()) {
                session.closed = true;
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
            execute(session, arguments, 8000L, workDir, pythonPath, scriptFile, profileDir, stateFile);

            arguments = new ArrayList<String>();
            arguments.add("--action");
            arguments.add("close");
            arguments.add("--browser-type");
            arguments.add(StringUtils.isEmpty(browserType) ? "edge" : browserType);
            if (StringUtils.isNotEmpty(browserBinaryPath)) {
                arguments.add("--browser-path");
                arguments.add(browserBinaryPath);
            }
            execute(session, arguments, 10000L, workDir, pythonPath, scriptFile, profileDir, stateFile);
            session.closed = true;
        } catch (Exception e) {
            Logger.debug("Close browser bridge error: %s", e.getMessage());
        }
    }

    public void cancelCurrentProcess() {
        for (BrowserSession session : allSessions()) {
            Process process;
            synchronized (session.processLock) {
                process = session.activeProcess;
            }
            if (process == null) {
                continue;
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
    }

    public void cleanupSessionWorkspace(String workDir) {
        if (StringUtils.isEmpty(workDir)) {
            return;
        }
        File browserWorkDir = new File(workDir, SCRIPT_DIR_NAME);
        for (BrowserSession session : allSessions()) {
            File sessionDir = new File(browserWorkDir, session.sessionId);
            if (sessionDir.exists()) {
                FileUtils.deleteFile(sessionDir);
            }
        }
    }

    private void writeRequestFile(File requestFile, BrowserRequest request, boolean scopeCheck) throws IOException {
        BufferedWriter writer = null;
        try {
            writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(requestFile),
                    StandardCharsets.UTF_8));
            writeLine(writer, "SCOPE_CHECK", String.valueOf(scopeCheck));
            writeLine(writer, "METHOD", encodeString(request.getMethod()));
            writeLine(writer, "URL", encodeString(request.getUrl()));
            writeLine(writer, "ISOLATE_COOKIES", String.valueOf(request.isolateCookies()));
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

    private String execute(BrowserSession session, List<String> arguments, long timeoutMillis, String workDir,
                           String pythonPath, File scriptFile, File profileDir, File stateFile) {
        List<List<String>> commands = buildPythonCommands(scriptFile, profileDir, stateFile, arguments, pythonPath,
                session.debugPort);
        return executeCommands(commands, command -> runCommand(session, command, timeoutMillis, workDir));
    }

    @FunctionalInterface
    interface BridgeCommandRunner {
        String run(List<String> command) throws Exception;
    }

    static String executeCommands(List<List<String>> commands, BridgeCommandRunner runner) {
        Exception lastError = null;
        for (List<String> command : commands) {
            try {
                return runner.run(command);
            } catch (IOException e) {
                lastError = e;
                Logger.debug("Run python browser bridge error: %s", e.getMessage());
            } catch (Exception e) {
                // Importing DrissionPage happens before the bridge can send a request. An interpreter
                // without the package is safe to skip; another installed Python may have it.
                if (isMissingDrissionPage(e)) {
                    lastError = e;
                    Logger.debug("Python interpreter has no DrissionPage, trying next candidate: %s", command.get(0));
                    continue;
                }
                // Other failures may occur after navigation starts; retrying could replay a POST.
                throw new IllegalStateException("python browser bridge execute failed: " + e.getMessage(), e);
            }
        }
        if (isMissingDrissionPage(lastError)) {
            throw new IllegalStateException("DrissionPage is not available in any detected Python interpreter. "
                    + "Install it in the Python selected in Browser settings or select an interpreter "
                    + "where it is installed.", lastError);
        }
        throw new IllegalStateException(lastError == null
                ? "python browser bridge execute failed"
                : lastError.getMessage(), lastError);
    }

    static boolean isMissingDrissionPage(Throwable error) {
        for (Throwable current = error; current != null; current = current.getCause()) {
            String message = current.getMessage();
            if (message != null && message.contains("No module named 'DrissionPage'")) {
                return true;
            }
        }
        return false;
    }

    private synchronized File ensureScriptFile(String workDir) {
        // Sessions share the script, not their execution lock. Never truncate a
        // script another Python process may be opening during concurrent startup.
        Path scriptDir = new File(workDir, SCRIPT_DIR_NAME).toPath();
        Path scriptFile = scriptDir.resolve(SCRIPT_FILE_NAME);
        Path temporary = null;
        try (InputStream is = BrowserRequestManager.class.getClassLoader().getResourceAsStream(SCRIPT_RESOURCE_PATH)) {
            if (is == null) throw new IllegalStateException("browser bridge script resource not found");
            byte[] content = is.readAllBytes();
            Files.createDirectories(scriptDir);
            if (Files.isRegularFile(scriptFile) && Arrays.equals(content, Files.readAllBytes(scriptFile))) {
                return scriptFile.toFile();
            }
            temporary = Files.createTempFile(scriptDir, SCRIPT_FILE_NAME, ".tmp");
            Files.write(temporary, content);
            try {
                Files.move(temporary, scriptFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temporary, scriptFile, StandardCopyOption.REPLACE_EXISTING);
            }
            return scriptFile.toFile();
        } catch (IOException e) {
            throw new IllegalStateException("write browser bridge script failed: " + e.getMessage(), e);
        } finally {
            if (temporary != null) {
                try { Files.deleteIfExists(temporary); } catch (IOException ignored) { }
            }
        }
    }

    private List<List<String>> buildPythonCommands(File scriptFile, File profileDir, File stateFile,
                                                   List<String> arguments, String pythonPath, int debugPort) {
        List<List<String>> commands = new ArrayList<List<String>>();
        Set<String> added = new HashSet<String>();
        if (StringUtils.isNotEmpty(pythonPath)) {
            addWindowsPythonCommand(commands, added, normalizePythonCommand(pythonPath),
                    scriptFile, profileDir, stateFile, arguments, debugPort);
        }
        if (isMac()) {
            addCommand(commands, added,
                    buildCommand(Arrays.asList("python3"), scriptFile, profileDir, stateFile, arguments, debugPort));
            addCommand(commands, added,
                    buildCommand(Arrays.asList("python"), scriptFile, profileDir, stateFile, arguments, debugPort));
        } else if (isWindows()) {
            for (String candidate : findWindowsPythonExecutables()) {
                addWindowsPythonCommand(commands, added, normalizePythonCommand(candidate),
                        scriptFile, profileDir, stateFile, arguments, debugPort);
            }
            addWindowsPythonCommand(commands, added, Arrays.asList("py", "-3"),
                    scriptFile, profileDir, stateFile, arguments, debugPort);
            addWindowsPythonCommand(commands, added, Arrays.asList("python"),
                    scriptFile, profileDir, stateFile, arguments, debugPort);
            addWindowsPythonCommand(commands, added, Arrays.asList("python3"),
                    scriptFile, profileDir, stateFile, arguments, debugPort);
        } else {
            addCommand(commands, added,
                    buildCommand(Arrays.asList("python3"), scriptFile, profileDir, stateFile, arguments, debugPort));
            addCommand(commands, added,
                    buildCommand(Arrays.asList("python"), scriptFile, profileDir, stateFile, arguments, debugPort));
            addCommand(commands, added,
                    buildCommand(Arrays.asList("py", "-3"), scriptFile, profileDir, stateFile, arguments,
                            debugPort));
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
                                         File scriptFile, File profileDir, File stateFile, List<String> arguments,
                                         int debugPort) {
        if (pythonCommand == null || pythonCommand.isEmpty()) {
            return;
        }
        addCommand(commands, added, buildCommand(pythonCommand, scriptFile, profileDir, stateFile, arguments,
                debugPort));
        String executable = pythonCommand.get(0);
        if (pythonCommand.size() == 1 && isPythonLauncher(executable)) {
            List<String> launcherCommand = new ArrayList<String>(pythonCommand);
            launcherCommand.add("-3");
            addCommand(commands, added, buildCommand(launcherCommand, scriptFile, profileDir, stateFile, arguments,
                    debugPort));
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
        Process process = null;
        InputStream stream = null;
        Thread reader = null;
        StringBuilder output = new StringBuilder();
        try {
            process = new ProcessBuilder(command).redirectErrorStream(true).start();
            stream = process.getInputStream();
            reader = startOutputReader(stream, output);
            // Reading to EOF first defeats the deadline if a launcher never exits.
            if (!process.waitFor(DISCOVERY_COMMAND_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)) {
                process.destroyForcibly();
            }
            joinOutputReader(reader, stream);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception ignored) {
        } finally {
            if (process != null && process.isAlive()) process.destroyForcibly();
            IOUtils.closeIO(stream);
            if (reader != null && reader.isAlive()) reader.interrupt();
        }
        return outputSnapshot(output).lines().map(String::trim).filter(line -> !line.isEmpty()).toList();
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
                                      File profileDir, File stateFile, List<String> arguments, int debugPort) {
        List<String> command = new ArrayList<String>(pythonCommand);
        command.add(scriptFile.getAbsolutePath());
        command.add("--port");
        command.add(String.valueOf(debugPort));
        command.add("--user-data-path");
        command.add(profileDir.getAbsolutePath());
        command.add("--state-file");
        command.add(stateFile.getAbsolutePath());
        command.addAll(arguments);
        return command;
    }

    private String runCommand(BrowserSession session, List<String> command, long timeoutMillis,
                              String workDir) throws Exception {
        if (Thread.currentThread().isInterrupted()) {
            throw new IllegalStateException("python browser bridge cancelled");
        }
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);
        builder.directory(new File(workDir));
        Process process = builder.start();
        InputStream processOutput = process.getInputStream();
        StringBuilder output = new StringBuilder();
        Thread outputReader = startOutputReader(processOutput, output, process.getOutputStream(), session.scopeCheck);
        synchronized (session.processLock) {
            session.activeProcess = process;
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
                joinOutputReader(outputReader, processOutput);
                throw new IllegalStateException("python browser bridge timeout");
            }
            joinOutputReader(outputReader, processOutput);
            String outputText = outputSnapshot(output);
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
            synchronized (session.processLock) {
                if (session.activeProcess == process) {
                    session.activeProcess = null;
                }
            }
            IOUtils.closeIO(processOutput);
        }
    }

    private Thread startOutputReader(InputStream is, StringBuilder output) {
        return startOutputReader(is, output, null, null);
    }

    private Thread startOutputReader(InputStream is, StringBuilder output, OutputStream replies,
                                     Predicate<String> scopeCheck) {
        Thread thread = new Thread(() -> {
            BufferedReader reader = null;
            try {
                reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("SCOPE_CHECK=")) {
                        boolean allowed = false;
                        try {
                            if (scopeCheck != null && line.length() < 131072) {
                                String url = new String(Base64.getDecoder().decode(line.substring(12)), StandardCharsets.UTF_8);
                                allowed = scopeCheck.test(url);
                            }
                        } catch (Exception ignored) { /* Fail closed, never retry a request. */ }
                        if (replies != null) {
                            replies.write((allowed ? "ALLOW\n" : "DENY\n").getBytes(StandardCharsets.US_ASCII));
                            replies.flush();
                        }
                        continue;
                    }
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
        }, "OST-browser-output");
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    private void joinOutputReader(Thread outputReader, InputStream processOutput) {
        if (outputReader == null) {
            return;
        }
        try {
            outputReader.join(5000L);
            if (outputReader.isAlive()) {
                IOUtils.closeIO(processOutput);
                outputReader.join(1000L);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private String outputSnapshot(StringBuilder output) {
        synchronized (output) {
            return output.toString();
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

    private BrowserSession getSession(String browserId) {
        String normalizedId = StringUtils.isEmpty(browserId)
                ? BrowserRequest.DEFAULT_BROWSER_ID : browserId.trim();
        synchronized (mSessions) {
            return mSessions.computeIfAbsent(normalizedId, id -> new BrowserSession(
                    buildSessionDirectoryName(id), allocateDebugPort()));
        }
    }

    private String buildSessionDirectoryName(String browserId) {
        String readable = browserId.replaceAll("[^A-Za-z0-9._-]", "_");
        if (readable.length() > 32) {
            readable = readable.substring(0, 32);
        }
        String identity = UUID.nameUUIDFromBytes(browserId.getBytes(StandardCharsets.UTF_8))
                .toString().replace("-", "").substring(0, 12);
        String instance = Long.toHexString(System.currentTimeMillis())
                + "-" + Integer.toHexString(System.identityHashCode(this)) + "-" + mSessionSequence.incrementAndGet();
        return "session-" + readable + "-" + identity + "-" + instance;
    }

    private int allocateDebugPort() {
        synchronized (DEBUG_PORT_LOCK) {
            int available = LAST_DEBUG_PORT - FIRST_DEBUG_PORT + 1;
            for (int i = 0; i < available; i++) {
                int candidate = sNextDebugPort++;
                if (sNextDebugPort > LAST_DEBUG_PORT) {
                    sNextDebugPort = FIRST_DEBUG_PORT;
                }
                if (RESERVED_DEBUG_PORTS.add(candidate)) {
                    return candidate;
                }
            }
        }
        throw new IllegalStateException("no browser debug port available for isolated session");
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

    private static final class BrowserSession {
        private final String sessionId;
        private final int debugPort;
        private final Object processLock = new Object();
        private volatile Process activeProcess;
        private boolean closed;
        private Predicate<String> scopeCheck;

        private BrowserSession(String sessionId, int debugPort) {
            this.sessionId = sessionId;
            this.debugPort = debugPort;
        }
    }

    public record BrowserResult(int status, String reason, Map<String, String> headers, byte[] bodyBytes,
                                String finalUrl, String title) {
        public BrowserResult {
            reason = reason == null ? "" : reason;
            headers = Collections.unmodifiableMap(headers == null ? new LinkedHashMap<>() : new LinkedHashMap<>(headers));
            bodyBytes = bodyBytes == null ? new byte[0] : bodyBytes.clone();
            finalUrl = finalUrl == null ? "" : finalUrl;
            title = title == null ? "" : title;
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
            return bodyBytes.clone();
        }

        public String getFinalUrl() {
            return finalUrl;
        }

        public String getTitle() {
            return title;
        }
    }
}
