package burp;

import burp.vaycore.common.helper.DomainHelper;
import burp.vaycore.ost.bean.TaskData;
import burp.vaycore.ost.browser.BrowserRequest;
import burp.vaycore.ost.browser.BrowserRequestManager;
import burp.vaycore.ost.common.Config;
import burp.vaycore.ost.common.HttpReqRespAdapter;
import burp.vaycore.ost.common.RequestMode;
import burp.vaycore.ost.manager.CollectManager;
import burp.vaycore.ost.manager.WordlistManager;
import burp.vaycore.ost.ui.tab.DataBoardTab;
import org.junit.*;
import org.junit.rules.TemporaryFolder;

import javax.swing.*;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.*;

/** Exercises the existing dashboard import -> doScan -> Burp dispatch -> table path.
 * Only the Burp API and executor scheduling are faked. No network requests are made. */
public class BurpExtenderUrlImportTest {
    @Rule public TemporaryFolder temp = new TemporaryFolder();
    private BurpExtender extender;
    private DataBoardTab board;
    private final RecordingExecutor requests = new RecordingExecutor();
    private final RecordingExecutor lowFrequency = new RecordingExecutor();
    private final RecordingExecutor browser = new RecordingExecutor();
    private final RecordingExecutor fingerprints = new RecordingExecutor();
    private final List<String> sent = new CopyOnWriteArrayList<>();
    private final AtomicReference<Thread> importer = new AtomicReference<>();
    private final AtomicReference<Throwable> importFailure = new AtomicReference<>();
    private CountDownLatch started;
    private boolean directories;
    private boolean preprocessing;
    private String brokenHost;
    private Runnable onFirstAnalysis;

    @Before public void setup() throws Exception {
        Config.init(temp.newFolder().getAbsolutePath() + File.separator);
        DomainHelper.init("public_suffix_list.json");
        Config.put(Config.KEY_FOLLOW_REDIRECT, "false");
        Config.put(Config.KEY_INTERCEPT_TIMEOUT_HOST, "false");
        WordlistManager.putList(WordlistManager.KEY_PATH_BLOCKLIST, List.of());
        WordlistManager.putList(WordlistManager.KEY_PAYLOAD, List.of("health", "/status"));
        extender = new BurpExtender();
        SwingUtilities.invokeAndWait(() -> {
            board = new DataBoardTab() {
                @Override public boolean hasDirScan() { return directories; }
                @Override public boolean hasReplaceHeader() { return preprocessing; }
                @Override public boolean hasRemoveHeader() { return preprocessing; }
                @Override public boolean hasPayloadProcessing() { return preprocessing; }
            };
            board.init(new JTextArea(), new JTextArea());
            board.setOnTabEventListener(extender);
        });
        setField("mDataBoardTab", board);
        setField("mTaskThreadPool", requests);
        setField("mLFTaskThreadPool", lowFrequency);
        setField("mBrowserTaskThreadPool", browser);
        fingerprints.shutdown();
        setField("mFpThreadPool", fingerprints);
        setField("mHelpers", helpers());
        setField("mCallbacks", Proxy.newProxyInstance(IBurpExtenderCallbacks.class.getClassLoader(),
                new Class<?>[]{IBurpExtenderCallbacks.class}, (proxy, method, args) -> {
                    if (!method.getName().equals("makeHttpRequest")) {
                        throw new AssertionError("Unexpected callback: " + method.getName());
                    }
                    IHttpService service = (IHttpService) args[0];
                    byte[] request = (byte[]) args[1];
                    sent.add(service.getProtocol() + "://" + service.getHost() + ":" + service.getPort()
                            + " " + text(request).split("\r\n", 2)[0]);
                    HttpReqRespAdapter response = HttpReqRespAdapter.from(service, request);
                    response.setResponse(bytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"));
                    return response;
                }));
    }

    @After public void cleanup() throws Exception {
        if (board != null) {
            SwingUtilities.invokeAndWait(() -> {
                board.closeAutoSaveTimer();
                board.getAllTaskTables().forEach(table -> table.clearAll());
            });
            board.closeDataSaveExecutor();
        }
        CollectManager.closeThreadPool();
    }

    @Test public void twoDifferentDomainsQueueBothOriginalRequests() throws Exception {
        importUrls(List.of("http://first.example.test/", "http://second.example.test/"));
        assertEquals(2, requests.tasks.size());
        assertTrue(lowFrequency.tasks.isEmpty());
        assertTrue(browser.tasks.isEmpty());
    }

    @Test public void directoryExpansionQueuesEveryHostAndBothResponsesReachDashboard() throws Exception {
        directories = true;
        importUrls(List.of("http://127.0.0.1/", "http://127.0.0.2/"));
        assertEquals(6, requests.tasks.size());
        requests.drain();
        assertEquals(6, sent.size());
        List<TaskData> data = board.getBurpTaskTable().getTaskDataList();
        assertEquals(6, data.size());
        assertEquals(Set.of("http://127.0.0.1", "http://127.0.0.2"),
                new HashSet<>(data.stream().map(TaskData::getHost).toList()));
        assertEquals(2, data.stream().filter(row -> row.getFrom().equals("Import")).count());
        assertTrue(board.getBrowserTaskTable().getTaskDataList().isEmpty());
        assertTrue(board.getParameterFuzzPanel().getTrafficTable().getTaskDataList().isEmpty());
    }

    @Test public void priorImportMustNotSilentlyRemoveOneUrlFromNextManualBatch() throws Exception {
        importUrls(List.of("http://127.0.0.2/"));
        requests.drain();
        importUrls(List.of("http://127.0.0.1/", "http://127.0.0.2/"));
        assertEquals("Both explicit imports should be dispatched even if one was scanned earlier",
                2, requests.tasks.size());
        requests.drain();
        assertEquals(3, sent.size());
    }

    @Test public void duplicateUrlsWithinOneBatchStillShareOneRequest() throws Exception {
        directories = true;
        importUrls(List.of("http://127.0.0.1/", "http://127.0.0.1/", "http://127.0.0.2/"));
        assertEquals(6, requests.tasks.size());
    }

    @Test public void failurePreparingOneUrlDoesNotAbortTheRestOfTheBatch() throws Exception {
        brokenHost = "broken.example.test";
        importUrls(List.of("http://broken.example.test/", "http://second.example.test/"));
        assertEquals(1, requests.tasks.size());
    }

    @Test public void invalidUrlDoesNotAbortLaterEntries() throws Exception {
        importUrls(List.of("http://first.example.test/", "invalid-url", "http://second.example.test/"));
        assertEquals(2, requests.tasks.size());
    }

    @Test public void asyncImportUsesSnapshotRatherThanMutableCallerList() throws Exception {
        List<String> urls = new ArrayList<>(List.of("http://first.example.test/", "http://second.example.test/"));
        CountDownLatch blocked = new CountDownLatch(1);
        CountDownLatch resume = new CountDownLatch(1);
        onFirstAnalysis = () -> {
            blocked.countDown();
            try { assertTrue(resume.await(5, TimeUnit.SECONDS)); }
            catch (InterruptedException e) { throw new AssertionError(e); }
        };
        beginImport(urls);
        try {
            assertTrue(blocked.await(5, TimeUnit.SECONDS));
            urls.clear();
        } finally { resume.countDown(); }
        awaitImport();
        assertEquals(2, requests.tasks.size());
    }

    @Test public void differentPortsAndSchemesAreNotDeduplicated() throws Exception {
        importUrls(List.of("http://127.0.0.1/", "http://127.0.0.1:8080/", "https://127.0.0.1/"));
        requests.drain();
        assertEquals(3, sent.size());
        assertEquals(3, board.getBurpTaskTable().getTaskDataList().size());
    }

    @Test public void explicitQueryVariantsAreRetainedButExactDuplicatesAreNot() throws Exception {
        importUrls(List.of("http://127.0.0.1/items?id=1", "http://127.0.0.1/items?id=2",
                "http://127.0.0.1/items?id=1", "http://127.0.0.2/items?id=1"));
        requests.drain();
        assertEquals(3, sent.size());
        assertEquals(List.of("/items?id=1", "/items?id=2", "/items?id=1"),
                board.getBurpTaskTable().getTaskDataList().stream().map(TaskData::getUrl).toList());
    }

    @Test public void manualBatchReplaysDirectoryTasksOncePerPath() throws Exception {
        directories = true;
        importUrls(List.of("http://127.0.0.2/"));
        requests.drain();
        importUrls(List.of("http://127.0.0.1/", "http://127.0.0.2/", "http://127.0.0.2/"));
        assertEquals(6, requests.tasks.size());
        requests.drain();
        assertEquals(9, sent.size());
    }

    @Test public void clearingTasksWhileImportingPreventsFurtherDispatch() throws Exception {
        onFirstAnalysis = () -> {
            try {
                Field field = BurpExtender.class.getDeclaredField("mTaskGeneration");
                field.setAccessible(true);
                ((java.util.concurrent.atomic.AtomicLong) field.get(extender)).incrementAndGet();
            } catch (ReflectiveOperationException e) { throw new AssertionError(e); }
        };
        directories = true;
        importUrls(List.of("http://127.0.0.1/", "http://127.0.0.2/"));
        assertTrue(requests.tasks.isEmpty());
    }

    @Test public void importWindowWithTwoSeparateRowsDispatchesBothThroughDashboard() throws Exception {
        started = new CountDownLatch(1);
        RuntimeException delivered = new RuntimeException("stop before showing success dialog");
        SwingUtilities.invokeAndWait(() -> {
            try {
                var window = new burp.vaycore.ost.ui.widget.ImportUrlWindow();
                Field field = window.getClass().getDeclaredField("mWordlist");
                field.setAccessible(true);
                var wordlist = (burp.vaycore.ost.ui.widget.SimpleWordlist) field.get(window);
                List<String> urls = List.of("http://127.0.0.1/", "http://127.0.0.2/");
                wordlist.setListData(urls);
                Field listField = wordlist.getClass().getDeclaredField("mListView");
                listField.setAccessible(true);
                ((JList<?>) listField.get(wordlist)).setSelectedIndex(0);
                window.setOnImportUrlListener((data, mode) -> {
                    assertEquals(urls, data);
                    assertEquals(RequestMode.BURP, mode);
                    board.onImportUrl(data, mode);
                    // The real UI has already collected, validated and emitted its data.
                    // Avoid opening a modal success dialog in an automated test.
                    throw delivered;
                });
                var scan = window.getClass().getDeclaredMethod("doScan");
                scan.setAccessible(true);
                try { scan.invoke(window); fail("No import event"); }
                catch (java.lang.reflect.InvocationTargetException e) { assertSame(delivered, e.getCause()); }
            } catch (ReflectiveOperationException e) { throw new AssertionError(e); }
        });
        awaitImport();
        requests.drain();
        assertEquals(2, sent.size());
        assertEquals(2, board.getBurpTaskTable().getTaskDataList().size());
    }

    @Test public void importWindowBrowserModeQueuesEveryUrlDespiteAutomaticHostFilter() throws Exception {
        Config.put(Config.KEY_ENABLE_BROWSER_REQUEST, "false");
        Config.put(Config.KEY_BROWSER_TARGET_HOST_REGEX, "^only-automatic.example.test$");
        started = new CountDownLatch(1);
        RuntimeException delivered = new RuntimeException("stop before showing success dialog");
        SwingUtilities.invokeAndWait(() -> {
            try {
                var window = new burp.vaycore.ost.ui.widget.ImportUrlWindow();
                Field wordlistField = window.getClass().getDeclaredField("mWordlist");
                wordlistField.setAccessible(true);
                var wordlist = (burp.vaycore.ost.ui.widget.SimpleWordlist) wordlistField.get(window);
                wordlist.setListData(List.of("http://127.0.0.1/", "http://127.0.0.2/"));
                Field modeField = window.getClass().getDeclaredField("mRequestMode");
                modeField.setAccessible(true);
                ((JComboBox<?>) modeField.get(window)).setSelectedIndex(1);
                window.setOnImportUrlListener((data, mode) -> {
                    assertEquals(RequestMode.BROWSER, mode);
                    board.onImportUrl(data, mode);
                    throw delivered;
                });
                var scan = window.getClass().getDeclaredMethod("doScan");
                scan.setAccessible(true);
                try { scan.invoke(window); fail("No import event"); }
                catch (java.lang.reflect.InvocationTargetException e) { assertSame(delivered, e.getCause()); }
            } catch (ReflectiveOperationException e) { throw new AssertionError(e); }
        });
        awaitImport();
        assertEquals(2, browser.tasks.size());
        assertTrue(requests.tasks.isEmpty());
        browser.drain();
        assertEquals(2, board.getBrowserTaskTable().getTaskDataList().size());
        for (TaskData row : board.getBrowserTaskTable().getTaskDataList()) {
            String response = text(row.getRespBytes());
            assertTrue(response.startsWith("HTTP/1.1 599 Browser Bridge Error"));
            assertTrue(response.contains("target host regex"));
        }
    }

    @Test public void directUrlImportActuallyDispatchesBrowserRequests() throws Exception {
        Config.put(Config.KEY_ENABLE_BROWSER_REQUEST, "false");
        Config.put(Config.KEY_BROWSER_TARGET_HOST_REGEX, "");
        List<String> navigated = new CopyOnWriteArrayList<>();
        setField("mBrowserRequestManager", new BrowserRequestManager() {
            @Override public BrowserResult navigate(BrowserRequest request, String type, String binaryPath,
                                                    long timeout, String workDir, String pythonPath,
                                                    boolean loadStaticResources) {
                navigated.add(request.getUrl());
                return new BrowserResult(200, "OK", Map.of("Content-Type", "text/plain"), bytes("OK"),
                        request.getUrl(), "");
            }
        });
        importUrls(List.of("http://127.0.0.1/", "http://127.0.0.2/"), RequestMode.BROWSER);
        assertEquals(2, browser.tasks.size());
        assertTrue(requests.tasks.isEmpty());
        browser.drain();
        assertEquals(List.of("http://127.0.0.1/", "http://127.0.0.2/"), navigated);
        assertEquals(2, board.getBrowserTaskTable().getTaskDataList().size());
        assertTrue(board.getBurpTaskTable().getTaskDataList().isEmpty());
    }

    @Test public void twoHostsSurviveHeaderReplacementAndAllBuiltInProcessingRules() throws Exception {
        directories = true;
        preprocessing = true;
        var rules = Config.getPayloadProcessList();
        rules.forEach(rule -> rule.setEnabled(true));
        Config.put(Config.KEY_PAYLOAD_PROCESS_LIST, rules);
        importUrls(List.of("http://127.0.0.1/", "http://127.0.0.2/"));
        assertEquals(6 * rules.size(), requests.tasks.size());
        requests.drain();
        assertEquals(6 * rules.size(), sent.size());
        List<TaskData> rows = board.getBurpTaskTable().getTaskDataList();
        assertEquals(3 * rules.size(), rows.stream().filter(row -> row.getHost().equals("http://127.0.0.1")).count());
        assertEquals(3 * rules.size(), rows.stream().filter(row -> row.getHost().equals("http://127.0.0.2")).count());
    }

    @Test public void freshBatchWithRealWorkerConcurrencyDisplaysBothHosts() throws Exception {
        directories = true;
        // Match the production HTTP pool rather than draining recorded tasks serially.
        ExecutorService workers = Executors.newFixedThreadPool(50);
        setField("mTaskThreadPool", workers);
        WordlistManager.putList(WordlistManager.KEY_PAYLOAD,
                java.util.stream.IntStream.range(0, 60).mapToObj(i -> "/route" + i).toList());
        try {
            importUrls(List.of("http://127.0.0.1/", "http://127.0.0.2/"));
            Field field = BurpExtender.class.getDeclaredField("mTaskOverCounter");
            field.setAccessible(true);
            var completed = (java.util.concurrent.atomic.AtomicInteger) field.get(extender);
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while (completed.get() < 122 && System.nanoTime() < deadline) Thread.sleep(10);
            assertEquals(122, completed.get());
            assertEquals(122, sent.size());
            List<TaskData> rows = board.getBurpTaskTable().getTaskDataList();
            assertEquals(122, rows.size());
            assertEquals(61, rows.stream().filter(row -> row.getHost().equals("http://127.0.0.1")).count());
            assertEquals(61, rows.stream().filter(row -> row.getHost().equals("http://127.0.0.2")).count());
        } finally {
            workers.shutdownNow();
            assertTrue(workers.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    private void importUrls(List<?> urls) throws Exception {
        importUrls(urls, RequestMode.BURP);
    }

    private void importUrls(List<?> urls, RequestMode mode) throws Exception {
        beginImport(urls, mode);
        awaitImport();
    }

    @SuppressWarnings("unchecked") private void beginImport(List<?> urls) throws Exception {
        beginImport(urls, RequestMode.BURP);
    }

    @SuppressWarnings("unchecked") private void beginImport(List<?> urls, RequestMode mode) throws Exception {
        started = new CountDownLatch(1);
        importer.set(null);
        importFailure.set(null);
        SwingUtilities.invokeAndWait(() -> board.onImportUrl((List<String>) urls, mode));
    }

    private void awaitImport() throws Exception {
        assertTrue("Importer did not start", started.await(5, TimeUnit.SECONDS));
        importer.get().join(5000);
        assertFalse("Importer did not finish", importer.get().isAlive());
        assertNull("Unexpected batch failure: " + importFailure.get(), importFailure.get());
    }

    private void setField(String name, Object value) throws Exception {
        Field field = BurpExtender.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(extender, value);
    }

    @SuppressWarnings("unchecked") private IExtensionHelpers helpers() {
        return (IExtensionHelpers) Proxy.newProxyInstance(IExtensionHelpers.class.getClassLoader(),
                new Class<?>[]{IExtensionHelpers.class}, (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "bytesToString": return text((byte[]) args[0]);
                        case "stringToBytes": return bytes((String) args[0]);
                        case "buildHttpMessage": {
                            List<String> headers = new ArrayList<>((List<String>) args[0]);
                            byte[] body = (byte[]) args[1];
                            if (body.length > 0) headers.add("Content-Length: " + body.length);
                            return bytes(String.join("\r\n", headers) + "\r\n\r\n" + text(body));
                        }
                        case "analyzeRequest": {
                            IHttpService service = null;
                            byte[] raw;
                            if (args[0] instanceof IHttpRequestResponse rr) {
                                service = rr.getHttpService(); raw = rr.getRequest();
                                if (importer.compareAndSet(null, Thread.currentThread())) {
                                    Thread.currentThread().setUncaughtExceptionHandler((thread, e) -> importFailure.set(e));
                                    started.countDown();
                                    if (onFirstAnalysis != null) onFirstAnalysis.run();
                                }
                                if (service.getHost().equals(brokenHost)) throw new IllegalStateException("fixture analysis failure");
                            } else {
                                raw = (byte[]) args[args.length - 1];
                                if (args.length == 2) service = (IHttpService) args[0];
                            }
                            String message = text(raw);
                            int offset = message.indexOf("\r\n\r\n") + 4;
                            List<String> headers = Arrays.asList(message.substring(0, offset - 4).split("\r\n"));
                            String[] line = headers.get(0).split(" ", 3);
                            URL url = service == null ? null : new URL(service.getProtocol(), service.getHost(), service.getPort(), line[1]);
                            return Proxy.newProxyInstance(IRequestInfo.class.getClassLoader(), new Class<?>[]{IRequestInfo.class},
                                    (info, getter, ignored) -> switch (getter.getName()) {
                                        case "getHeaders" -> headers;
                                        case "getBodyOffset" -> offset;
                                        case "getMethod" -> line[0];
                                        case "getUrl" -> url;
                                        case "getParameters" -> List.of();
                                        default -> throw new AssertionError(getter.getName());
                                    });
                        }
                        case "analyzeResponse": {
                            String raw = text((byte[]) args[0]);
                            return Proxy.newProxyInstance(IResponseInfo.class.getClassLoader(), new Class<?>[]{IResponseInfo.class},
                                    (info, getter, ignored) -> switch (getter.getName()) {
                                        case "getStatusCode" -> (short) 200;
                                        case "getBodyOffset" -> raw.indexOf("\r\n\r\n") + 4;
                                        default -> throw new AssertionError(getter.getName());
                                    });
                        }
                        default: throw new AssertionError("Unexpected helper: " + method.getName());
                    }
                });
    }

    private static byte[] bytes(String text) { return text.getBytes(StandardCharsets.ISO_8859_1); }
    private static String text(byte[] bytes) { return new String(bytes, StandardCharsets.ISO_8859_1); }

    private static final class RecordingExecutor extends AbstractExecutorService {
        final List<Runnable> tasks = new CopyOnWriteArrayList<>();
        boolean stopped;
        @Override public void execute(Runnable task) { tasks.add(task); }
        @Override public void shutdown() { stopped = true; }
        @Override public List<Runnable> shutdownNow() { stopped = true; return List.of(); }
        @Override public boolean isShutdown() { return stopped; }
        @Override public boolean isTerminated() { return stopped; }
        @Override public boolean awaitTermination(long timeout, TimeUnit unit) { return stopped; }
        void drain() { while (!tasks.isEmpty()) tasks.remove(0).run(); }
    }
}
