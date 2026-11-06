package burp;

import burp.vaycore.common.helper.DomainHelper;
import burp.vaycore.ost.bean.TaskData;
import burp.vaycore.ost.common.*;
import burp.vaycore.ost.manager.CollectManager;
import burp.vaycore.ost.manager.WordlistManager;
import burp.vaycore.ost.ui.tab.DataBoardTab;
import burp.vaycore.ost.ui.tab.ParameterFuzzScanOptions;
import org.junit.*;
import org.junit.rules.TemporaryFolder;

import javax.swing.*;
import java.io.File;
import java.lang.reflect.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

import static org.junit.Assert.*;

/** Real scheduling/dispatch with a strict local Burp boundary; never sends network traffic. */
public class BurpExtenderDispatchRegressionTest {
    @Rule public TemporaryFolder temp = new TemporaryFolder();
    private BurpExtender extender;
    private DataBoardTab board;
    private final QueueExecutor http = new QueueExecutor();
    private final QueueExecutor low = new QueueExecutor();
    private final QueueExecutor browser = new QueueExecutor();
    private final QueueExecutor parameterBrowser = new QueueExecutor();
    private final List<byte[]> sent = new ArrayList<>();
    private boolean replaceHeaders;

    @Before public void setup() throws Exception {
        Config.init(temp.newFolder().getAbsolutePath() + File.separator);
        DomainHelper.init("public_suffix_list.json");
        Config.put(Config.KEY_FOLLOW_REDIRECT, "false");
        WordlistManager.putList(WordlistManager.KEY_PATH_BLOCKLIST, List.of());
        extender = new BurpExtender();
        SwingUtilities.invokeAndWait(() -> {
            board = new DataBoardTab() {
                @Override public boolean hasDirScan() { return false; }
                @Override public boolean hasReplaceHeader() { return replaceHeaders; }
                @Override public boolean hasRemoveHeader() { return replaceHeaders; }
                @Override public boolean hasPayloadProcessing() { return false; }
            };
            board.init(new JTextArea(), new JTextArea());
        });
        set("mDataBoardTab", board);
        set("mTaskThreadPool", http);
        set("mLFTaskThreadPool", low);
        set("mBrowserTaskThreadPool", browser);
        set("mParameterFuzzBrowserTaskThreadPool", parameterBrowser);
        set("mHelpers", helpers());
        set("mCallbacks", Proxy.newProxyInstance(IBurpExtenderCallbacks.class.getClassLoader(),
                new Class<?>[]{IBurpExtenderCallbacks.class}, (proxy, method, args) -> {
                    assertEquals("makeHttpRequest", method.getName());
                    byte[] request = ((byte[]) args[1]).clone();
                    sent.add(request);
                    var response = HttpReqRespAdapter.from((IHttpService) args[0], request);
                    response.setResponse(bytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"));
                    return response;
                }));
    }

    @After public void cleanup() throws Exception {
        if (extender != null) {
            ExecutorService preparation = (ExecutorService) get("mParameterFuzzPreparationExecutor");
            ExecutorService probes = (ExecutorService) get("mParameterFuzzBrowserTaskThreadPool");
            if (probes != parameterBrowser) {
                probes.shutdownNow();
                assertTrue(probes.awaitTermination(5, TimeUnit.SECONDS));
            }
            preparation.shutdownNow();
            assertTrue(preparation.awaitTermination(5, TimeUnit.SECONDS));
        }
        if (board != null) {
            SwingUtilities.invokeAndWait(() -> {
                board.closeAutoSaveTimer();
                board.getParameterFuzzPanel().close();
                board.getAllTaskTables().forEach(table -> table.clearAll());
            });
            board.closeDataSaveExecutor();
        }
        Field collectorField = CollectManager.class.getDeclaredField("sThreadPool");
        collectorField.setAccessible(true);
        ExecutorService collector = (ExecutorService) collectorField.get(null);
        collector.shutdown();
        assertTrue(collector.awaitTermination(5, TimeUnit.SECONDS));
    }

    @Test public void customDictionaryValuesStayLiteralThroughActualDispatch() throws Exception {
        String template = "POST /probe HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n$1$";
        List<String> values = List.of("{{host}}", "{{value.missing}}", "$2$\\literal");
        scan(template, values);
        assertEquals("Literal dictionary entries must not be expanded or dropped", 3, sent.size());
        for (int i = 0; i < values.size(); i++) {
            String raw = text(sent.get(i));
            assertTrue(raw.endsWith("\r\n\r\n" + values.get(i)));
            assertTrue(raw.contains("Content-Length: " + values.get(i).length() + "\r\n"));
        }
        assertEquals(3, board.getParameterFuzzPanel().getTrafficTable().getTaskDataList().size());
        assertTrue(board.getBurpTaskTable().getTaskDataList().isEmpty());
    }

    @Test public void customHeaderPositionsAreNotOverwrittenOrRemovedByGlobalRules() throws Exception {
        replaceHeaders = true;
        WordlistManager.putList(WordlistManager.KEY_HEADERS, List.of("X-Probe: global-value"));
        WordlistManager.putList(WordlistManager.KEY_REMOVE_HEADERS, List.of("X-Keep"));
        String template = "GET /probe HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Probe: $1$\r\nX-Keep: yes\r\n\r\n";
        scan(template, List.of("dictionary-value"));
        assertEquals(1, sent.size());
        assertEquals(template.replace("$1$", "dictionary-value"), text(sent.get(0)));
    }

    @Test public void browserSendCompletionUsesSameCounterAsSubmission() throws Exception {
        enqueue("Send (Browser)", RequestMode.BROWSER);
        assertEquals(1, count("mTaskCommitCounter"));
        // Cancel before execution so no browser process is started. Completion must still balance.
        ((AtomicLong) get("mTaskGeneration")).incrementAndGet();
        browser.drain();
        assertEquals(1, count("mTaskOverCounter"));
        assertEquals(0, count("mLFTaskOverCounter"));
    }

    @Test public void clearingQueuedBrowserSendTasksBalancesCountersToo() throws Exception {
        enqueue("Send (Browser)", RequestMode.BROWSER);
        invoke("handleStopTasks", new Class<?>[]{List.class}, new ArrayList<>(browser.tasks));
        assertEquals(1, count("mTaskOverCounter"));
        assertEquals(0, count("mLFTaskOverCounter"));
    }

    @Test public void httpSendStillUsesLowFrequencyCounters() throws Exception {
        enqueue("Send (Burp)", RequestMode.BURP);
        assertEquals(1, count("mLFTaskCommitCounter"));
        ((AtomicLong) get("mTaskGeneration")).incrementAndGet();
        low.drain();
        assertEquals(1, count("mLFTaskOverCounter"));
        assertEquals(0, count("mTaskOverCounter"));
    }

    @Test public void parameterRequestsStillRespectTheExistingPathBlocklist() throws Exception {
        WordlistManager.putList(WordlistManager.KEY_PATH_BLOCKLIST, List.of("/probe"));
        scan("GET /probe?id=$1$ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", List.of("value"));
        assertTrue(sent.isEmpty());
        assertTrue(board.getParameterFuzzPanel().getTrafficTable().getTaskDataList().isEmpty());
    }

    @Test public void jsonMediaTypesWithCharsetAreEligibleButSubstringMatchesAreNot() throws Exception {
        for (String mediaType : List.of("application/json; charset=UTF-8", "application/problem+json; charset=UTF-8")) {
            byte[] request = bytes("POST /probe HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: " + mediaType + "\r\n\r\n{}");
            IRequestInfo info = helpers().analyzeRequest(request);
            assertEquals(true, invoke("isParameterLocationAvailable", new Class<?>[]{IRequestInfo.class, byte[].class, byte.class},
                    info, request, IParameter.PARAM_JSON));
        }
        byte[] request = bytes("POST /probe HTTP/1.1\r\nContent-Type: text/notapplication/json\r\n\r\n{}");
        assertEquals(false, invoke("isParameterLocationAvailable", new Class<?>[]{IRequestInfo.class, byte[].class, byte.class},
                helpers().analyzeRequest(request), request, IParameter.PARAM_JSON));
    }

    @Test public void browserOnlyScanCanPrepareWhileHttpWorkersAreOccupied() throws Exception {
        ExecutorService occupiedHttp = Executors.newSingleThreadExecutor();
        CountDownLatch occupied = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        occupiedHttp.execute(() -> {
            occupied.countDown();
            try { release.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        });
        assertTrue(occupied.await(5, TimeUnit.SECONDS));
        set("mTaskThreadPool", occupiedHttp);
        try {
            var message = HttpReqRespAdapter.from("http://127.0.0.1/probe");
            TaskData target = new TaskData(); target.setMethod("GET"); target.setStatus(200); target.setReqResp(message);
            var options = new ParameterFuzzScanOptions(List.of(new ParameterFuzzScanOptions.TargetOptions(
                    target, ParameterFuzzScanOptions.Mode.POSITIONS, List.of(), List.of(),
                    bytes("GET /probe?id=$1$ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"), Map.of("1", List.of("value")),
                    true, false, true, RequestMode.BROWSER, "parameter-fuzz-test")));
            invoke("startParameterFuzzScan", new Class<?>[]{ParameterFuzzScanOptions.class}, options);
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
            while (parameterBrowser.tasks.isEmpty() && System.nanoTime() < deadline) Thread.sleep(10);
            assertEquals("A busy/paused HTTP queue must not starve browser probe preparation", 1, parameterBrowser.tasks.size());
            assertTrue(browser.tasks.isEmpty());
        } finally {
            ((AtomicLong) get("mTaskGeneration")).incrementAndGet();
            release.countDown();
            occupiedHttp.shutdownNow();
            assertTrue(occupiedHttp.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test public void parameterBrowserScanDoesNotWaitForRunningOrdinaryBrowser() throws Exception {
        ExecutorService ordinary = Executors.newSingleThreadExecutor();
        set("mParameterFuzzBrowserTaskThreadPool", newParameterBrowserWorker());
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        CountDownLatch parameterDone = new CountDownLatch(2);
        List<String> parameterUrls = new CopyOnWriteArrayList<>();
        set("mBrowserTaskThreadPool", ordinary);
        set("mBrowserRequestManager", new burp.vaycore.ost.browser.BrowserRequestManager() {
            @Override public BrowserResult navigate(burp.vaycore.ost.browser.BrowserRequest request,
                    String type, String binary, long timeout, String dir, String python, boolean resources) {
                if (request.getBrowserId().equals(burp.vaycore.ost.browser.BrowserRequest.DEFAULT_BROWSER_ID)) {
                    entered.countDown();
                    try { if (!release.await(10, TimeUnit.SECONDS)) throw new AssertionError("fixture timeout"); }
                    catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                } else {
                    parameterUrls.add(request.url()); parameterDone.countDown();
                }
                return new BrowserResult(200, "OK", Map.of(), bytes("OK"), request.url(), "");
            }
        });
        try {
            enqueue("Send (Browser)", RequestMode.BROWSER);
            assertTrue("ordinary request must already be running", entered.await(3, TimeUnit.SECONDS));
            invoke("startParameterFuzzScan", new Class<?>[]{ParameterFuzzScanOptions.class}, browserOptions());
            assertTrue("parameter browser must not wait for the ordinary browser queue or global lock",
                    parameterDone.await(3, TimeUnit.SECONDS));
            assertEquals(1L, release.getCount());
            assertEquals(2, parameterUrls.size());
            assertTrue(parameterUrls.get(0).endsWith("/probe?id=one"));
            assertTrue(parameterUrls.get(1).endsWith("/probe?id=two"));
            ((ExecutorService) get("mParameterFuzzBrowserTaskThreadPool")).submit(() -> {}).get(3, TimeUnit.SECONDS);
            SwingUtilities.invokeAndWait(() -> {});
            assertFalse(((AtomicBoolean) get("mParameterFuzzRunning")).get());
            assertEquals(2, board.getParameterFuzzPanel().getTrafficTable().getTaskDataList().size());
            assertTrue(board.getBrowserTaskTable().getTaskDataList().isEmpty());
        } finally {
            release.countDown(); ordinary.shutdown();
            if (!ordinary.awaitTermination(5, TimeUnit.SECONDS)) ordinary.shutdownNow();
            assertTrue(ordinary.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test public void ordinaryBrowserDoesNotWaitForParameterScanAndProbeLaneRemainsSerial() throws Exception {
        ExecutorService ordinary = Executors.newSingleThreadExecutor();
        ExecutorService probes = newParameterBrowserWorker();
        set("mBrowserTaskThreadPool", ordinary);
        set("mParameterFuzzBrowserTaskThreadPool", probes);
        CountDownLatch firstProbe = new CountDownLatch(1), release = new CountDownLatch(1);
        CountDownLatch ordinaryDone = new CountDownLatch(1);
        AtomicInteger probeCalls = new AtomicInteger();
        set("mBrowserRequestManager", new burp.vaycore.ost.browser.BrowserRequestManager() {
            @Override public BrowserResult navigate(burp.vaycore.ost.browser.BrowserRequest request,
                    String type, String binary, long timeout, String dir, String python, boolean resources) {
                if (request.getBrowserId().equals(burp.vaycore.ost.browser.BrowserRequest.DEFAULT_BROWSER_ID)) {
                    ordinaryDone.countDown();
                } else if (probeCalls.incrementAndGet() == 1) {
                    firstProbe.countDown();
                    try { if (!release.await(10, TimeUnit.SECONDS)) throw new AssertionError("fixture timeout"); }
                    catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                }
                return new BrowserResult(200, "OK", Map.of(), bytes("OK"), request.url(), "");
            }
        });
        try {
            invoke("startParameterFuzzScan", new Class<?>[]{ParameterFuzzScanOptions.class}, browserOptions());
            assertTrue(firstProbe.await(3, TimeUnit.SECONDS));
            ((ExecutorService) get("mParameterFuzzPreparationExecutor")).submit(() -> {}).get(3, TimeUnit.SECONDS);
            enqueue("Send (Browser)", RequestMode.BROWSER);
            assertTrue("ordinary browser must run while parameter browser is waiting", ordinaryDone.await(3, TimeUnit.SECONDS));
            ordinary.submit(() -> {}).get(3, TimeUnit.SECONDS);
            assertEquals("second probe must wait for the first probe in the same session", 1, probeCalls.get());
            assertTrue(((AtomicBoolean) get("mParameterFuzzRunning")).get());
            assertEquals(1, board.getBrowserTaskTable().getTaskDataList().size());
            release.countDown();
            probes.submit(() -> {}).get(3, TimeUnit.SECONDS);
            SwingUtilities.invokeAndWait(() -> {});
            assertEquals(2, probeCalls.get());
            assertEquals(2, board.getParameterFuzzPanel().getTrafficTable().getTaskDataList().size());
            assertEquals(3, count("mTaskCommitCounter"));
            assertEquals(3, count("mTaskOverCounter"));
            assertFalse(((AtomicBoolean) get("mParameterFuzzRunning")).get());
        } finally {
            release.countDown(); ordinary.shutdownNow();
            assertTrue(ordinary.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test public void stoppingBothBrowserQueuesCancelsQueuedProbesAndSupportsRestart() throws Exception {
        ExecutorService ordinary = Executors.newSingleThreadExecutor();
        ExecutorService probes = newParameterBrowserWorker();
        set("mBrowserTaskThreadPool", ordinary);
        set("mParameterFuzzBrowserTaskThreadPool", probes);
        CountDownLatch occupied = new CountDownLatch(2), interrupted = new CountDownLatch(2);
        Runnable hold = () -> {
            occupied.countDown();
            try { new CountDownLatch(1).await(); }
            catch (InterruptedException e) { interrupted.countDown(); Thread.currentThread().interrupt(); }
        };
        ordinary.execute(hold); probes.execute(hold);
        try {
            assertTrue(occupied.await(3, TimeUnit.SECONDS));
            enqueue("Send (Browser)", RequestMode.BROWSER);
            invoke("startParameterFuzzScan", new Class<?>[]{ParameterFuzzScanOptions.class}, browserOptions());
            ((ExecutorService) get("mParameterFuzzPreparationExecutor")).submit(() -> {}).get(3, TimeUnit.SECONDS);
            assertEquals(3, count("mTaskCommitCounter"));
            ((AtomicLong) get("mTaskGeneration")).incrementAndGet();
            Object progress = get("mActiveParameterFuzzProgress");
            Method cancel = progress.getClass().getDeclaredMethod("cancel"); cancel.setAccessible(true); cancel.invoke(progress);
            List<?> stopped = (List<?>) invoke("shutdownBrowserTaskQueues", new Class<?>[0]);
            assertEquals(3, stopped.size());
            invoke("handleStopTasks", new Class<?>[]{List.class}, stopped);
            assertTrue(interrupted.await(3, TimeUnit.SECONDS));
            assertTrue(ordinary.awaitTermination(3, TimeUnit.SECONDS));
            assertTrue(probes.awaitTermination(3, TimeUnit.SECONDS));
            assertEquals(3, count("mTaskOverCounter"));
            assertFalse(((AtomicBoolean) get("mParameterFuzzRunning")).get());
            assertTrue(sent.isEmpty());
            set("mBrowserTaskThreadPool", browser);
            set("mParameterFuzzBrowserTaskThreadPool", parameterBrowser);
            invoke("startParameterFuzzScan", new Class<?>[]{ParameterFuzzScanOptions.class}, browserOptions());
            ((ExecutorService) get("mParameterFuzzPreparationExecutor")).submit(() -> {}).get(3, TimeUnit.SECONDS);
            assertEquals(2, parameterBrowser.tasks.size());
            assertTrue(browser.tasks.isEmpty());
            // Cancel before draining; stale tasks must not invoke a real browser.
            ((AtomicLong) get("mTaskGeneration")).incrementAndGet();
            parameterBrowser.drain();
            assertFalse(((AtomicBoolean) get("mParameterFuzzRunning")).get());
            assertEquals(5, count("mTaskCommitCounter"));
            assertEquals(5, count("mTaskOverCounter"));
        } finally {
            ordinary.shutdownNow(); probes.shutdownNow();
            assertTrue(ordinary.awaitTermination(5, TimeUnit.SECONDS));
            assertTrue(probes.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test public void browserPauseStillAppliesToBothQueuesUntilExplicitResume() throws Exception {
        ExecutorService ordinary = Executors.newSingleThreadExecutor();
        ExecutorService probes = newParameterBrowserWorker();
        set("mBrowserTaskThreadPool", ordinary); set("mParameterFuzzBrowserTaskThreadPool", probes);
        Object pauseLock = get("mRequestPauseLock");
        @SuppressWarnings("unchecked") Set<RequestMode> paused = (Set<RequestMode>) get("mPausedRequestModes");
        CountDownLatch calls = new CountDownLatch(3);
        set("mBrowserRequestManager", new burp.vaycore.ost.browser.BrowserRequestManager() {
            @Override public BrowserResult navigate(burp.vaycore.ost.browser.BrowserRequest request,
                    String type, String binary, long timeout, String dir, String python, boolean resources) {
                calls.countDown();
                return new BrowserResult(200, "OK", Map.of(), bytes("OK"), request.url(), "");
            }
        });
        try {
            synchronized (pauseLock) { paused.add(RequestMode.BROWSER); }
            enqueue("Send (Browser)", RequestMode.BROWSER);
            invoke("startParameterFuzzScan", new Class<?>[]{ParameterFuzzScanOptions.class}, browserOptions());
            ((ExecutorService) get("mParameterFuzzPreparationExecutor")).submit(() -> {}).get(3, TimeUnit.SECONDS);
            assertFalse(calls.await(200, TimeUnit.MILLISECONDS));
            assertEquals(3L, calls.getCount());
            synchronized (pauseLock) { paused.clear(); pauseLock.notifyAll(); }
            assertTrue(calls.await(3, TimeUnit.SECONDS));
            ordinary.submit(() -> {}).get(3, TimeUnit.SECONDS);
            probes.submit(() -> {}).get(3, TimeUnit.SECONDS);
            assertFalse(((AtomicBoolean) get("mParameterFuzzRunning")).get());
        } finally {
            synchronized (pauseLock) { paused.clear(); pauseLock.notifyAll(); }
            ordinary.shutdownNow(); assertTrue(ordinary.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    private ExecutorService newParameterBrowserWorker() throws Exception {
        return (ExecutorService) invoke("newParameterFuzzBrowserExecutor", new Class<?>[0]);
    }

    private ParameterFuzzScanOptions browserOptions() {
        var options = customOptions("GET /probe?id=$1$ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", List.of("one", "two"));
        var o = options.scans().get(0);
        return new ParameterFuzzScanOptions(List.of(new ParameterFuzzScanOptions.TargetOptions(
                o.target(), o.mode(), o.parameterNameCandidates(), o.parameterValues(), o.requestTemplate(),
                o.positionValues(), o.scanGet(), o.scanPost(), o.onlyExistingRoutes(),
                RequestMode.BROWSER, "parameter-fuzz-concurrent")));
    }

    @Test public void browserSourceProbesReallyNavigateAndStayInParameterTraffic() throws Exception {
        List<burp.vaycore.ost.browser.BrowserRequest> requests = new ArrayList<>();
        set("mBrowserRequestManager", new burp.vaycore.ost.browser.BrowserRequestManager() {
            @Override public BrowserResult navigate(burp.vaycore.ost.browser.BrowserRequest request,
                    String browserType, String binary, long timeout, String workDir,
                    String python, boolean loadStatic) {
                requests.add(request);
                return new BrowserResult(200, "OK", Map.of("Content-Type", "text/plain"),
                        bytes("OK"), request.url(), "");
            }
        });
        WordlistManager.putList(WordlistManager.KEY_PAYLOAD, "browser-values", List.of("one", "two"));
        List<TaskData> sources = new ArrayList<>();
        for (String method : List.of("GET", "POST")) {
            var original = HttpReqRespAdapter.from("http://127.0.0.1/probe?id=old");
            original.setRequest(bytes(method.equals("GET")
                    ? "GET /probe?id=old HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
                    : "POST /probe HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\r\n{\"id\":\"old\"}"));
            TaskData target = new TaskData();
            target.setMethod(method); target.setStatus(method.equals("GET") ? 412 : 401);
            target.setHost("http://127.0.0.1"); target.setUrl("/probe");
            target.setReqResp(original); target.setReqBytes(original.getRequest());
            target.setRequestScope("browser"); sources.add(target);
        }
        AtomicReference<ParameterFuzzScanOptions> submitted = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try {
                var panel = board.getParameterFuzzPanel();
                panelAction(panel, "populateDictionaries");
                ((JComboBox<?>) panelField(panel, "mMode")).setSelectedIndex(2);
                ((JComboBox<?>) panelField(panel, "mValueDictionary")).setSelectedItem("browser-values");
                board.getBrowserTaskTable().loadTaskData(sources);
                board.getBrowserTaskTable().setRowSelectionInterval(0, 1);
                JMenuItem menu = new JMenuItem(); menu.setActionCommand("parameter-fuzz");
                board.getBrowserTaskTable().actionPerformed(new java.awt.event.ActionEvent(menu, 0, "parameter-fuzz"));
                var targets = (JList<?>) panelField(panel, "mTargetList");
                var editor = (JTextArea) panelField(panel, "mRequestTemplate");
                assertEquals(2, targets.getModel().getSize());
                for (int i = 0; i < 2; i++) {
                    targets.setSelectedIndex(i);
                    assertTrue(((JCheckBox) panelField(panel, "mUseBrowser")).isSelected());
                    int pos = editor.getText().indexOf("old");
                    editor.select(pos, pos + 3); panelAction(panel, "markPosition");
                }
                panel.setScanHandler(options -> {
                    submitted.set(options);
                    try { invoke("startParameterFuzzScan", new Class<?>[]{ParameterFuzzScanOptions.class}, options); }
                    catch (Exception e) { throw new RuntimeException(e); }
                });
                ((JButton) panelField(panel, "mStart")).doClick();
            } catch (Exception e) { throw new RuntimeException(e); }
        });
        assertNotNull(submitted.get());
        assertTrue(submitted.get().scans().stream().allMatch(o -> o.requestMode() == RequestMode.BROWSER));
        ((ExecutorService) get("mParameterFuzzPreparationExecutor")).submit(() -> {}).get(5, TimeUnit.SECONDS);
        assertEquals(4, parameterBrowser.tasks.size());
        assertTrue(browser.tasks.isEmpty());
        parameterBrowser.drain();
        SwingUtilities.invokeAndWait(() -> {});
        assertEquals(4, requests.size());
        assertTrue(requests.get(0).url().endsWith("/probe?id=one"));
        assertTrue(requests.get(1).url().endsWith("/probe?id=two"));
        assertEquals("POST", requests.get(2).method());
        assertEquals("{\"id\":\"one\"}", text(requests.get(2).body()));
        assertEquals("{\"id\":\"two\"}", text(requests.get(3).body()));
        String browserId = submitted.get().scans().get(0).browserId();
        assertTrue(browserId.startsWith("parameter-fuzz-"));
        assertTrue(requests.stream().allMatch(r -> r.getBrowserId().equals(browserId)));
        assertNotEquals(burp.vaycore.ost.browser.BrowserRequest.DEFAULT_BROWSER_ID, browserId);
        assertEquals(4, board.getParameterFuzzPanel().getTrafficTable().getTaskDataList().size());
        assertTrue(board.getBurpTaskTable().getTaskDataList().isEmpty());
        assertEquals(sources, board.getBrowserTaskTable().getTaskDataList());
        assertTrue(sent.isEmpty());
        assertFalse(((AtomicBoolean) get("mParameterFuzzRunning")).get());
        var progress = (JProgressBar) panelField(board.getParameterFuzzPanel(), "mProgressBar");
        assertEquals(4, progress.getMaximum());
        assertEquals(4, progress.getValue());
    }

    private static Object panelField(burp.vaycore.ost.ui.tab.ParameterFuzzPanel panel, String name) throws Exception {
        Field field = panel.getClass().getDeclaredField(name); field.setAccessible(true); return field.get(panel);
    }
    private static void panelAction(burp.vaycore.ost.ui.tab.ParameterFuzzPanel panel, String name) throws Exception {
        Method method = panel.getClass().getDeclaredMethod(name); method.setAccessible(true); method.invoke(panel);
    }

    @Test public void rejectedPreparationReleasesBusyStateWithoutAnyRequests() throws Exception {
        ((ExecutorService) get("mParameterFuzzPreparationExecutor")).shutdown();
        invoke("startParameterFuzzScan", new Class<?>[]{ParameterFuzzScanOptions.class},
                customOptions("GET /probe?id=$1$ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", List.of("value")));
        SwingUtilities.invokeAndWait(() -> {});
        assertFalse(((AtomicBoolean) get("mParameterFuzzRunning")).get());
        assertTrue(http.tasks.isEmpty());
        assertTrue(sent.isEmpty());
    }

    @Test public void cancelledQueuedPreparationNeverDispatchesStaleProbes() throws Exception {
        ExecutorService preparation = (ExecutorService) get("mParameterFuzzPreparationExecutor");
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        preparation.execute(() -> {
            entered.countDown();
            try { release.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        });
        assertTrue(entered.await(5, TimeUnit.SECONDS));
        try {
            invoke("startParameterFuzzScan", new Class<?>[]{ParameterFuzzScanOptions.class},
                    customOptions("GET /probe?id=$1$ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", List.of("value")));
            ((AtomicLong) get("mTaskGeneration")).incrementAndGet();
        } finally { release.countDown(); }
        preparation.submit(() -> {}).get(5, TimeUnit.SECONDS);
        SwingUtilities.invokeAndWait(() -> {});
        assertTrue(http.tasks.isEmpty());
        assertTrue(browser.tasks.isEmpty());
        assertTrue(parameterBrowser.tasks.isEmpty());
        assertFalse(((AtomicBoolean) get("mParameterFuzzRunning")).get());
    }

    private void enqueue(String from, RequestMode mode) throws Exception {
        var request = HttpReqRespAdapter.from("http://127.0.0.1/");
        var group = new BurpExtender.RequestGroup("fixture");
        invoke("doBurpRequest", new Class<?>[]{IHttpService.class, String.class, byte[].class,
                String.class, RequestMode.class, String.class, String.class, BurpExtender.RequestGroup.class},
                request.getHttpService(), "fixture", request.getRequest(), from, mode, "", "variant", group);
    }

    private ParameterFuzzScanOptions customOptions(String template, List<String> values) {
        var original = HttpReqRespAdapter.from("http://127.0.0.1/probe");
        original.setRequest(bytes(template.replace("$1$", "original")));
        TaskData target = new TaskData();
        target.setMethod(template.startsWith("POST") ? "POST" : "GET");
        target.setStatus(200);
        target.setReqResp(original);
        return new ParameterFuzzScanOptions(List.of(new ParameterFuzzScanOptions.TargetOptions(
                target, ParameterFuzzScanOptions.Mode.POSITIONS, List.of(), List.of(), bytes(template),
                Map.of("1", values), true, true, true, RequestMode.BURP, "")));
    }

    private void scan(String template, List<String> values) throws Exception {
        invoke("startParameterFuzzScan", new Class<?>[]{ParameterFuzzScanOptions.class}, customOptions(template, values));
        ((ExecutorService) get("mParameterFuzzPreparationExecutor")).submit(() -> {}).get(5, TimeUnit.SECONDS);
        http.drain();
        SwingUtilities.invokeAndWait(() -> {});
        assertFalse(((AtomicBoolean) get("mParameterFuzzRunning")).get());
    }

    private int count(String field) throws Exception { return ((AtomicInteger) get(field)).get(); }
    private Object get(String name) throws Exception {
        Field field = BurpExtender.class.getDeclaredField(name); field.setAccessible(true); return field.get(extender);
    }
    private void set(String name, Object value) throws Exception {
        Field field = BurpExtender.class.getDeclaredField(name); field.setAccessible(true); field.set(extender, value);
    }
    private Object invoke(String name, Class<?>[] types, Object... args) throws Exception {
        Method method = BurpExtender.class.getDeclaredMethod(name, types); method.setAccessible(true);
        return method.invoke(extender, args);
    }

    @SuppressWarnings("unchecked") private static IExtensionHelpers helpers() {
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
                            IHttpService service = args[0] instanceof IHttpRequestResponse rr ? rr.getHttpService()
                                    : args.length == 2 ? (IHttpService) args[0] : null;
                            byte[] bytes = args[0] instanceof IHttpRequestResponse rr ? rr.getRequest() : (byte[]) args[args.length - 1];
                            String raw = text(bytes);
                            int offset = raw.indexOf("\r\n\r\n") + 4;
                            List<String> headers = Arrays.asList(raw.substring(0, offset - 4).split("\r\n"));
                            String[] line = headers.get(0).split(" ", 3);
                            URL url = service == null ? null : new URL(service.getProtocol(), service.getHost(), service.getPort(), line[1]);
                            return Proxy.newProxyInstance(IRequestInfo.class.getClassLoader(), new Class<?>[]{IRequestInfo.class},
                                    (p, getter, ignored) -> switch (getter.getName()) {
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
                                    (p, getter, ignored) -> switch (getter.getName()) {
                                        case "getStatusCode" -> (short) 200;
                                        case "getBodyOffset" -> raw.indexOf("\r\n\r\n") + 4;
                                        default -> throw new AssertionError(getter.getName());
                                    });
                        }
                        default: throw new AssertionError(method.getName());
                    }
                });
    }
    private static byte[] bytes(String text) { return text.getBytes(StandardCharsets.ISO_8859_1); }
    private static String text(byte[] bytes) { return new String(bytes, StandardCharsets.ISO_8859_1); }
    private static final class QueueExecutor extends AbstractExecutorService {
        final List<Runnable> tasks = new CopyOnWriteArrayList<>();
        @Override public void execute(Runnable task) { tasks.add(task); }
        @Override public void shutdown() { }
        @Override public List<Runnable> shutdownNow() { return List.of(); }
        @Override public boolean isShutdown() { return false; }
        @Override public boolean isTerminated() { return false; }
        @Override public boolean awaitTermination(long timeout, TimeUnit unit) { return false; }
        void drain() { while (!tasks.isEmpty()) tasks.remove(0).run(); }
    }
}
