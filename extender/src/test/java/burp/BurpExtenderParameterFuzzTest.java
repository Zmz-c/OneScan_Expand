package burp;

import burp.vaycore.ost.bean.TaskData;
import burp.vaycore.ost.common.HttpReqRespAdapter;
import burp.vaycore.ost.common.RequestMode;
import burp.vaycore.ost.ui.tab.ParameterFuzzScanOptions;
import burp.vaycore.ost.ui.tab.ParameterFuzzScanOptions.TargetOptions;
import burp.vaycore.ost.ui.tab.ParameterFuzzScanOptions.Mode;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class BurpExtenderParameterFuzzTest {

    @org.junit.Rule public org.junit.rules.TemporaryFolder temp = new org.junit.rules.TemporaryFolder();

    @Test
    public void cancelledProgressShowsSettledCountInsteadOfPretendingEverythingCompleted() throws Exception {
        burp.vaycore.ost.common.Config.init(temp.newFolder().getAbsolutePath() + java.io.File.separator);
        javax.swing.SwingUtilities.invokeAndWait(() -> {
            try {
                BurpExtender extender = new BurpExtender();
                burp.vaycore.ost.ui.tab.DataBoardTab board = new burp.vaycore.ost.ui.tab.DataBoardTab();
                board.init(new javax.swing.JTextArea(), new javax.swing.JTextArea());
                setField(extender, "mDataBoardTab", board);
                Class<?> type = Class.forName("burp.BurpExtender$ParameterFuzzProgress");
                var constructor = type.getDeclaredConstructor(BurpExtender.class, long.class);
                constructor.setAccessible(true);
                Object progress = constructor.newInstance(extender, 0L);
                setField(extender, "mActiveParameterFuzzProgress", progress);
                board.getParameterFuzzPanel().setScanRunning(true);
                Method start = type.getDeclaredMethod("startDispatch", int.class);
                start.setAccessible(true); start.invoke(progress, 10);
                for (String name : List.of("requestQueued", "requestQueued", "requestCompleted", "cancel")) {
                    Method action = type.getDeclaredMethod(name); action.setAccessible(true); action.invoke(progress);
                }
                Field field = board.getParameterFuzzPanel().getClass().getDeclaredField("mProgressBar");
                field.setAccessible(true);
                javax.swing.JProgressBar bar = (javax.swing.JProgressBar) field.get(board.getParameterFuzzPanel());
                assertEquals(1, bar.getValue());
                assertEquals(10, bar.getMaximum());
                board.closeDataSaveExecutor();
            } catch (Exception e) { throw new RuntimeException(e); }
        });
    }

    private static final IHttpService SERVICE = new IHttpService() {
        public String getHost() { return "example.test"; }
        public int getPort() { return 443; }
        public String getProtocol() { return "https"; }
    };

    @Test
    public void buildsExactPositionProbesAndRecalculatesBodyLength() throws Exception {
        String get = "GET /items?id=keep&id=$1$ HTTP/1.1\r\nHost: example.test\r\n\r\n";
        String body = "{\n\"items\": [1, \"$1$\", 3], \"fixed\": true\n}";
        String post = "POST /items HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\nContent-Length: 999\r\n\r\n" + body;
        List<TaskData> targets = List.of(target("GET", get, 200), target("POST", post, 200));
        ParameterFuzzScanOptions options = options(targets, List.of(get, post), true, true);
        List<byte[]> probes = buildProbes(options);
        assertEquals(4, probes.size());
        assertEquals(get.replace("$1$", "abc"), new String(probes.get(0), StandardCharsets.UTF_8));
        assertEquals(get.replace("$1$", "中文"), new String(probes.get(1), StandardCharsets.UTF_8));
        for (int i = 0; i < 2; i++) {
            String expectedBody = body.replace("$1$", options.scans().get(0).positionValues().get("1").get(i));
            String result = new String(probes.get(i + 2), StandardCharsets.UTF_8);
            assertTrue(result.endsWith("\r\n\r\n" + expectedBody));
            assertTrue(result.contains("\r\nContent-Length: " + expectedBody.getBytes(StandardCharsets.UTF_8).length + "\r\n"));
            assertFalse(result.contains("Content-Length: 999"));
        }
    }

    @Test
    public void customProbesRespectRoutesMethodsAndUnmarkedRequests() throws Exception {
        String get = "GET /items?id=$1$ HTTP/1.1\r\nHost: example.test\r\n\r\n";
        String post = "POST /items HTTP/1.1\r\nHost: example.test\r\n\r\n$1$";
        List<TaskData> targets = List.of(target("GET", get, 200), target("GET", get, 404),
                target("GET", get, 410), target("POST", post, 200), target("GET", get, 200));
        assertEquals(2, buildProbes(options(targets, List.of(get, get, get, post, get.replace("$1$", "fixed")),
                true, false)).size());
        assertEquals(2, buildProbes(options(targets, List.of(get, get, get, post, get.replace("$1$", "fixed")),
                false, true)).size());
    }

    @Test
    public void requestTemplateSnapshotDoesNotExposeMutableBytes() {
        String get = "GET /?id=$1$ HTTP/1.1\r\nHost: example.test\r\n\r\n";
        byte[] template = get.getBytes(StandardCharsets.UTF_8);
        ParameterFuzzScanOptions options = batch(List.of(target("GET", get, 200)), false,
                List.of(), List.of("value"), List.of(template), List.of(Map.of("1", List.of("value"))), true, false, true, RequestMode.BURP, "");
        template[0] = 'X';
        options.scans().get(0).requestTemplate()[1] = 'X';
        assertArrayEquals(get.getBytes(StandardCharsets.UTF_8), options.scans().get(0).requestTemplate());
    }

    @Test public void independentPerUrlDictionariesGenerateAllCombinationsWithoutGlobalValues() throws Exception {
        String first = "GET /first?$1$=$2$&$3$=$4$ HTTP/1.1\r\nHost: example.test\r\n\r\n";
        String second = "POST /second HTTP/1.1\r\nHost: example.test\r\n\r\n{\"$1$\":\"$2$\"}";
        var options = batch(List.of(target("GET", first, 200), target("POST", second, 200)),
                false, List.of(), List.of(), List.of(first.getBytes(), second.getBytes()), List.of(
                Map.of("1", List.of("a", "b"), "2", List.of("1", "2"), "3", List.of("fixed"), "4", List.of("yes")),
                Map.of("1", List.of("jsonName"), "2", List.of("jsonValue"))), true, true, true, RequestMode.BURP, "");
        List<byte[]> probes = buildProbes(options);
        assertEquals(5, probes.size());
        assertTrue(new String(probes.get(0)).startsWith("GET /first?a=1&fixed=yes "));
        assertTrue(new String(probes.get(3)).startsWith("GET /first?b=2&fixed=yes "));
        assertTrue(new String(probes.get(4)).endsWith("{\"jsonName\":\"jsonValue\"}"));
    }

    @Test public void positionSnapshotCopiesMappingsAndNestedDictionaryLists() {
        String raw = "GET /?$1$=$2$ HTTP/1.1\r\n\r\n";
        List<String> names = new ArrayList<>(List.of("name"));
        Map<String, List<String>> positions = new java.util.LinkedHashMap<>();
        positions.put("1", names); positions.put("2", List.of("value"));
        List<Map<String, List<String>>> all = new ArrayList<>(List.of(positions));
        var options = batch(List.of(target("GET", raw, 200)), false, List.of(), List.of(),
                List.of(raw.getBytes()), all, true, false, true, RequestMode.BURP, "");
        names.clear(); positions.clear(); all.clear();
        assertEquals(List.of("name"), options.scans().get(0).positionValues().get("1"));
        org.junit.Assert.assertThrows(UnsupportedOperationException.class, () -> options.scans().clear());
        org.junit.Assert.assertThrows(UnsupportedOperationException.class, () -> options.scans().get(0).positionValues().clear());
        org.junit.Assert.assertThrows(UnsupportedOperationException.class, () -> options.scans().get(0).positionValues().get("1").clear());
    }

    @Test public void rejectsTooManyCombinationsBeforeExpansionAndEnforcesAggregateLimit() throws Exception {
        String raw = "GET /?$1$=$2$ HTTP/1.1\r\nHost: example.test\r\n\r\n";
        List<String> values = java.util.stream.IntStream.range(0, 100).mapToObj(String::valueOf).toList();
        var options = batch(List.of(target("GET", raw, 200)), false, List.of(), List.of(),
                List.of(raw.getBytes()), List.of(Map.of("1", values, "2", values)), true, false, true, RequestMode.BURP, "");
        var exception = org.junit.Assert.assertThrows(java.lang.reflect.InvocationTargetException.class, () -> buildProbes(options));
        assertEquals("ParameterFuzzLimitException", exception.getCause().getClass().getSimpleName());
        List<String> half = values.subList(0, 50);
        var atLimit = batch(options.scans().stream().map(TargetOptions::target).toList(), false, List.of(), List.of(), options.scans().stream().map(TargetOptions::requestTemplate).toList(),
                List.of(Map.of("1", values, "2", half)), true, false, true, RequestMode.BURP, "");
        assertEquals(5000, buildProbes(atLimit).size());
        var twoTargets = batch(List.of(target("GET", raw, 200), target("GET", raw, 200)),
                false, List.of(), List.of(), List.of(raw.getBytes(), raw.getBytes()),
                List.of(Map.of("1", values, "2", half), Map.of("1", List.of("x"), "2", List.of("y"))),
                true, false, true, RequestMode.BURP, "");
        var aggregate = org.junit.Assert.assertThrows(java.lang.reflect.InvocationTargetException.class, () -> buildProbes(twoTargets));
        assertEquals("ParameterFuzzLimitException", aggregate.getCause().getClass().getSimpleName());
    }

    @Test public void mixedModesGenerateActualProbesWithIndependentDictionariesAndTransportsInAnyOrder() throws Exception {
        String get = "GET /names HTTP/1.1\r\nHost: example.test\r\n\r\n";
        String post = "POST /values?q=old HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{\"id\":\"old\"}";
        String custom = "GET /positions?id=$1$ HTTP/1.1\r\nHost: example.test\r\n\r\n";
        TargetOptions names = new TargetOptions(target("GET", get, 200), Mode.NAMES, List.of("debug"),
                List.of("a1", "a2"), null, Map.of(), true, false, true, RequestMode.BURP, "ignored");
        TargetOptions values = new TargetOptions(target("POST", post, 200), Mode.VALUES, List.of(),
                List.of("b1"), null, Map.of(), false, true, true, RequestMode.BROWSER, "parameter-fuzz-test");
        TargetOptions positions = new TargetOptions(target("GET", custom, 200), Mode.POSITIONS, List.of(),
                List.of(), custom.getBytes(), Map.of("1", List.of("c1", "c2")), true, false, true, RequestMode.BURP, "");
        for (List<TargetOptions> order : List.of(List.of(names, values, positions), List.of(names, positions, values),
                List.of(values, names, positions), List.of(values, positions, names),
                List.of(positions, names, values), List.of(positions, values, names))) {
            List<?> probes = buildProbeRecords(new ParameterFuzzScanOptions(order), mixedMessageHelpers());
            assertEquals(6, probes.size());
            java.util.Set<String> signatures = new java.util.HashSet<>();
            for (Object probe : probes) {
                String raw = new String((byte[]) probeField(probe, "request"), StandardCharsets.UTF_8);
                String firstLine = raw.substring(0, raw.indexOf("\r\n"));
                String body = raw.substring(raw.indexOf("\r\n\r\n") + 4);
                signatures.add(firstLine + "|" + body);
                if (raw.startsWith("POST /values")) {
                    assertEquals(RequestMode.BROWSER, probeField(probe, "requestMode"));
                    assertEquals("parameter-fuzz-test", probeField(probe, "browserId"));
                    assertTrue(raw.contains("Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\n"));
                } else {
                    assertEquals(RequestMode.BURP, probeField(probe, "requestMode"));
                    assertEquals("", probeField(probe, "browserId"));
                }
            }
            assertEquals(java.util.Set.of("GET /names?debug=a1 HTTP/1.1|", "GET /names?debug=a2 HTTP/1.1|",
                    "POST /values?q=b1 HTTP/1.1|{\"id\":\"old\"}", "POST /values?q=old HTTP/1.1|{\"id\":\"b1\"}",
                    "GET /positions?id=c1 HTTP/1.1|", "GET /positions?id=c2 HTTP/1.1|"), signatures);
        }
    }

    @Test public void unmarkedAndFilteredEntriesDoNotAbortOtherModesAndLimitIsSharedAcrossModes() throws Exception {
        String raw = "GET /?id=old HTTP/1.1\r\nHost: example.test\r\n\r\n";
        TargetOptions unmarked = new TargetOptions(target("GET", raw, 200), Mode.POSITIONS, List.of(), List.of(),
                raw.getBytes(), Map.of(), true, false, true, RequestMode.BURP, "");
        TargetOptions filtered = new TargetOptions(target("GET", raw, 404), Mode.NAMES, List.of(), List.of(),
                null, Map.of(), true, false, true, RequestMode.BURP, "");
        TargetOptions values = new TargetOptions(target("GET", raw, 200), Mode.VALUES, List.of(), List.of("one"),
                null, Map.of(), true, false, true, RequestMode.BURP, "");
        assertEquals(1, buildProbeRecords(new ParameterFuzzScanOptions(List.of(unmarked, filtered, values)), mixedMessageHelpers()).size());
        List<String> many = java.util.stream.IntStream.range(0, 5000).mapToObj(String::valueOf).toList();
        TargetOptions names = new TargetOptions(target("GET", raw, 200), Mode.NAMES, List.of("debug"), many,
                null, Map.of(), true, false, true, RequestMode.BURP, "");
        String template = raw.replace("old", "$1$");
        TargetOptions positions = new TargetOptions(target("GET", raw, 200), Mode.POSITIONS, List.of(), List.of(),
                template.getBytes(), Map.of("1", List.of("one")), true, false, true, RequestMode.BURP, "");
        for (var order : List.of(List.of(names, positions), List.of(positions, names))) {
            var exception = org.junit.Assert.assertThrows(java.lang.reflect.InvocationTargetException.class,
                    () -> buildProbeRecords(new ParameterFuzzScanOptions(order), mixedMessageHelpers()));
            assertEquals("ParameterFuzzLimitException", exception.getCause().getClass().getSimpleName());
        }
    }

    @Test @SuppressWarnings("unchecked") public void browserContextDoesNotLeakToHttpProbeOrCallerAfterFailure() throws Exception {
        BurpExtender extender = new BurpExtender();
        Field contextField = BurpExtender.class.getDeclaredField("mBrowserRequestIdContext");
        contextField.setAccessible(true);
        ThreadLocal<String> context = (ThreadLocal<String>) contextField.get(extender);
        context.set("caller");
        Method run = BurpExtender.class.getDeclaredMethod("runWithBrowserRequestId", String.class, Runnable.class);
        run.setAccessible(true);
        run.invoke(extender, "fuzz-browser", (Runnable) () -> assertEquals("fuzz-browser", context.get()));
        assertEquals("caller", context.get());
        run.invoke(extender, "", (Runnable) () -> org.junit.Assert.assertNull(context.get()));
        assertEquals("caller", context.get());
        org.junit.Assert.assertThrows(java.lang.reflect.InvocationTargetException.class,
                () -> run.invoke(extender, "fuzz-browser", (Runnable) () -> { throw new IllegalStateException("fixture"); }));
        assertEquals("caller", context.get());
        context.remove();
    }

    private static Object probeField(Object probe, String name) throws Exception {
        Method getter = probe.getClass().getDeclaredMethod(name); getter.setAccessible(true); return getter.invoke(probe);
    }

    /** Fake Burp mutators for local request-generation regression tests; never sends network traffic. */
    private static IExtensionHelpers mixedMessageHelpers() {
        IExtensionHelpers base = httpMessageHelpers();
        return (IExtensionHelpers) Proxy.newProxyInstance(IExtensionHelpers.class.getClassLoader(),
                new Class<?>[]{IExtensionHelpers.class}, (proxy, method, args) -> {
            if (method.getName().equals("buildParameter")) {
                return testParameter((String) args[0], (String) args[1], (Byte) args[2]);
            }
            if (method.getName().equals("analyzeRequest")) {
                byte[] bytes = (byte[]) args[args.length - 1];
                String raw = new String(bytes, StandardCharsets.UTF_8);
                IRequestInfo info = base.analyzeRequest(bytes);
                List<IParameter> parameters = new ArrayList<>();
                String path = raw.split(" ", 3)[1];
                if (path.contains("?")) for (String entry : path.substring(path.indexOf('?') + 1).split("&")) {
                    String[] pair = entry.split("=", 2);
                    parameters.add(testParameter(pair[0], pair.length == 1 ? "" : pair[1], IParameter.PARAM_URL));
                }
                String body = raw.substring(raw.indexOf("\r\n\r\n") + 4);
                if (body.startsWith("{")) {
                    var json = com.google.gson.JsonParser.parseString(body).getAsJsonObject();
                    json.entrySet().forEach(entry -> parameters.add(testParameter(entry.getKey(), entry.getValue().getAsString(), IParameter.PARAM_JSON)));
                }
                return Proxy.newProxyInstance(IRequestInfo.class.getClassLoader(), new Class<?>[]{IRequestInfo.class},
                        (object, getter, arguments) -> getter.getName().equals("getParameters") ? parameters : getter.invoke(info, arguments));
            }
            if (method.getName().equals("addParameter") || method.getName().equals("updateParameter")) {
                String raw = new String((byte[]) args[0], StandardCharsets.UTF_8);
                IParameter parameter = (IParameter) args[1];
                if (parameter.getType() == IParameter.PARAM_JSON) {
                    throw new AssertionError("Burp addParameter/updateParameter do not support JSON");
                } else {
                    String[] requestLine = raw.substring(0, raw.indexOf("\r\n")).split(" ");
                    String path = requestLine[1];
                    if (method.getName().equals("addParameter")) path += (path.contains("?") ? "&" : "?") + parameter.getName() + "=" + parameter.getValue();
                    else path = path.replace(parameter.getName() + "=old", parameter.getName() + "=" + parameter.getValue());
                    raw = requestLine[0] + " " + path + " " + requestLine[2] + raw.substring(raw.indexOf("\r\n"));
                }
                return raw.getBytes(StandardCharsets.UTF_8);
            }
            return method.invoke(base, args);
        });
    }

    private static IParameter testParameter(String name, String value, byte type) {
        return (IParameter) Proxy.newProxyInstance(IParameter.class.getClassLoader(), new Class<?>[]{IParameter.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getName" -> name;
                    case "getValue" -> value;
                    case "getType" -> type;
                    default -> -1;
                });
    }

    private static ParameterFuzzScanOptions batch(List<TaskData> targets, boolean names, List<String> nameValues,
                                                   List<String> values, List<byte[]> templates,
                                                   List<Map<String, List<String>>> positions,
                                                   boolean get, boolean post, boolean existing,
                                                   RequestMode requestMode, String browserId) {
        List<TargetOptions> scans = new ArrayList<>();
        for (int i = 0; i < targets.size(); i++) {
            scans.add(new TargetOptions(targets.get(i), templates.isEmpty() ? (names ? Mode.NAMES : Mode.VALUES) : Mode.POSITIONS,
                    nameValues, values, templates.isEmpty() ? null : templates.get(i),
                    positions.isEmpty() ? Map.of() : positions.get(i), get, post, existing, requestMode, browserId));
        }
        return new ParameterFuzzScanOptions(scans);
    }

    private static ParameterFuzzScanOptions options(List<TaskData> targets, List<String> templates,
                                                     boolean get, boolean post) {
        return batch(targets, false, List.of(), List.of("abc", "中文"),
                templates.stream().map(s -> s.getBytes(StandardCharsets.UTF_8)).toList(),
                templates.stream().map(s -> Map.of("1", List.of("abc", "中文"))).toList(),
                get, post, true, RequestMode.BURP, "");
    }

    private static TaskData target(String method, String raw, int status) {
        TaskData target = new TaskData();
        target.setMethod(method);
        target.setStatus(status);
        target.setReqResp(HttpReqRespAdapter.from(SERVICE, raw.replace("$1$", "original").getBytes(StandardCharsets.UTF_8)));
        return target;
    }

    private static List<byte[]> buildProbes(ParameterFuzzScanOptions options) throws Exception {
        List<byte[]> result = new ArrayList<>();
        for (Object probe : buildProbeRecords(options, httpMessageHelpers())) result.add((byte[]) probeField(probe, "request"));
        return result;
    }

    private static List<?> buildProbeRecords(ParameterFuzzScanOptions options, IExtensionHelpers helpers) throws Exception {
        BurpExtender extender = new BurpExtender();
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            setField(extender, "mTaskThreadPool", pool);
            setField(extender, "mLFTaskThreadPool", pool);
            setField(extender, "mBrowserTaskThreadPool", pool);
            setField(extender, "mHelpers", helpers);
            Method build = BurpExtender.class.getDeclaredMethod("buildParameterFuzzProbes", ParameterFuzzScanOptions.class);
            build.setAccessible(true);
            return (List<?>) build.invoke(extender, options);
        } finally { pool.shutdownNow(); }
    }

    private static void setField(Object instance, String name, Object value) throws Exception {
        Field field = BurpExtender.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(instance, value);
    }

    @SuppressWarnings("unchecked")
    private static IExtensionHelpers httpMessageHelpers() {
        return (IExtensionHelpers) Proxy.newProxyInstance(IExtensionHelpers.class.getClassLoader(),
                new Class<?>[]{IExtensionHelpers.class}, (instance, method, args) -> {
                    if (method.getName().equals("analyzeRequest")) {
                        String raw = new String((byte[]) args[args.length - 1], StandardCharsets.ISO_8859_1);
                        int headerEnd = raw.indexOf("\r\n\r\n");
                        assertTrue(headerEnd >= 0);
                        List<String> headers = Arrays.asList(raw.substring(0, headerEnd).split("\r\n"));
                        return Proxy.newProxyInstance(IRequestInfo.class.getClassLoader(), new Class<?>[]{IRequestInfo.class},
                                (info, getter, ignored) -> switch (getter.getName()) {
                                    case "getHeaders" -> headers;
                                    case "getBodyOffset" -> headerEnd + 4;
                                    case "getMethod" -> raw.substring(0, raw.indexOf(' '));
                                    default -> throw new AssertionError("Unexpected request inspection: " + getter.getName());
                                });
                    }
                    if (method.getName().equals("buildHttpMessage")) {
                        List<String> headers = new ArrayList<>((List<String>) args[0]);
                        byte[] body = (byte[]) args[1];
                        if (body.length > 0) {
                            headers.add("Content-Length: " + body.length);
                        }
                        ByteArrayOutputStream result = new ByteArrayOutputStream();
                        result.write((String.join("\r\n", headers) + "\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
                        result.write(body);
                        return result.toByteArray();
                    }
                    // Explicit positions must not call addParameter/updateParameter.
                    throw new AssertionError("Unexpected helper call: " + method.getName());
                });
    }

    @Test
    public void filtersKnownMissingRoutesFromParameterFuzzTargets() {
        assertTrue(BurpExtender.isConfirmedExistingRouteStatus(200));
        assertTrue(BurpExtender.isConfirmedExistingRouteStatus(301));
        assertTrue(BurpExtender.isConfirmedExistingRouteStatus(401));
        assertTrue(BurpExtender.isConfirmedExistingRouteStatus(403));
        assertTrue(BurpExtender.isConfirmedExistingRouteStatus(500));

        assertFalse(BurpExtender.isConfirmedExistingRouteStatus(-1));
        assertFalse(BurpExtender.isConfirmedExistingRouteStatus(0));
        assertFalse(BurpExtender.isConfirmedExistingRouteStatus(404));
        assertFalse(BurpExtender.isConfirmedExistingRouteStatus(410));
        assertFalse(BurpExtender.isConfirmedExistingRouteStatus(600));
    }

    @Test
    public void parameterScanningOnlyAcceptsSelectedGetAndPostMethods() {
        assertTrue(BurpExtender.isParameterScanMethodAllowed("GET", true, false));
        assertTrue(BurpExtender.isParameterScanMethodAllowed("POST", false, true));
        assertFalse(BurpExtender.isParameterScanMethodAllowed("GET", false, true));
        assertFalse(BurpExtender.isParameterScanMethodAllowed("POST", true, false));
        assertFalse(BurpExtender.isParameterScanMethodAllowed("PUT", true, true));
        assertFalse(BurpExtender.isParameterScanMethodAllowed(null, true, true));
    }
}
