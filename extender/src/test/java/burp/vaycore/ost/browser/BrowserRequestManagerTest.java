package burp.vaycore.ost.browser;

import org.junit.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

public class BrowserRequestManagerTest {

    @org.junit.Rule public org.junit.rules.TemporaryFolder temp = new org.junit.rules.TemporaryFolder();

    @Test public void concurrentScriptExportsDoNotRewriteAnAlreadyPublishedScript() throws Exception {
        BrowserRequestManager manager = new BrowserRequestManager();
        var export = BrowserRequestManager.class.getDeclaredMethod("ensureScriptFile", String.class);
        export.setAccessible(true);
        String dir = temp.newFolder().getAbsolutePath();
        java.io.File script = (java.io.File) export.invoke(manager, dir);
        byte[] expected = java.nio.file.Files.readAllBytes(script.toPath());
        var timestamp = java.nio.file.attribute.FileTime.fromMillis(1000000000000L);
        java.nio.file.Files.setLastModifiedTime(script.toPath(), timestamp);
        var pool = java.util.concurrent.Executors.newFixedThreadPool(4);
        try {
            java.util.List<java.util.concurrent.Future<java.io.File>> results = new java.util.ArrayList<>();
            for (int i = 0; i < 16; i++) results.add(pool.submit(() -> (java.io.File) export.invoke(manager, dir)));
            for (var result : results) {
                assertEquals(script, result.get(3, java.util.concurrent.TimeUnit.SECONDS));
                assertArrayEquals(expected, java.nio.file.Files.readAllBytes(script.toPath()));
            }
            assertEquals(timestamp, java.nio.file.Files.getLastModifiedTime(script.toPath()));
            java.nio.file.Files.writeString(script.toPath(), "outdated script");
            export.invoke(manager, dir);
            assertArrayEquals(expected, java.nio.file.Files.readAllBytes(script.toPath()));
            try (var files = java.nio.file.Files.list(script.toPath().getParent())) {
                assertEquals(1, files.count());
            }
        } finally {
            pool.shutdownNow(); assertTrue(pool.awaitTermination(3, java.util.concurrent.TimeUnit.SECONDS));
        }
    }

    @Test public void browserIdsResolveToIndependentSessionLocksProfilesAndPorts() throws Exception {
        BrowserRequestManager manager = new BrowserRequestManager();
        var get = BrowserRequestManager.class.getDeclaredMethod("getSession", String.class); get.setAccessible(true);
        Object ordinary = get.invoke(manager, BrowserRequest.DEFAULT_BROWSER_ID);
        Object probe = get.invoke(manager, "parameter-fuzz-test");
        assertSame(ordinary, get.invoke(manager, BrowserRequest.DEFAULT_BROWSER_ID));
        assertSame(probe, get.invoke(manager, "parameter-fuzz-test"));
        assertNotSame(ordinary, probe);
        for (String name : List.of("sessionId", "debugPort", "processLock")) {
            var field = ordinary.getClass().getDeclaredField(name); field.setAccessible(true);
            assertNotEquals(name, field.get(ordinary), field.get(probe));
        }
    }

    @Test public void retiredCleanupCannotCloseAReplacementSessionWithTheSameBrowserId() throws Exception {
        BrowserRequestManager manager = new BrowserRequestManager();
        var get = BrowserRequestManager.class.getDeclaredMethod("getSession", String.class); get.setAccessible(true);
        Object old = get.invoke(manager, BrowserRequest.DEFAULT_BROWSER_ID);
        Object oldProbe = get.invoke(manager, "parameter-fuzz-test");
        Runnable cleanup = manager.detachSessionsForClose(temp.newFolder().getAbsolutePath(), "", "edge", "");
        Object current = get.invoke(manager, BrowserRequest.DEFAULT_BROWSER_ID);
        Object currentProbe = get.invoke(manager, "parameter-fuzz-test");
        assertNotSame(old, current); assertNotSame(oldProbe, currentProbe);
        var directory = old.getClass().getDeclaredField("sessionId"); directory.setAccessible(true);
        assertNotEquals(directory.get(old), directory.get(current));
        // No profiles exist in this local fixture, so cleanup must not launch Python.
        cleanup.run();
        assertSame(current, get.invoke(manager, BrowserRequest.DEFAULT_BROWSER_ID));
        assertSame(currentProbe, get.invoke(manager, "parameter-fuzz-test"));
        var closed = old.getClass().getDeclaredField("closed"); closed.setAccessible(true);
        assertEquals(true, closed.get(old)); assertEquals(true, closed.get(oldProbe));
        assertEquals(false, closed.get(current)); assertEquals(false, closed.get(currentProbe));
    }

    @Test public void interpreterDiscoveryHasARealTimeoutEvenWhileStdoutStaysOpen() throws Exception {
        var method = BrowserRequestManager.class.getDeclaredMethod("runProcessAndCollectOutput", List.class);
        method.setAccessible(true);
        String javaExecutable = new java.io.File(System.getProperty("java.home"), "bin/java").getAbsolutePath();
        String classpath = System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
        long start = System.nanoTime();
        Object lines = method.invoke(new BrowserRequestManager(), List.of(javaExecutable, "-cp", classpath, DiscoveryFixture.class.getName()));
        long elapsed = java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
        assertTrue("discovery must not read stdout until EOF before checking the deadline: " + elapsed, elapsed < 4000);
        assertTrue(((List<?>) lines).contains("fixture-started"));
    }

    public static class DiscoveryFixture {
        public static void main(String[] args) throws Exception {
            System.out.println("fixture-started"); System.out.flush();
            Thread.sleep(6000);
        }
    }

    @Test public void missingDrissionPageInFirstInterpreterFallsBackToNext() {
        AtomicInteger attempts = new AtomicInteger();
        String result = BrowserRequestManager.executeCommands(
                List.of(List.of("python-without-package"), List.of("python-with-package")), command -> {
                    attempts.incrementAndGet();
                    if (command.get(0).equals("python-without-package")) {
                        throw new IllegalStateException("python browser bridge exit=1 output=Traceback:\n"
                                + "ModuleNotFoundError: No module named 'DrissionPage'");
                    }
                    return "STATUS=200";
                });
        assertEquals("STATUS=200", result);
        assertEquals(2, attempts.get());
    }

    @Test public void navigationFailureDoesNotReplayRequestWithNextInterpreter() {
        AtomicInteger attempts = new AtomicInteger();
        try {
            BrowserRequestManager.executeCommands(List.of(List.of("first"), List.of("second")), command -> {
                attempts.incrementAndGet();
                throw new IllegalStateException("browser navigation failed after POST");
            });
            fail("Expected the browser failure");
        } catch (IllegalStateException expected) {
            assertTrue(expected.getMessage().contains("browser navigation failed"));
        }
        assertEquals(1, attempts.get());
    }

    @Test public void scopeDecisionsUseExistingProcessPipesWithoutLeakingProtocolIntoResponse() throws Exception {
        BrowserRequestManager manager = new BrowserRequestManager();
        var get = BrowserRequestManager.class.getDeclaredMethod("getSession", String.class); get.setAccessible(true);
        Object session = get.invoke(manager, "scope-pipes");
        var predicate = session.getClass().getDeclaredField("scopeCheck"); predicate.setAccessible(true);
        AtomicInteger queries = new AtomicInteger();
        predicate.set(session, (java.util.function.Predicate<String>) url -> {
            queries.incrementAndGet();
            if (url.endsWith("/error")) throw new IllegalStateException("scope unavailable");
            return url.endsWith("/allowed");
        });
        var run = BrowserRequestManager.class.getDeclaredMethod("runCommand", session.getClass(), List.class, long.class, String.class);
        run.setAccessible(true);
        String java = new java.io.File(System.getProperty("java.home"), "bin/java").getAbsolutePath();
        String cp = System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
        String result = (String) run.invoke(manager, session, List.of(java, "-cp", cp, ScopePipeFixture.class.getName()),
                5000L, temp.newFolder().getAbsolutePath());
        assertEquals("STATUS=200", result); assertEquals(3, queries.get());
    }

    public static class ScopePipeFixture {
        public static void main(String[] args) throws Exception {
            var input = new java.io.BufferedReader(new java.io.InputStreamReader(System.in));
            for (String path : List.of("allowed", "denied", "error")) {
                System.out.println("SCOPE_CHECK=" + java.util.Base64.getEncoder().encodeToString(
                        ("https://scope.test/" + path).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
                System.out.flush();
                String expected = path.equals("allowed") ? "ALLOW" : "DENY";
                if (!expected.equals(input.readLine())) throw new AssertionError("Invalid scope decision");
            }
            System.out.println("STATUS=200");
        }
    }

    @Test public void missingDependencyEverywhereHasActionableError() {
        try {
            BrowserRequestManager.executeCommands(List.of(List.of("first"), List.of("second")), command -> {
                throw new IllegalStateException("ModuleNotFoundError: No module named 'DrissionPage'");
            });
            fail("Expected missing dependency error");
        } catch (IllegalStateException expected) {
            assertTrue(expected.getMessage().contains("DrissionPage is not available"));
            assertTrue(expected.getMessage().contains("Browser settings"));
        }
    }
}
