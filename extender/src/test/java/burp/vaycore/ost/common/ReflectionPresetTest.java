package burp.vaycore.ost.common;

import burp.vaycore.ost.bean.FpData;
import burp.vaycore.ost.manager.FpManager;
import burp.vaycore.ost.ui.widget.payloadlist.ProcessingItem;
import burp.vaycore.ost.ui.widget.payloadlist.rule.MatchReplace;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class ReflectionPresetTest {
    @Rule public TemporaryFolder temp = new TemporaryFolder();
    private String directory;

    @Before public void init() throws Exception {
        directory = temp.newFolder().getAbsolutePath() + File.separator;
        Config.init(directory);
        FpManager.clearCache();
        FpManager.clearHistory();
    }

    private static boolean isReflection(FpData item) {
        return item.getParams().stream().anyMatch(p -> ReflectionProbe.FINDING.equals(p.getV()));
    }

    private static String request() {
        return ReflectionTestSupport.apply("GET /?q=hello HTTP/1.1\r\nHost: example.test\r\n\r\n");
    }

    private static String response(int status, String headers, String body) {
        return "HTTP/1.1 " + status + " Test\r\n" + headers + "\r\n\r\n" + body;
    }

    private static boolean matches(String req, String resp) {
        return FpManager.check(req.getBytes(StandardCharsets.UTF_8), resp.getBytes(StandardCharsets.UTF_8))
                .stream().anyMatch(ReflectionPresetTest::isReflection);
    }

    @Test public void presetIsOptInTypedAndSurvivesReloadWithoutDuplication() {
        for (int i = 0; i < 3; i++) {
            List<ProcessingItem> rules = Config.getPayloadProcessList().stream()
                    .filter(r -> ReflectionProbe.PRESET_NAME.equals(r.getName())).toList();
            assertEquals(1, rules.size());
            assertFalse(rules.get(0).isEnabled());
            assertFalse(rules.get(0).isMerge());
            assertEquals(2, rules.get(0).getItems().size());
            assertTrue(rules.get(0).getItems().stream().allMatch(child -> child.getRule() instanceof MatchReplace
                    && child.getRule().paramCount() == 2));
            assertEquals(1, FpManager.getList().stream().filter(ReflectionPresetTest::isReflection).count());
            Config.init(directory);
        }
    }

    @Test public void userDeletionIsRespectedAndUpgradeDoesNotRestoreOldBypassTemplates() {
        Config.put(Config.KEY_PAYLOAD_PROCESS_LIST, new ArrayList<ProcessingItem>());
        for (int i = FpManager.getCount() - 1; i >= 0; i--) {
            if (isReflection(FpManager.getList().get(i))) FpManager.removeItem(i);
        }
        FpManager.saveNow();
        Config.init(directory);
        assertTrue(Config.getPayloadProcessList().isEmpty());
        assertFalse(FpManager.getList().stream().anyMatch(ReflectionPresetTest::isReflection));
        // Simulate upgrading a pre-reflection installation whose old templates were deleted.
        Config.removeKey(Config.KEY_REFLECTION_PRESET_INITIALIZED);
        Config.init(directory);
        assertEquals(1, Config.getPayloadProcessList().size());
        assertEquals(ReflectionProbe.PRESET_NAME, Config.getPayloadProcessList().get(0).getName());
        assertEquals(1, FpManager.getList().stream().filter(ReflectionPresetTest::isReflection).count());
    }

    @Test public void existingCustomizationsAreNotOverwrittenDuringMigration() {
        ProcessingItem rule = Config.getPayloadProcessList().stream()
                .filter(r -> ReflectionProbe.PRESET_NAME.equals(r.getName())).findFirst().orElseThrow();
        rule.setEnabled(true);
        rule.setName("My reflection probe");
        Config.put(Config.KEY_PAYLOAD_PROCESS_LIST, new ArrayList<>(List.of(rule)));
        int count = FpManager.getCount();
        Config.removeKey(Config.KEY_REFLECTION_PRESET_INITIALIZED);
        Config.init(directory);
        assertEquals(1, Config.getPayloadProcessList().size());
        assertEquals("My reflection probe", Config.getPayloadProcessList().get(0).getName());
        assertTrue(Config.getPayloadProcessList().get(0).isEnabled());
        assertEquals(count, FpManager.getCount());
    }

    @Test public void acceptsHtmlAndXhtmlButRejectsStatusContentTypeAndAttachments() {
        String req = request(), marker = ReflectionProbe.markerFromRequest(req);
        String body = "<html><title>Search results</title><p>" + marker + "</p></html>";
        assertTrue(matches(req, response(200, "Content-Type: text/html; charset=UTF-8", body)));
        assertTrue(matches(req, response(201, "content-type: application/xhtml+xml", body)));
        for (int status : new int[]{301, 400, 401, 403, 404, 412, 413, 429, 500, 503, 599}) {
            assertFalse("status " + status, matches(req, response(status, "Content-Type: text/html", body)));
        }
        for (String type : new String[]{"", "Content-Type: application/json", "Content-Type: text/plain",
                "Content-Type: text/htmlish", "Content-Type: text/html\r\nContent-Disposition: attachment; filename=a.html"}) {
            assertFalse(type, matches(req, response(200, type, body)));
        }
    }

    @Test public void excludesSoftErrorsAndChallengePagesWithoutBanningEveryErrorWord() {
        String req = request(), marker = ReflectionProbe.markerFromRequest(req);
        for (String title : new String[]{"404 Not Found", "Forbidden", "Just a moment...", "系统异常", "安全验证"}) {
            assertFalse(title, matches(req, response(200, "Content-Type: text/html", "<title>" + title + "</title>" + marker)));
        }
        for (String heading : new String[]{"<h1>404 Not Found</h1>", "<h2 class='x'><span>Error</span></h2>",
                "<H1>拒绝访问</H1>", "<h1>Request blocked</h1>"}) {
            assertFalse(heading, matches(req, response(200, "Content-Type: text/html", heading + marker)));
        }
        assertTrue(matches(req, response(200, "Content-Type: text/html",
                "<title>Search</title><script>var error = null;</script><p>" + marker + "</p>")));
    }

    @Test public void cookieSettingResponsesCannotReuseAnEarlierReflectionHit() {
        String req = request();
        String headers = "Content-Type: text/html\r\nSet-Cookie: session=fresh";
        assertTrue(matches(req, response(200, headers, ReflectionProbe.markerFromRequest(req))));
        assertFalse(matches(req, response(200, headers, "<p>No reflected input</p>")));
    }

    @Test public void cacheUsesThePairedRequestAndNeverAddsReflectionToSiteHistory() {
        String first = request(), second = request();
        String resp = response(200, "Content-Type: text/html", ReflectionProbe.markerFromRequest(first));
        assertTrue(matches(first, resp));
        assertTrue(matches(first, resp));
        assertFalse(matches(second, resp));
        List<FpData> history = FpManager.findHistoryByHost("example.test");
        assertTrue(history == null || history.stream().noneMatch(ReflectionPresetTest::isReflection));
    }
}
