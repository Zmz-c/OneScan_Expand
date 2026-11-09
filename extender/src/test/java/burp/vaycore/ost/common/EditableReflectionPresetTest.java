package burp.vaycore.ost.common;

import burp.vaycore.ost.bean.*;
import burp.vaycore.ost.manager.*;
import burp.vaycore.ost.ui.widget.payloadlist.*;
import burp.vaycore.ost.ui.widget.payloadlist.rule.MatchReplace;
import org.junit.*;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.junit.Assert.*;

public class EditableReflectionPresetTest {
    @Rule public TemporaryFolder temp = new TemporaryFolder();
    private String directory;
    @Before public void init() throws Exception {
        directory = temp.newFolder().getAbsolutePath() + File.separator;
        Config.init(directory);
        FpManager.clearCache(); FpManager.clearHistory();
    }
    @After public void flush() { FpManager.saveNow(); }

    private ProcessingItem preset() {
        return Config.getPayloadProcessList().stream().filter(p -> p.getName().equals(ReflectionProbe.PRESET_NAME))
                .findFirst().orElseThrow();
    }
    private FpData fingerprint() {
        return FpManager.getList().stream().filter(p -> p.getParams().stream()
                .anyMatch(value -> ReflectionProbe.FINDING.equals(value.getV()))).findFirst().orElseThrow();
    }
    private static String process(ProcessingItem preset, String request) {
        for (var item : preset.getItems()) request = item.getRule().handleProcess(request);
        return VariableManager.resolveVariables(request);
    }
    private static boolean hit(String request, String responseBody) {
        return FpManager.check(request.getBytes(StandardCharsets.UTF_8),
                ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + responseBody).getBytes(StandardCharsets.UTF_8), false)
                .stream().anyMatch(p -> p.getParams().stream().anyMatch(v -> ReflectionProbe.FINDING.equals(v.getV())));
    }

    @Test public void usesOnlyExistingEditableActionsAndEditableFingerprintExpressions() {
        assertNull(SimplePayloadList.getPayloadRuleByType("AppendReflectionMarker"));
        for (var item : preset().getItems()) {
            assertTrue(item.getRule() instanceof MatchReplace);
            assertEquals(2, item.getRule().paramCount());
            assertFalse(item.getRule().getParamValues()[0].isBlank());
            assertTrue(item.getRule().getParamValues()[1].contains("{{nonce}}"));
        }
        var rule = fingerprint().getRules().get(0).get(0);
        assertEquals("response", rule.getDataSource());
        assertEquals("body", rule.getField());
        assertEquals("containsRequestMatch", rule.getMethod());
        assertFalse(rule.getContent().isBlank());
        assertTrue(FpRule.getMethods().contains("containsRequestMatch"));
    }

    @Test public void editedPositionAndMarkerFormatWorkAndSurviveReload() {
        ProcessingItem preset = preset();
        MatchReplace rule = new MatchReplace();
        rule.setParamValue(0, "(second=[^& \\r\\n]*)");
        rule.setParamValue(1, "$1custom{{nonce}}stop");
        PayloadItem item = new PayloadItem(); item.setScope(PayloadRule.SCOPE_REQUEST); item.setRule(rule);
        preset.setItems(new ArrayList<>(List.of(item)));
        preset.setEnabled(true);
        Config.put(Config.KEY_PAYLOAD_PROCESS_LIST, new ArrayList<>(List.of(preset)));
        fingerprint().getRules().get(0).get(0).setContent("(custom[0-9a-f]{24}stop)");
        FpManager.saveNow();
        Config.init(directory);
        String request = process(preset(), "GET /?first=keep&second=edit HTTP/1.1\r\nHost: example.test\r\n\r\n");
        assertTrue(request.contains("first=keep&second=editcustom"));
        var matcher = java.util.regex.Pattern.compile("custom[0-9a-f]{24}stop").matcher(request);
        assertTrue(matcher.find());
        String marker = matcher.group();
        assertTrue(hit(request, "<p>" + marker + "</p>"));
        assertFalse(hit(request, "customdifferentstop"));
        assertTrue(preset().isEnabled());
        assertEquals("(second=[^& \\r\\n]*)", preset().getItems().get(0).getRule().getParamValues()[0]);
    }

    @Test public void migratesOpaqueDevelopmentRuleWithoutChangingGroupSettingsOrOtherRules() {
        Map<String,Object> legacy = Map.of("name", "My saved probe", "enabled", true, "merge", true,
                "items", List.of(
                        Map.of("scope", 1, "ruleType", "AddSuffix", "rule", Map.of("paramValues", List.of("\r\nX-Test: 1"))),
                        Map.of("scope", 3, "ruleType", "AppendReflectionMarker", "rule", Map.of("paramValues", List.of()))));
        Config.put(Config.KEY_PAYLOAD_PROCESS_LIST, List.of(legacy));
        var oldCondition = fingerprint().getRules().get(0).get(0);
        oldCondition.setDataSource("reflection"); oldCondition.setField("reflected");
        oldCondition.setMethod("equals"); oldCondition.setContent("true");
        var exclusions = fingerprint().getRules().get(0).get(1);
        exclusions.setContent("^200$");
        FpManager.saveNow();
        for (int i=0;i<2;i++) {
            Config.init(directory);
            assertEquals(1, Config.getPayloadProcessList().size());
            var migrated = Config.getPayloadProcessList().get(0);
            assertEquals("My saved probe", migrated.getName());
            assertTrue(migrated.isEnabled()); assertTrue(migrated.isMerge());
            assertEquals(3, migrated.getItems().size());
            assertEquals("AddSuffix", migrated.getItems().get(0).getRuleType());
            assertEquals("\r\nX-Test: 1", migrated.getItems().get(0).getRule().getParamValues()[0]);
            assertEquals("MatchReplace", migrated.getItems().get(1).getRuleType());
            assertEquals("containsRequestMatch", fingerprint().getRules().get(0).get(0).getMethod());
            assertEquals("^200$", fingerprint().getRules().get(0).get(1).getContent());
        }
    }

    @Test public void requestMatchUsesFirstCaptureOrWholeMatchAndRejectsEmptyOrInvalidPatterns() {
        assertTrue(FpMethodHandler.containsRequestMatch("abc-123", "q=(abc-123)", "GET /?q=abc-123 HTTP/1.1"));
        assertTrue(FpMethodHandler.containsRequestMatch("abc-123", "abc-123", "q=abc-123"));
        assertFalse(FpMethodHandler.containsRequestMatch("ABC-123", "q=(abc-123)", "q=abc-123"));
        for (String pattern : new String[]{"", "(", "q=()", "not-present", "(optional)?q="}) {
            assertFalse(pattern, FpMethodHandler.containsRequestMatch("abc-123", pattern, "q=abc-123"));
        }
        assertFalse(FpMethodHandler.containsRequestMatch("abc-123", "(abc-123)", null));
    }

    @Test public void nonceIsSharedWithinExpansionButNotAcrossRequests() {
        String first = VariableManager.resolveVariables("{{nonce}}|{{nonce}}");
        String[] pair = first.split("\\|");
        assertEquals(pair[0], pair[1]);
        assertTrue(pair[0].matches("[0-9a-f]{24}"));
        assertNotEquals(first, VariableManager.resolveVariables("{{nonce}}|{{nonce}}"));
        assertEquals("fixed", VariableManager.resolveVariables("fixed"));
    }
}
