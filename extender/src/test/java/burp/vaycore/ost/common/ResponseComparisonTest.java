package burp.vaycore.ost.common;

import burp.vaycore.ost.bean.TaskData;
import burp.vaycore.ost.browser.BrowserRequest;
import burp.vaycore.ost.manager.VariableManager;
import burp.vaycore.ost.ui.widget.payloadlist.PayloadItem;
import burp.vaycore.ost.ui.widget.payloadlist.PayloadRule;
import com.google.gson.internal.LinkedTreeMap;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class ResponseComparisonTest {

    @Test
    public void comparesJsonRegexAndRawBodyDifferences() {
        String result = ResponseComparison.compare(List.of(
                task("reader", "same", 200, "{\"id\":1,\"role\":\"reader\"}"),
                task("admin", "same", 200, "{\"id\":1,\"role\":\"admin\"}")), "\"role\":\"\\w+\"");

        assertTrue(result.contains("$.role"));
        assertTrue(result.contains("reader"));
        assertTrue(result.contains("admin"));
        assertTrue(result.contains("reader: \"role\":\"reader\""));
        assertTrue(result.contains("admin: \"role\":\"admin\""));
        assertTrue(result.contains("- {\"id\":1,\"role\":\"reader\"}"));
        assertTrue(result.contains("+ {\"id\":1,\"role\":\"admin\"}"));
    }

    @Test
    public void browserRequestCookieIsolationDefaultsToFalseAndCanBeEnabled() {
        BrowserRequest defaultRequest = BrowserRequest.of("GET", "https://example.test", List.of(), new byte[0]);
        BrowserRequest isolatedRequest = BrowserRequest.of("GET", "https://example.test", List.of(), new byte[0], true);

        assertTrue(!defaultRequest.isolateCookies());
        assertTrue(isolatedRequest.isolateCookies());
    }
    @Test
    public void detectsUnresolvedNamedVariablePlaceholders() {
        assertTrue(VariableManager.hasUnresolvedVariables("/api/{{value.tenant}}"));
        assertTrue(VariableManager.hasUnresolvedVariables("https://{{random.host}}/health"));
        assertTrue(!VariableManager.hasUnresolvedVariables("/api/tenant-a"));
    }
    @Test
    public void migratesIncompleteLegacyPayloadRules() {
        LinkedTreeMap<String, Object> rule = new LinkedTreeMap<>();
        rule.put("ruleType", "AddPrefix");
        rule.put("rule", new LinkedTreeMap<String, Object>());

        PayloadItem migrated = Config.mapItemsConvert(new java.util.ArrayList<>(List.of(rule))).get(0);

        assertTrue(migrated.getScope() == PayloadRule.SCOPE_URL);
        assertTrue(migrated.getRule() != null);
        assertTrue("".equals(migrated.getRule().getParamValues()[0]));
    }
    @Test
    public void rejectsDifferentVariants() {
        assertThrows(IllegalArgumentException.class, () -> ResponseComparison.compare(List.of(
                task("reader", "one", 200, "ok"),
                task("admin", "two", 200, "ok"))));
    }

    @Test
    public void rejectsInvalidRegex() {
        assertThrows(IllegalArgumentException.class, () -> ResponseComparison.compare(List.of(
                task("reader", "same", 200, "ok"),
                task("admin", "same", 200, "ok")), "["));
    }

    private static TaskData task(String profile, String variant, int status, String body) {
        TaskData task = new TaskData();
        task.setProfile(profile);
        task.setVariantId(variant);
        task.setHost("https://example.test");
        task.setUrl("/api/orders");
        task.setStatus(status);
        task.setRespBytes(("HTTP/1.1 " + status + " OK\r\nContent-Type: application/json\r\n\r\n" + body)
                .getBytes(StandardCharsets.UTF_8));
        return task;
    }
}
