package burp;

import burp.vaycore.ost.bean.VariableDefinition;
import burp.vaycore.ost.common.Config;
import burp.vaycore.ost.manager.WordlistManager;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class BurpExtenderMcpTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void managesVariablesAndRedactsProfilesByDefault() throws Exception {
        File workDir = temporaryFolder.newFolder("mcp-config");
        Config.init(workDir.getAbsolutePath() + File.separator);
        BurpExtender extender = new BurpExtender();

        Map<String, Object> variable = map(extender.callTool("ost.variable.create", Map.of("name", "tenant")));
        assertEquals(VariableDefinition.STRATEGY_FIXED, variable.get("strategy"));
        assertEquals("{{value.tenant}}", variable.get("placeholder"));

        Map<String, Object> profileArguments = new LinkedHashMap<>();
        profileArguments.put("name", "reader");
        profileArguments.put("replace_cookie", true);
        profileArguments.put("cookie", "session=secret");
        profileArguments.put("headers", Map.of("Authorization", "Bearer secret"));
        profileArguments.put("variables", Map.of("userId", "17"));
        Map<String, Object> created = map(extender.callTool("ost.profile.create", profileArguments));
        assertFalse(created.containsKey("cookie"));
        assertFalse(created.containsKey("headers"));

        Map<String, Object> listed = map(extender.callTool("ost.profiles.list", Map.of()));
        Map<String, Object> summary = map(((List<?>) listed.get("items")).get(0));
        assertFalse(summary.containsKey("cookie"));
        assertEquals(1, ((Number) summary.get("header_count")).intValue());

        Map<String, Object> sensitive = map(extender.callTool("ost.profile.get",
                Map.of("name", "reader", "include_sensitive", true)));
        assertEquals("session=secret", sensitive.get("cookie"));
        assertEquals("Bearer secret", map(sensitive.get("headers")).get("Authorization"));

        try {
            extender.callTool("ost.profile.delete", Map.of("name", "reader"));
            fail("profile deletion should require confirmation");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("confirm=true"));
        }
        Map<String, Object> deleted = map(extender.callTool("ost.profile.delete",
                Map.of("name", "reader", "confirm", true)));
        assertEquals(Boolean.TRUE, deleted.get("deleted"));
    }

    @Test
    public void readsAndDeletesPersistedHistoryWithExplicitConfirmation() throws Exception {
        File workDir = temporaryFolder.newFolder("mcp-history");
        Config.init(workDir.getAbsolutePath() + File.separator);
        File database = new File(workDir, "history.sqlite");
        Config.put(Config.KEY_DATA_PERSISTENCE_DB_PATH, database.getAbsolutePath());

        burp.vaycore.ost.bean.TaskData task = new burp.vaycore.ost.bean.TaskData();
        task.setId(42);
        task.setHost("https://history.test");
        task.setRequestScope("burp");
        task.setReqBytes("GET /history HTTP/1.1\\r\\nHost: history.test\\r\\n\\r\\n"
                .getBytes(StandardCharsets.ISO_8859_1));
        task.setRespBytes("HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nOK"
                .getBytes(StandardCharsets.ISO_8859_1));
        burp.vaycore.ost.manager.TaskPersistenceManager.persistSnapshot(
                List.of(task), List.of(burp.vaycore.ost.manager.TaskPersistenceManager.FIELD_HOST), "mcp-history");

        BurpExtender extender = new BurpExtender();
        Map<String, Object> listed = map(extender.callTool("ost.history.tasks.list",
                Map.of("label", "mcp-history", "include_body", true)));
        assertEquals(1, ((Number) listed.get("total")).intValue());
        Map<String, Object> item = map(((List<?>) listed.get("items")).get(0));
        assertEquals("history", item.get("source"));
        assertEquals("GET /history HTTP/1.1\\r\\nHost: history.test\\r\\n\\r\\n", item.get("request"));

        try {
            extender.callTool("ost.history.delete", Map.of("labels", List.of("mcp-history")));
            fail("history deletion should require confirmation");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("confirm=true"));
        }
        Map<String, Object> deleted = map(extender.callTool("ost.history.delete",
                Map.of("labels", List.of("mcp-history"), "confirm", true)));
        assertEquals(1, ((Number) deleted.get("deleted")).intValue());
    }

    @Test
    public void requiresConfirmationBeforeReplacingAnExistingExport() throws Exception {
        File workDir = temporaryFolder.newFolder("mcp-export");
        Config.init(workDir.getAbsolutePath() + File.separator);
        Config.put(Config.KEY_DATA_PERSISTENCE_DB_PATH,
                new File(workDir, "history.sqlite").getAbsolutePath());
        File output = temporaryFolder.newFile("existing.csv");
        java.nio.file.Files.writeString(output.toPath(), "preserve", StandardCharsets.UTF_8);

        BurpExtender extender = new BurpExtender();
        try {
            extender.callTool("ost.export.csv", Map.of("path", output.getAbsolutePath()));
            fail("export should require confirmation before replacing a file");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("confirm=true"));
        }
        Map<String, Object> exported = map(extender.callTool("ost.export.csv",
                Map.of("path", output.getAbsolutePath(), "confirm", true)));
        assertEquals(0, ((Number) exported.get("count")).intValue());
        String exportedContent = java.nio.file.Files.readString(output.toPath(), StandardCharsets.UTF_8);
        assertFalse(exportedContent.isEmpty());
        assertFalse("preserve".equals(exportedContent));
    }

    @Test
    public void doesNotCreateWordlistWhenReplaceImportLacksConfirmation() throws Exception {
        File workDir = temporaryFolder.newFolder("mcp-import");
        Config.init(workDir.getAbsolutePath() + File.separator);
        File input = temporaryFolder.newFile("replacement.txt");
        java.nio.file.Files.writeString(input.toPath(), "example" + System.lineSeparator(), StandardCharsets.UTF_8);
        BurpExtender extender = new BurpExtender();
        String wordlistName = "replace-confirmation";

        assertFalse(WordlistManager.getItemList(WordlistManager.KEY_PAYLOAD).contains(wordlistName));
        try {
            extender.callTool("ost.wordlist.import_file", Map.of(
                    "key", WordlistManager.KEY_PAYLOAD, "name", wordlistName,
                    "path", input.getAbsolutePath(), "mode", "replace"));
            fail("replace import should require confirmation");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("confirm=true"));
        }
        assertFalse(WordlistManager.getItemList(WordlistManager.KEY_PAYLOAD).contains(wordlistName));

        Map<String, Object> imported = map(extender.callTool("ost.wordlist.import_file", Map.of(
                "key", WordlistManager.KEY_PAYLOAD, "name", wordlistName,
                "path", input.getAbsolutePath(), "mode", "replace", "confirm", true)));
        assertEquals(wordlistName, imported.get("name"));
        assertTrue(WordlistManager.getItemList(WordlistManager.KEY_PAYLOAD).contains(wordlistName));
    }
    @Test
    public void validatesMcpMutationArgumentsAgainstTheirSchemas() throws Exception {
        File workDir = temporaryFolder.newFolder("mcp-schema");
        Config.init(workDir.getAbsolutePath() + File.separator);
        BurpExtender extender = new BurpExtender();

        try {
            extender.callTool("ost.wordlist.append", Map.of(
                    "key", "payload", "items", List.of("ok", 1)));
            fail("wordlist append should reject non-string entries");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("only strings"));
        }
        try {
            extender.callTool("ost.history.delete", Map.of("labels", List.of("default", 1), "confirm", true));
            fail("history deletion should reject non-string labels");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("only strings"));
        }
        try {
            extender.callTool("ost.export.csv", Map.of(
                    "path", new File(workDir, "schema.csv").getAbsolutePath(), "fields", List.of("host", 1)));
            fail("CSV export should reject non-string fields");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("only strings"));
        }
        try {
            extender.callTool("ost.profiles.list", Map.of("include_sensitive", "true"));
            fail("profile listing should reject a string boolean");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("must be a boolean"));
        }
        try {
            extender.callTool("ost.scan.urls", Map.of(
                    "urls", List.of("https://example.test"), "profiles", List.of(1)));
            fail("scan Profiles should reject non-string entries");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("only string Profile names"));
        }
    }

    @Test
    public void exposesRiskAnnotationsForMcpClients() {
        BurpExtender extender = new BurpExtender();
        assertEquals(Boolean.TRUE, extender.listTools().stream()
                .filter(tool -> "ost.profile.delete".equals(tool.getName()))
                .findFirst().orElseThrow().getAnnotations().get("destructiveHint"));
        assertEquals(Boolean.TRUE, extender.listTools().stream()
                .filter(tool -> "ost.scan.request".equals(tool.getName()))
                .findFirst().orElseThrow().getAnnotations().get("openWorldHint"));
        assertEquals(Boolean.TRUE, extender.listTools().stream()
                .filter(tool -> "ost.wordlist.import_file".equals(tool.getName()))
                .findFirst().orElseThrow().getAnnotations().get("destructiveHint"));
        assertEquals(Boolean.TRUE, extender.listTools().stream()
                .filter(tool -> "ost.tasks.list".equals(tool.getName()))
                .findFirst().orElseThrow().getAnnotations().get("idempotentHint"));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object value) {
        return (Map<String, Object>) value;
    }
}
