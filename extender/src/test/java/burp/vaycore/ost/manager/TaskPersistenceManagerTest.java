package burp.vaycore.ost.manager;

import burp.vaycore.common.log.Logger;
import burp.vaycore.ost.bean.TaskData;
import burp.vaycore.ost.common.Config;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class TaskPersistenceManagerTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void profileAndVariantAreAlwaysPersistedWithConfiguredFields() {
        List<String> fields = TaskPersistenceManager.normalizeFieldKeys(
                List.of(TaskPersistenceManager.FIELD_HOST));

        assertEquals(TaskPersistenceManager.FIELD_HOST, fields.get(0));
        assertTrue(fields.contains(TaskPersistenceManager.FIELD_PROFILE));
        assertTrue(fields.contains(TaskPersistenceManager.FIELD_VARIANT));
    }

    @Test
    public void profileVariantAndRawBytesSurviveDatabaseRoundTrip() throws Exception {
        File workDir = temporaryFolder.newFolder("persistence-work");
        Config.init(workDir.getAbsolutePath() + File.separator);
        Config.put(Config.KEY_DATA_PERSISTENCE_DB_PATH,
                new File(workDir, "history.sqlite").getAbsolutePath());

        TaskData source = new TaskData();
        source.setId(17);
        source.setHost("https://example.test");
        source.setProfile("auditor");
        source.setVariantId("variant-42");
        source.setRequestScope(TaskPersistenceManager.SCOPE_BROWSER);
        source.setReqBytes("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
                .getBytes(StandardCharsets.ISO_8859_1));
        source.setRespBytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
                .getBytes(StandardCharsets.ISO_8859_1));

        TaskPersistenceManager.persistSnapshot(
                List.of(source), List.of(TaskPersistenceManager.FIELD_HOST), "round-trip");
        List<TaskData> restored = TaskPersistenceManager.loadTaskDataByLabel("round-trip");

        assertEquals(1, restored.size());
        TaskData result = restored.get(0);
        assertEquals("auditor", result.getProfile());
        assertEquals("variant-42", result.getVariantId());
        assertEquals(TaskPersistenceManager.SCOPE_BROWSER, result.getRequestScope());
        assertArrayEquals(source.getReqBytes(), result.getReqBytes());
        assertArrayEquals(source.getRespBytes(), result.getRespBytes());
    }

    @Test
    public void reportsSnapshotFailureInsteadOfReturningASuccessCount() throws Exception {
        File workDir = temporaryFolder.newFolder("persistence-failure");
        Config.init(workDir.getAbsolutePath() + File.separator);
        File directoryAsDatabase = new File(workDir, "database-directory");
        assertTrue(directoryAsDatabase.mkdirs());
        Config.put(Config.KEY_DATA_PERSISTENCE_DB_PATH, directoryAsDatabase.getAbsolutePath());

        TaskData source = new TaskData();
        source.setHost("https://failure.test");

        ByteArrayOutputStream expectedErrorOutput = new ByteArrayOutputStream();
        Logger.init(false, System.out, expectedErrorOutput);
        IllegalStateException error;
        try {
            error = assertThrows(IllegalStateException.class,
                    () -> TaskPersistenceManager.persistSnapshot(
                            List.of(source), List.of(TaskPersistenceManager.FIELD_HOST), "failure"));
        } finally {
            Logger.init(false, System.out, System.err);
        }

        assertTrue(error.getMessage().contains("Persist task snapshot failed"));
        assertTrue(expectedErrorOutput.toString(StandardCharsets.UTF_8)
                .contains("Persist task snapshot failed"));
    }

    @Test
    public void deletingAHistoryLabelCascadesFieldRows() throws Exception {
        File workDir = temporaryFolder.newFolder("persistence-delete");
        Config.init(workDir.getAbsolutePath() + File.separator);
        Config.put(Config.KEY_DATA_PERSISTENCE_DB_PATH,
                new File(workDir, "history.sqlite").getAbsolutePath());

        TaskData source = new TaskData();
        source.setHost("https://deleted.test");
        TaskPersistenceManager.persistSnapshot(
                List.of(source), List.of(TaskPersistenceManager.FIELD_HOST), "delete-me");

        assertTrue(TaskPersistenceManager.listDistinctHosts().contains("https://deleted.test"));
        assertEquals(1, TaskPersistenceManager.deleteByLabels(List.of("delete-me")));
        assertFalse(TaskPersistenceManager.listDistinctHosts().contains("https://deleted.test"));
    }
}