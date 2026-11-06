package burp.vaycore.ost.ui.tab;

import burp.IHttpRequestResponse;
import burp.vaycore.ost.bean.TaskData;
import burp.vaycore.ost.common.Config;
import burp.vaycore.ost.common.Constants;
import burp.vaycore.ost.common.RequestMode;
import burp.vaycore.ost.ui.widget.MessageEditorFixture;
import burp.vaycore.ost.ui.widget.TaskTable;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.Assert.*;

public class ParameterFuzzTrafficTest {
    @Rule public TemporaryFolder temp = new TemporaryFolder();
    @Before public void setup() throws Exception {
        Config.init(temp.newFolder().getAbsolutePath() + File.separator);
    }

    @Test public void routesBurpAndBrowserParameterTrafficExclusivelyAndPersistsAllTables() throws Exception {
        DataBoardTab[] board = new DataBoardTab[1];
        SwingUtilities.invokeAndWait(() -> {
            board[0] = new DataBoardTab();
            board[0].init(new JTextArea(), new JTextArea());
        });
        try {
            TaskData http = task(Constants.PARAMETER_FUZZ_SOURCE, "http-probe");
            TaskData browser = task(Constants.PARAMETER_FUZZ_SOURCE + " (Browser)", "browser-probe");
            board[0].addTaskData(task("Send", "regular"), RequestMode.BURP);
            board[0].addTaskData(task("Send (Browser)", "regular-browser"), RequestMode.BROWSER);
            board[0].addTaskData(http, RequestMode.BURP);
            board[0].addTaskData(browser, RequestMode.BROWSER);
            assertEquals(1, board[0].getBurpTaskTable().getTaskDataList().size());
            assertEquals(1, board[0].getBrowserTaskTable().getTaskDataList().size());
            assertEquals(List.of(http, browser), board[0].getParameterFuzzPanel().getTrafficTable().getTaskDataList());
            assertEquals("burp", http.getRequestScope());
            assertEquals("browser", browser.getRequestScope());
            Method snapshot = DataBoardTab.class.getDeclaredMethod("getPersistSnapshot", boolean.class);
            snapshot.setAccessible(true);
            Object value = snapshot.invoke(board[0], false);
            Method items = value.getClass().getDeclaredMethod("items");
            items.setAccessible(true);
            assertEquals(4, ((List<?>) items.invoke(value)).size());
        } finally {
            SwingUtilities.invokeAndWait(() -> board[0].getAllTaskTables().forEach(TaskTable::clearAll));
            board[0].closeDataSaveExecutor();
        }
    }

    @Test public void importsScopedAndLegacyParameterHistoryIntoItsOwnPanel() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            DataBoardTab board = new DataBoardTab();
            board.init(new JTextArea(), new JTextArea());
            try {
                Method restore = DataBoardTab.class.getDeclaredMethod("loadStoredTaskData", List.class, TaskTable.class);
                restore.setAccessible(true);
                TaskData regular = task("Send", "regular");
                TaskData legacy = task(Constants.PARAMETER_FUZZ_SOURCE, "legacy");
                restore.invoke(board, List.of(regular, legacy), board.getBurpTaskTable());
                assertEquals(List.of(regular), board.getBurpTaskTable().getTaskDataList());
                assertEquals(List.of(legacy), board.getParameterFuzzPanel().getTrafficTable().getTaskDataList());
                TaskData scoped = task(Constants.PARAMETER_FUZZ_SOURCE + " (Browser)", "scoped");
                scoped.setRequestScope("browser");
                restore.invoke(board, List.of(scoped), board.getBrowserTaskTable());
                assertEquals(0, board.getBrowserTaskTable().getTaskCount());
                assertEquals(List.of(scoped), board.getParameterFuzzPanel().getTrafficTable().getTaskDataList());
                assertEquals(List.of(regular), board.getBurpTaskTable().getTaskDataList());
            } catch (Exception e) {
                throw new RuntimeException(e);
            } finally {
                board.closeDataSaveExecutor();
            }
        });
    }

    @Test public void selectionRepeaterAndClearUseOnlyParameterTraffic() throws Exception {
        MessageEditorFixture fixture = new MessageEditorFixture();
        AtomicReference<List<TaskData>> sent = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ParameterFuzzPanel panel = new ParameterFuzzPanel();
            panel.initTrafficView(fixture.callbacks, Runnable::run, data -> (IHttpRequestResponse) data.getReqResp(),
                    new TaskTable.OnTaskTableEventListener() {
                        public void onChangeSelection(TaskData data) { fail("must not change main-board selection"); }
                        public void onSendToRepeater(ArrayList<TaskData> items) { sent.set(items); }
                        public byte[] getBodyByTaskData(TaskData data) { return new byte[0]; }
                        public void addHostToBlocklist(ArrayList<String> hosts) { }
                    });
            TaskData first = task(Constants.PARAMETER_FUZZ_SOURCE, "one");
            TaskData second = task(Constants.PARAMETER_FUZZ_SOURCE, "two");
            TaskTable table = panel.getTrafficTable();
            table.loadTaskData(List.of(first, second));
            table.changeSelection(1, 0, false, false);
            assertSame(second.getReqResp(), panel.currentMessage());
            assertArrayEquals(((IHttpRequestResponse) second.getReqResp()).getResponse(), fixture.editors.get(1).getMessage());
            JMenuItem item = new JMenuItem();
            item.setActionCommand("send-to-repeater");
            table.actionPerformed(new ActionEvent(item, 0, "send-to-repeater"));
            assertEquals(List.of(second), sent.get());
            table.clearAll();
            assertNull(panel.currentMessage());
            assertEquals(0, fixture.editors.get(0).getMessage().length);
            assertEquals(0, table.getTaskCount());
        });
    }

    @Test public void changingTargetsDoesNotReplaceRunningProgressOrDeleteTraffic() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            try {
                ParameterFuzzPanel panel = new ParameterFuzzPanel();
                TaskData existing = task(Constants.PARAMETER_FUZZ_SOURCE, "one");
                panel.getTrafficTable().loadTaskData(List.of(existing));
                panel.setScanRunning(true);
                panel.setScanProgress(3, 10, "running");
                panel.updateTargets(List.of(task("Send", "new-target")), false);
                assertEquals("running", ((JLabel) field(panel, "mStatus")).getText());
                assertEquals(3, ((JProgressBar) field(panel, "mProgressBar")).getValue());
                assertFalse(((JButton) field(panel, "mStart")).isEnabled());
                assertEquals(List.of(existing), panel.getTrafficTable().getTaskDataList());
                panel.setScanRunning(false);
                panel.setScanProgress(0, 0, "no probes");
                assertEquals(0, ((JProgressBar) field(panel, "mProgressBar")).getValue());
                assertTrue(((JButton) field(panel, "mStart")).isEnabled());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    private static Object field(Object instance, String name) throws Exception {
        Field field = instance.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(instance);
    }

    private static TaskData task(String from, String path) {
        TaskData task = new TaskData();
        task.setFrom(from);
        task.setMethod("GET");
        task.setHost("https://example.test");
        task.setUrl("/" + path);
        task.setReqResp(MessageEditorFixture.message("example.test", path));
        return task;
    }
}
