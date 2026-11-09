package burp.vaycore.ost.ui.tab;

import burp.vaycore.ost.common.Config;
import burp.vaycore.ost.common.L;
import burp.vaycore.ost.manager.CollectManager;
import burp.vaycore.ost.ui.tab.config.HostTab;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class ScopeOnlyControlTest {
    @Rule public TemporaryFolder temp = new TemporaryFolder();

    @Test public void hostControlSavesScopeAndStatusShowsBlockedCount() throws Exception {
        Config.init(temp.newFolder().getAbsolutePath() + File.separator);
        try {
            SwingUtilities.invokeAndWait(() -> {
                HostTab host = new HostTab();
                List<JRadioButton> radios = new ArrayList<>();
                collect(host, radios);
                assertFalse(radios.get(0).isSelected());
                assertTrue(radios.get(1).isSelected());
                radios.get(0).doClick();
                assertTrue(Config.getBoolean(Config.KEY_SCOPE_ONLY));
                DataBoardTab board = new DataBoardTab();
                try {
                    board.init(new JTextArea(), new JTextArea());
                    board.refreshScopeStatus(7);
                    var field = DataBoardTab.class.getDeclaredField("mScopeStatus");
                    field.setAccessible(true);
                    JLabel status = (JLabel) field.get(board);
                    assertEquals(L.get("scope_status_on", 7), status.getText());
                    radios.get(1).doClick();
                    board.refreshScopeStatus(7);
                    assertEquals(L.get("scope_status_off"), status.getText());
                    assertFalse(Config.getBoolean(Config.KEY_SCOPE_ONLY));
                } catch (ReflectiveOperationException e) {
                    throw new AssertionError(e);
                } finally {
                    board.closeAutoSaveTimer();
                    board.closeDataSaveExecutor();
                    board.getParameterFuzzPanel().close();
                }
            });
        } finally {
            CollectManager.closeThreadPool();
        }
    }

    private static void collect(Container parent, List<JRadioButton> result) {
        for (Component child : parent.getComponents()) {
            if (child instanceof JRadioButton radio) result.add(radio);
            if (child instanceof Container container) collect(container, result);
        }
    }
}
