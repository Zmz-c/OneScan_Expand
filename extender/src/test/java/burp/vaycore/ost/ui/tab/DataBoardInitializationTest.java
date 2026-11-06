package burp.vaycore.ost.ui.tab;

import burp.vaycore.ost.common.Config;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import javax.swing.SwingUtilities;
import java.io.File;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class DataBoardInitializationTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void initializesBothTaskTablesAlongsideParameterPanel() throws Exception {
        File workDir = temporaryFolder.newFolder("ost-board");
        Config.init(workDir.getAbsolutePath() + File.separator);
        AtomicReference<DataBoardTab> tabReference = new AtomicReference<DataBoardTab>();

        SwingUtilities.invokeAndWait(() -> {
            DataBoardTab tab = new DataBoardTab();
            tab.testInit();
            tabReference.set(tab);
        });

        DataBoardTab tab = tabReference.get();
        assertNotNull(tab);
        assertEquals(50, tab.getBurpTaskTable().getTaskDataList().size());
        assertEquals(50, tab.getBrowserTaskTable().getTaskDataList().size());
    }
}
