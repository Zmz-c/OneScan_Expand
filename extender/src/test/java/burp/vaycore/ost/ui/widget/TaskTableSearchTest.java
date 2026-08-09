package burp.vaycore.ost.ui.widget;

import burp.vaycore.ost.bean.TaskData;
import burp.vaycore.ost.common.Config;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.awt.*;
import java.io.File;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class TaskTableSearchTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Before
    public void initializeConfig() throws Exception {
        File workDir = temporaryFolder.newFolder("ost-search");
        Config.init(workDir.getAbsolutePath() + File.separator);
    }

    @Test
    public void searchesAllColumnsCaseInsensitivelyAndHighlightsMatches() {
        TaskTable table = new TaskTable();
        table.loadTaskData(List.of(
                task("api.example.test", "/admin/users"),
                task("public.example.test", "/health")));

        table.setSearchText("ADMIN");

        assertEquals(1, table.getRowCount());
        Color background = table.getCellRenderer(0, 3)
                .getTableCellRendererComponent(table, table.getValueAt(0, 3), false, false, 0, 3)
                .getBackground();
        assertEquals(new Color(255, 244, 180), background);

        table.setSearchText("");
        assertEquals(2, table.getRowCount());
    }

    private TaskData task(String host, String url) {
        TaskData data = new TaskData();
        data.setHost(host);
        data.setUrl(url);
        data.setMethod("GET");
        return data;
    }
}
