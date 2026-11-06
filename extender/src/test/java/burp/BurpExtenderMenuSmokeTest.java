package burp;

import burp.vaycore.ost.common.Config;
import burp.vaycore.ost.common.L;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import java.io.File;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class BurpExtenderMenuSmokeTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void exposesOstSendMenuFromBurpContextFactory() throws Exception {
        File workDir = temporaryFolder.newFolder("ost-menu");
        Config.init(workDir.getAbsolutePath() + File.separator);

        List<JMenuItem> items = new BurpExtender().createMenuItems(null);

        assertNotNull(items);
        assertTrue("OST context menu should always be available", !items.isEmpty());
        assertTrue("first context item should be the OST submenu", items.get(0) instanceof JMenu);
        JMenu sendMenu = (JMenu) items.get(0);
        assertEquals(L.get("send_to_plugin"), sendMenu.getText());
        assertTrue(sendMenu.getItemCount() >= 2);
        assertEquals(L.get("send_to_plugin_burp"), sendMenu.getItem(0).getText());
        assertEquals(L.get("send_to_plugin_browser"), sendMenu.getItem(1).getText());
    }
}
