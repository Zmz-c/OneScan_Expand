package burp.vaycore.ost;

import burp.vaycore.ost.common.Config;
import burp.vaycore.ost.common.L;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;

public class OstParameterFuzzTabTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void exposesParameterScannerAsSeparateOstTab() throws Exception {
        File workDir = temporaryFolder.newFolder("ost-parameter-tab");
        Config.init(workDir.getAbsolutePath() + File.separator);

        Ost ost = new Ost();

        assertNotNull(ost.getParameterFuzzPanel());
        assertSame(ost.getParameterFuzzPanel(), ost.getDataBoardTab().getParameterFuzzPanel());
        assertEquals(ost.getParameterFuzzPanel(), ost.getComponentAt(1));
        assertEquals(L.get("parameter_fuzz.tab"), ost.getTitleAt(1));
    }
}
