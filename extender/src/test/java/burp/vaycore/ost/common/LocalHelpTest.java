package burp.vaycore.ost.common;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.Assert.*;

public class LocalHelpTest {
    @Rule public TemporaryFolder temp = new TemporaryFolder();

    @Test public void extractsTheBundledOfflineManualAtomicallyWithoutOpeningABrowser() throws Exception {
        Path dir = temp.newFolder("work with spaces").toPath();
        Config.init(dir + File.separator);
        Path page = LocalHelp.prepare();
        assertEquals(dir.resolve("help/ost-guide-" + Constants.PLUGIN_VERSION + ".html"), page);
        try (var source = LocalHelp.class.getResourceAsStream("/help/user-guide.html")) {
            assertNotNull(source);
            assertArrayEquals(source.readAllBytes(), Files.readAllBytes(page));
        }
        String content = Files.readString(page);
        assertTrue(content.contains("Reflection probe"));
        assertTrue(content.contains("$1$"));
        assertTrue(content.contains("containsRequestMatch"));
        assertTrue(content.contains("class=\"zh\""));
        assertTrue(content.contains("class=\"en\""));
        assertFalse(content.matches("(?is).*<(?:script|link)[^>]+(?:src|href)=[\"']https?://.*"));
        Files.writeString(page, "old manual");
        assertEquals(page, LocalHelp.prepare());
        assertEquals(content, Files.readString(page));
        try (var files = Files.list(page.getParent())) {
            assertEquals(1, files.count());
        }
    }
}
