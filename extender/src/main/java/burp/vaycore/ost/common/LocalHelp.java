package burp.vaycore.ost.common;

import burp.vaycore.common.helper.UIHelper;

import java.awt.Component;
import java.awt.Desktop;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;

/** Opens the packaged, self-contained manual. No server, CDN or network download is needed. */
public final class LocalHelp {
    private LocalHelp() { }

    public static Path prepare() throws IOException {
        Path directory = Path.of(Config.getWorkDir(), "help");
        Files.createDirectories(directory);
        Path target = directory.resolve("ost-guide-" + Constants.PLUGIN_VERSION + ".html");
        try (InputStream source = LocalHelp.class.getResourceAsStream("/help/user-guide.html")) {
            if (source == null) throw new IOException("Packaged manual is missing");
            Path temp = Files.createTempFile(directory, "guide-", ".tmp");
            try {
                Files.copy(source, temp, StandardCopyOption.REPLACE_EXISTING);
                try {
                    Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
                }
            } finally {
                Files.deleteIfExists(temp);
            }
        }
        return target;
    }

    public static void open(Component parent) {
        try {
            Path path = prepare();
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                try {
                    String language = "zh".equals(L.getLocale().getLanguage()) ? "zh" : "en";
                    Desktop.getDesktop().browse(java.net.URI.create(path.toUri().toASCIIString() + "#" + language));
                    return;
                } catch (Exception ignored) {
                    // Keep the extracted path usable even on desktops without browser integration.
                }
            }
            UIHelper.showTipsDialog(L.get("help.open_manually", path.toAbsolutePath()), parent);
        } catch (Exception e) {
            UIHelper.showTipsDialog(L.get("help.open_failed", e.getMessage()), parent);
        }
    }
}
