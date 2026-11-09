package burp.vaycore.ost.common;

import burp.vaycore.common.filter.*;
import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.ost.manager.TaskPersistenceManager;
import burp.vaycore.ost.ui.widget.*;
import org.junit.*;
import org.junit.rules.TemporaryFolder;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.regex.*;

import static org.junit.Assert.*;

public class UiLanguageRegressionTest {
    @Rule public TemporaryFolder temporaryFolder = new TemporaryFolder();
    private final Locale originalLocale = Locale.getDefault();
    private static final Pattern HAN = Pattern.compile("[\\p{IsHan}]");

    @Before public void initialize() throws Exception {
        Config.init(temporaryFolder.newFolder("language").getAbsolutePath() + File.separator);
    }

    @After public void restore() {
        Locale.setDefault(originalLocale);
        L.configure(L.LANGUAGE_AUTO);
    }

    @Test public void translatedFieldsDoNotRetainClassInitializationLanguage() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            L.configure(L.LANGUAGE_CHINESE);
            assertTrue(HAN.matcher(TaskTable.getColumnNames().get(5)).find());
            assertTrue(HAN.matcher(FilterRule.getOperateItems()[1]).find());
            assertTrue(HAN.matcher(TaskPersistenceManager.getBaseFields().get(4).label()).find());
            FpColumnManagerWindow chinese = new FpColumnManagerWindow();
            JTable chineseTable = findTable(chinese);
            assertTrue(HAN.matcher(chineseTable.getColumnName(1)).find());

            L.configure(L.LANGUAGE_ENGLISH);
            assertEquals("Title", TaskTable.getColumnNames().get(5));
            assertEquals("Equal to", FilterRule.getOperateItems()[1]);
            assertEquals("Title", TaskPersistenceManager.getBaseFields().get(4).label());
            assertEquals("Title", new TaskTable().getColumnName(5));
            JTable englishTable = findTable(new FpColumnManagerWindow());
            assertFalse(HAN.matcher(englishTable.getColumnName(1)).find());
        });
    }

    @Test public void filterEditorHasEnglishLabelsAfterChineseInitialization() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            L.configure(L.LANGUAGE_CHINESE);
            new TableFilterPanel(TaskFilterFields.create(List::of), new ArrayList<>());
            L.configure(L.LANGUAGE_ENGLISH);
            TableFilterPanel panel = new TableFilterPanel(TaskFilterFields.create(List::of), new ArrayList<>());
            assertNoChineseText(panel);
            List<FilterField> fields = TaskFilterFields.create(List::of);
            assertEquals("Fingerprint", fields.get(fields.size() - 1).label());
            assertEquals("No profile", fields.get(10).choices().get().get(0).label());
        });
    }

    @Test public void swingChooserAndButtonsUseExtensionLanguageNotHostLanguage() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            Locale.setDefault(Locale.SIMPLIFIED_CHINESE);
            L.configure(L.LANGUAGE_ENGLISH);
            assertArrayEquals(new String[]{"OK", "Cancel"}, UIHelper.okCancelOptions());
            JFileChooser chooser = UIHelper.createFileChooser();
            assertEquals(Locale.ROOT, chooser.getLocale());
            assertEquals("All files", chooser.getFileFilter().getDescription());
            assertNoChineseText(chooser);
            assertEquals(Locale.SIMPLIFIED_CHINESE, Locale.getDefault());
            L.configure(L.LANGUAGE_CHINESE);
            assertTrue(HAN.matcher(UIHelper.okCancelOptions()[1]).find());
            assertEquals(Locale.SIMPLIFIED_CHINESE, UIHelper.createFileChooser().getLocale());
        });
    }

    @Test public void languageBundlesHaveMatchingKeysAndFormatArguments() throws Exception {
        Properties english = bundle("en_US");
        Properties chinese = bundle("zh_CN");
        assertEquals(english.stringPropertyNames(), chinese.stringPropertyNames());
        for (String key : english.stringPropertyNames()) {
            assertFalse("Chinese text in English resource: " + key, HAN.matcher(english.getProperty(key)).find());
            assertEquals("Format arguments differ: " + key, placeholders(english.getProperty(key)),
                    placeholders(chinese.getProperty(key)));
        }
    }

    @Test public void startupNoteUsesSelectedLanguageAndPreservesAuthorName() {
        L.configure(L.LANGUAGE_CHINESE);
        assertTrue(Constants.banner().contains("提示"));
        L.configure(L.LANGUAGE_ENGLISH);
        assertTrue(Constants.banner().contains("Note:"));
        assertFalse(Constants.banner().contains("提示"));
        assertTrue(Constants.banner().contains("人间小福星"));
    }

    @Test public void allLiteralTranslationKeysUsedByJavaExist() throws Exception {
        Properties english = bundle("en_US");
        Pattern keyPattern = Pattern.compile("L\\.get\\(\"([^\"]+)\"\\s*[,)]");
        java.nio.file.Path root = java.nio.file.Path.of("src/main/java");
        assertTrue(java.nio.file.Files.isDirectory(root));
        try (var paths = java.nio.file.Files.walk(root)) {
            for (var path : paths.filter(p -> p.toString().endsWith(".java")).toList()) {
                Matcher matcher = keyPattern.matcher(java.nio.file.Files.readString(path));
                while (matcher.find()) assertTrue(path + ": missing " + matcher.group(1), english.containsKey(matcher.group(1)));
            }
        }
    }

    private Properties bundle(String locale) throws Exception {
        Properties properties = new Properties();
        try (InputStream stream = getClass().getResourceAsStream("/i18n/messages_" + locale + ".properties")) {
            assertNotNull(stream);
            properties.load(new InputStreamReader(stream, StandardCharsets.UTF_8));
        }
        return properties;
    }

    private List<String> placeholders(String value) {
        Matcher matcher = Pattern.compile("%(?:\\d+\\$)?[-#+ 0,(]*\\d*(?:\\.\\d+)?[a-zA-Z%]").matcher(value);
        List<String> found = new ArrayList<>();
        while (matcher.find()) found.add(matcher.group());
        return found;
    }

    private static JTable findTable(Container root) {
        for (Component component : root.getComponents()) {
            if (component instanceof JTable table) return table;
            if (component instanceof Container container) {
                JTable table = findTable(container);
                if (table != null) return table;
            }
        }
        return null;
    }

    private static void assertNoChineseText(Component component) {
        if (component instanceof JLabel label) assertFalse(HAN.matcher(label.getText() == null ? "" : label.getText()).find());
        if (component instanceof AbstractButton button) assertFalse(HAN.matcher(button.getText() == null ? "" : button.getText()).find());
        if (component instanceof JComboBox<?> box) {
            for (int i = 0; i < box.getItemCount(); i++) {
                Object item = box.getItemAt(i);
                // File and directory names are user/OS data, not extension translations.
                if (item instanceof File) continue;
                assertFalse("Untranslated choice: " + item, HAN.matcher(item.toString()).find());
            }
        }
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) assertNoChineseText(child);
        }
    }
}
