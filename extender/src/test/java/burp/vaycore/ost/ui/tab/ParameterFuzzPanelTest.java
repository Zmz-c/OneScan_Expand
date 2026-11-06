package burp.vaycore.ost.ui.tab;

import burp.vaycore.ost.bean.TaskData;
import burp.vaycore.ost.common.Config;
import burp.vaycore.ost.manager.WordlistManager;
import burp.vaycore.ost.ui.tab.ParameterFuzzScanOptions.Mode;
import burp.vaycore.ost.common.RequestMode;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import javax.swing.JComboBox;
import javax.swing.JList;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertArrayEquals;

public class ParameterFuzzPanelTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void sendsParameterValuesFromSelectedPayloadDictionary() throws Exception {
        File workDir = temporaryFolder.newFolder("parameter-fuzz-dictionaries");
        Config.init(workDir.getAbsolutePath() + File.separator);
        AtomicReference<ParameterFuzzPanel> panelReference = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> panelReference.set(new ParameterFuzzPanel()));

        WordlistManager.putList(WordlistManager.KEY_PAYLOAD, "parameter-names", List.of("debug", "role"));
        WordlistManager.putList(WordlistManager.KEY_PAYLOAD, "parameter-values", List.of("0", "admin"));

        AtomicReference<ParameterFuzzScanOptions> optionsReference = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try {
                ParameterFuzzPanel panel = panelReference.get();
                Method refreshDictionaries = ParameterFuzzPanel.class.getDeclaredMethod("populateDictionaries");
                refreshDictionaries.setAccessible(true);
                refreshDictionaries.invoke(panel);
                TaskData target = new TaskData();
                target.setMethod("GET");
                target.setStatus(200);
                target.setHost("https://example.test");
                target.setUrl("/api/items");
                panel.updateTargets(List.of(target), false);
                combo(panel, "mNameDictionary").setSelectedItem("parameter-names");
                combo(panel, "mValueDictionary").setSelectedItem("parameter-values");
                Method buildOptions = ParameterFuzzPanel.class.getDeclaredMethod("buildScanOptions");
                buildOptions.setAccessible(true);
                optionsReference.set((ParameterFuzzScanOptions) buildOptions.invoke(panel));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        ParameterFuzzScanOptions options = optionsReference.get();
        assertNotNull(options);
        assertEquals(List.of("debug", "role"), options.scans().get(0).parameterNameCandidates());
        assertEquals(List.of("0", "admin"), options.scans().get(0).parameterValues());
        assertEquals(0, options.scans().get(0).requestTemplate().length);
        assertFalse(options.scans().get(0).customPositions());
    }

    @Test
    public void editsPerTargetPositionsWithoutRequiringANameDictionary() throws Exception {
        Config.init(temporaryFolder.newFolder("positions").getAbsolutePath() + File.separator);
        WordlistManager.putList(WordlistManager.KEY_PAYLOAD, "values", List.of("one", "two"));
        SwingUtilities.invokeAndWait(() -> {
            try {
                ParameterFuzzPanel panel = new ParameterFuzzPanel();
                String first = "GET /first?id=original&keep=yes HTTP/1.1\r\nHost: first.test\r\n\r\n";
                String second = "POST /second HTTP/1.1\r\nHost: second.test\r\n\r\n{\n\"items\": [1, 2]\n}";
                panel.updateTargets(List.of(target("GET", "/first", first), target("POST", "/second", second)), true);
                combo(panel, "mMode").setSelectedIndex(2);
                combo(panel, "mValueDictionary").setSelectedItem("values");
                invoke(panel, "applySettingsToAllTargets");
                assertFalse(combo(panel, "mNameDictionary").isEnabled());
                JTextArea editor = (JTextArea) field(panel, "mRequestTemplate");
                assertEquals(first, editor.getText());
                int pos = editor.getText().indexOf("original");
                editor.select(pos, pos + "original".length());
                invoke(panel, "markPosition");
                String markedFirst = first.replace("original", "$1$");
                assertEquals(markedFirst, editor.getText());

                JList<?> list = (JList<?>) field(panel, "mTargetList");
                list.setSelectedIndex(1);
                assertEquals(second, editor.getText());
                editor.setText(second.replace("[1, 2]", "[1, $1$]"));
                list.setSelectedIndex(0);
                assertEquals(markedFirst, editor.getText());
                ParameterFuzzScanOptions options = (ParameterFuzzScanOptions) invoke(panel, "buildScanOptions");
                assertNotNull(options);
                assertTrue(options.scans().get(0).customPositions());
                assertTrue(options.scans().get(0).parameterValues().isEmpty());
                assertEquals(List.of("one", "two"), options.scans().get(0).positionValues().get("1"));
                assertTrue(options.scans().get(0).parameterNameCandidates().isEmpty());
                assertEquals(markedFirst, new String(options.scans().get(0).requestTemplate(), StandardCharsets.UTF_8));
                assertEquals(second.replace("[1, 2]", "[1, $1$]"),
                        new String(options.scans().get(1).requestTemplate(), StandardCharsets.UTF_8));
                assertFalse(options.scans().get(0).browserId().isEmpty());
                editor.setText("changed after submission");
                assertEquals(markedFirst, new String(options.scans().get(0).requestTemplate(), StandardCharsets.UTF_8));
                assertArrayEquals(first.getBytes(StandardCharsets.UTF_8), options.scans().get(0).target().getReqBytes());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Test
    public void customModeRejectsNoPositionsAndOldValueTemplates() throws Exception {
        Config.init(temporaryFolder.newFolder("invalid-positions").getAbsolutePath() + File.separator);
        WordlistManager.putList(WordlistManager.KEY_PAYLOAD, "values", List.of("one"));
        SwingUtilities.invokeAndWait(() -> {
            try {
                ParameterFuzzPanel panel = new ParameterFuzzPanel();
                panel.updateTargets(List.of(target("GET", "/", "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")), false);
                combo(panel, "mMode").setSelectedIndex(2);
                combo(panel, "mValueDictionary").setSelectedItem("values");
                assertNull(invoke(panel, "buildScanOptions"));
                ((JTextArea) field(panel, "mRequestTemplate")).setText("[$1$]");
                assertNull(invoke(panel, "buildScanOptions"));
                // Automatic modes use the dictionaries directly and do not require markers.
                combo(panel, "mMode").setSelectedIndex(1);
                assertNotNull(invoke(panel, "buildScanOptions"));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Test
    public void previewCountsOnlyMarkedEligibleTargetsAndKeepsDictionarySelection() throws Exception {
        Config.init(temporaryFolder.newFolder("preview-positions").getAbsolutePath() + File.separator);
        WordlistManager.putList(WordlistManager.KEY_PAYLOAD, "values", List.of("one", "two"));
        SwingUtilities.invokeAndWait(() -> {
            try {
                ParameterFuzzPanel panel = new ParameterFuzzPanel();
                combo(panel, "mValueDictionary").setSelectedItem("values");
                String marked = "GET /?id=$1$&other=$1$ HTTP/1.1\r\nHost: example.test\r\n\r\n";
                TaskData missing = target("GET", "/missing", marked);
                missing.setStatus(404);
                panel.updateTargets(List.of(target("GET", "/marked", marked), missing,
                        target("GET", "/plain", marked.replace("$1$", "keep"))), false);
                combo(panel, "mMode").setSelectedIndex(2);
                combo(panel, "mValueDictionary").setSelectedItem("values");
                invoke(panel, "applySettingsToAllTargets");
                WordlistManager.putList(WordlistManager.KEY_PAYLOAD, "added-later", List.of("new"));
                invoke(panel, "previewPlan");
                assertEquals("values", combo(panel, "mValueDictionary").getSelectedItem());
                assertTrue(combo(panel, "mValueDictionary").getItemCount() >= 2);
                javax.swing.table.DefaultTableModel model = (javax.swing.table.DefaultTableModel) field(panel, "mResultModel");
                assertEquals(3, model.getRowCount());
                assertEquals(2L, model.getValueAt(0, 3));
                assertEquals(0L, model.getValueAt(1, 3));
                assertEquals(0L, model.getValueAt(2, 3));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Test public void appendsUrlsAndPreservesDraftsMappingsAndBrowserIdOnDuplicateImports() throws Exception {
        Config.init(temporaryFolder.newFolder().getAbsolutePath() + File.separator);
        WordlistManager.putList(WordlistManager.KEY_PAYLOAD, "names", List.of("a", "b"));
        WordlistManager.putList(WordlistManager.KEY_PAYLOAD, "values", List.of("one", "two"));
        onEdt(() -> {
            ParameterFuzzPanel panel = new ParameterFuzzPanel();
            String first = "GET /first?name=value HTTP/1.1\r\nHost: example.test\r\n\r\n";
            TaskData firstTarget = target("GET", "/first", first);
            panel.updateTargets(List.of(firstTarget), true);
            combo(panel, "mMode").setSelectedIndex(2);
            JTextArea editor = (JTextArea) field(panel, "mRequestTemplate");
            markText(panel, editor, "name");
            markText(panel, editor, "value");
            javax.swing.JTable positions = (javax.swing.JTable) field(panel, "mPositionTable");
            positions.setValueAt("names", 0, 1);
            positions.setValueAt("values", 1, 1);
            String draft = editor.getText();
            String browserId = (String) field(panel, "mScanBrowserId");
            String second = "POST /second HTTP/1.1\r\nHost: other.test\r\n\r\n{\"name\":\"value\"}";
            TaskData secondTarget = target("POST", "/second", second);
            secondTarget.setHost("https://other.test");
            panel.updateTargets(List.of(secondTarget), false);
            panel.updateTargets(List.of(target("GET", "/first", "replacement must not overwrite")), true);
            assertEquals(draft, editor.getText());
            JList<?> list = (JList<?>) field(panel, "mTargetList");
            assertEquals(2, list.getModel().getSize());
            assertEquals(browserId, field(panel, "mScanBrowserId"));
            list.setSelectedIndex(1);
            assertEquals(second, editor.getText());
            markText(panel, editor, "name");
            markText(panel, editor, "value");
            positions.setValueAt("values", 0, 1);
            positions.setValueAt("names", 1, 1);
            list.setSelectedIndex(0);
            assertEquals(draft, editor.getText());
            assertEquals("names", positions.getValueAt(0, 1));
            assertEquals("values", positions.getValueAt(1, 1));
            var options = (ParameterFuzzScanOptions) invoke(panel, "buildScanOptions");
            assertEquals(List.of("a", "b"), options.scans().get(0).positionValues().get("1"));
            assertEquals(List.of("one", "two"), options.scans().get(1).positionValues().get("1"));
            invoke(panel, "previewPlan");
            var results = (javax.swing.table.DefaultTableModel) field(panel, "mResultModel");
            assertEquals(4L, results.getValueAt(0, 3));
            assertEquals(4L, results.getValueAt(1, 3));
            panel.close();
        });
    }

    @Test public void browserSourceIsNotDiscardedWhenSameUrlAlreadyExists() throws Exception {
        Config.init(temporaryFolder.newFolder().getAbsolutePath() + File.separator);
        WordlistManager.putList(WordlistManager.KEY_PAYLOAD, "values", List.of("one"));
        onEdt(() -> {
            ParameterFuzzPanel panel = new ParameterFuzzPanel();
            String raw = "GET /?id=old HTTP/1.1\r\nHost: example.test\r\n\r\n";
            TaskData http = target("GET", "/", raw);
            TaskData browser = target("GET", "/", raw);
            panel.updateTargets(List.of(http), false);
            panel.updateTargets(List.of(browser), true);
            JList<?> list = (JList<?>) field(panel, "mTargetList");
            assertEquals(2, list.getModel().getSize());
            assertEquals(1, list.getSelectedIndex());
            assertTrue(((javax.swing.JCheckBox) field(panel, "mUseBrowser")).isSelected());
            combo(panel, "mMode").setSelectedIndex(2);
            combo(panel, "mValueDictionary").setSelectedItem("values");
            JTextArea editor = (JTextArea) field(panel, "mRequestTemplate");
            markText(panel, editor, "old");
            var options = (ParameterFuzzScanOptions) invoke(panel, "buildScanOptions");
            assertNotNull(options);
            assertEquals(RequestMode.BROWSER, options.scans().get(1).requestMode());
            assertFalse(options.scans().get(1).browserId().isEmpty());
            assertEquals(List.of("one"), options.scans().get(1).positionValues().get("1"));
            panel.updateTargets(List.of(browser), true);
            assertEquals(2, list.getModel().getSize());
            invoke(panel, "removeTarget");
            panel.updateTargets(List.of(browser), true);
            assertEquals(2, list.getModel().getSize());
            panel.close();
        });
    }

    @Test public void mixedSourceImportsKeepIdentityWhenTransportSettingChanges() throws Exception {
        Config.init(temporaryFolder.newFolder().getAbsolutePath() + File.separator);
        onEdt(() -> {
            ParameterFuzzPanel panel = new ParameterFuzzPanel();
            String raw = "GET /?id=old HTTP/1.1\r\nHost: example.test\r\n\r\n";
            TaskData http = target("GET", "/", raw);
            TaskData browser = target("GET", "/", raw); browser.setRequestScope("browser");
            panel.updateTargets(List.of(http, browser), false);
            JList<?> targets = (JList<?>) field(panel, "mTargetList");
            assertEquals(2, targets.getModel().getSize());
            targets.setSelectedIndex(1);
            javax.swing.JCheckBox useBrowser = (javax.swing.JCheckBox) field(panel, "mUseBrowser");
            assertTrue(useBrowser.isSelected());
            useBrowser.doClick();
            panel.updateTargets(List.of(browser), false);
            assertEquals(2, targets.getModel().getSize());
            assertFalse(useBrowser.isSelected());
            invoke(panel, "clearTargets");
            panel.updateTargets(List.of(browser), false);
            assertEquals(1, targets.getModel().getSize());
            assertTrue(useBrowser.isSelected());
            panel.close();
        });
    }

    @Test public void markerInsertionKeepsCaretAfterMarkerAcrossDocumentEvents() throws Exception {
        Config.init(temporaryFolder.newFolder().getAbsolutePath() + File.separator);
        ParameterFuzzPanel[] panels = new ParameterFuzzPanel[1];
        onEdt(() -> {
            ParameterFuzzPanel panel = panels[0] = new ParameterFuzzPanel();
            String raw = "GET /?id=old HTTP/1.1\r\nHost: example.test\r\n\r\n";
            panel.updateTargets(List.of(target("GET", "/", raw)), false);
            JTextArea editor = (JTextArea) field(panel, "mRequestTemplate");
            markText(panel, editor, "old");
            int end = editor.getText().indexOf("$1$") + 3;
            assertEquals(end, editor.getSelectionStart());
            assertEquals(end, editor.getSelectionEnd());
        });
        onEdt(() -> {
            JTextArea editor = (JTextArea) field(panels[0], "mRequestTemplate");
            editor.replaceSelection(" ");
        });
        onEdt(() -> {
            JTextArea editor = (JTextArea) field(panels[0], "mRequestTemplate");
            editor.replaceSelection("x");
            assertTrue(editor.getText().contains("id=$1$ x HTTP"));
            assertEquals(editor.getText().indexOf("$1$ x") + 5, editor.getCaretPosition());
            // A second marker at an empty caret and a dictionary refresh must not steal it.
            invoke(panels[0], "markPosition");
            assertEquals(editor.getText().indexOf("$2$") + 3, editor.getCaretPosition());
        });
        onEdt(() -> {
            JTextArea editor = (JTextArea) field(panels[0], "mRequestTemplate");
            WordlistManager.putList(WordlistManager.KEY_PAYLOAD, "new-dict", List.of("a"));
            invoke(panels[0], "populateDictionaries");
            editor.replaceSelection("&next=");
            assertTrue(editor.getText().contains("id=$1$ x$2$&next= HTTP"));
            assertEquals(editor.getText().indexOf("&next=") + 6, editor.getCaretPosition());
            assertEquals(editor.getSelectionStart(), editor.getSelectionEnd());
            panels[0].close();
        });
    }

    @Test public void deletingMarkersRestoresOriginalNamesAndValuesWithoutTouchingOtherIds() throws Exception {
        Config.init(temporaryFolder.newFolder().getAbsolutePath() + File.separator);
        onEdt(() -> {
            ParameterFuzzPanel panel = new ParameterFuzzPanel();
            String raw = "GET /?name=value&other=keep HTTP/1.1\r\nHost: example.test\r\n\r\n";
            panel.updateTargets(List.of(target("GET", "/", raw)), false);
            JTextArea editor = (JTextArea) field(panel, "mRequestTemplate");
            markText(panel, editor, "name");
            markText(panel, editor, "value");
            assertTrue(editor.getText().contains("$1$=$2$"));
            javax.swing.JTable positions = (javax.swing.JTable) field(panel, "mPositionTable");
            positions.setRowSelectionInterval(0, 0);
            invoke(panel, "removePosition");
            assertEquals(raw.replace("value", "$2$"), editor.getText());
            invoke(panel, "clearPositions");
            assertEquals(raw, editor.getText());
            assertEquals(0, positions.getRowCount());
            markText(panel, editor, "name");
            markText(panel, editor, "value");
            int selectionStart = editor.getText().indexOf("$1$");
            editor.select(selectionStart, selectionStart + "$1$=$2$".length());
            invoke(panel, "removePosition");
            assertEquals(raw, editor.getText());
            // Reuse a removed number with a fresh original; caret removal also works.
            markText(panel, editor, "other");
            invoke(panel, "removePosition");
            assertEquals(raw, editor.getText());
            editor.setText(raw.replace("keep", "$10$"));
            invoke(panel, "syncPositionRows");
            assertEquals("$10$", positions.getValueAt(0, 0));
            invoke(panel, "clearPositions");
            assertEquals(raw.replace("keep", ""), editor.getText());
            panel.close();
        });
    }

    @Test public void editedDictionaryIsCommittedOnSwitchAndNewDictionariesRefreshPositionChoices() throws Exception {
        Config.init(temporaryFolder.newFolder().getAbsolutePath() + File.separator);
        WordlistManager.putList(WordlistManager.KEY_PAYLOAD, "values", List.of("one"));
        onEdt(() -> {
            ParameterFuzzPanel panel = new ParameterFuzzPanel();
            String raw = "GET /?id=$1$ HTTP/1.1\r\nHost: example.test\r\n\r\n";
            panel.updateTargets(List.of(target("GET", "/first", raw), target("GET", "/second", raw)), false);
            combo(panel, "mMode").setSelectedIndex(2);
            invoke(panel, "applySettingsToAllTargets");
            javax.swing.JTable positions = (javax.swing.JTable) field(panel, "mPositionTable");
            WordlistManager.putList(WordlistManager.KEY_PAYLOAD, "later", List.of("late"));
            invoke(panel, "populateDictionaries");
            assertTrue(positions.editCellAt(0, 1));
            JComboBox<?> picker = (JComboBox<?>) positions.getEditorComponent();
            assertTrue(java.util.stream.IntStream.range(0, picker.getItemCount())
                    .anyMatch(i -> "later".equals(picker.getItemAt(i))));
            picker.setSelectedItem("later");
            JList<?> list = (JList<?>) field(panel, "mTargetList");
            list.setSelectedIndex(1);
            positions.setValueAt("values", 0, 1);
            list.setSelectedIndex(0);
            assertEquals("later", positions.getValueAt(0, 1));
            invoke(panel, "populateDictionaries");
            assertEquals("later", positions.getValueAt(0, 1));
            var options = (ParameterFuzzScanOptions) invoke(panel, "buildScanOptions");
            assertEquals(List.of("late"), options.scans().get(0).positionValues().get("1"));
            positions.setValueAt("removed-dictionary", 0, 1);
            assertNull(invoke(panel, "buildScanOptions"));
            panel.close();
        });
    }

    @Test public void targetRemovalDuringScanDoesNotChangeSnapshotProgressOrTraffic() throws Exception {
        Config.init(temporaryFolder.newFolder().getAbsolutePath() + File.separator);
        WordlistManager.putList(WordlistManager.KEY_PAYLOAD, "values", List.of("one"));
        onEdt(() -> {
            ParameterFuzzPanel panel = new ParameterFuzzPanel();
            combo(panel, "mValueDictionary").setSelectedItem("values");
            combo(panel, "mMode").setSelectedIndex(2);
            String raw = "GET /?id=$1$ HTTP/1.1\r\nHost: example.test\r\n\r\n";
            panel.updateTargets(List.of(target("GET", "/first", raw), target("GET", "/second", raw)), false);
            var options = (ParameterFuzzScanOptions) invoke(panel, "buildScanOptions");
            panel.setScanRunning(true);
            panel.setScanProgress(2, 8, "running");
            panel.getTrafficTable().loadTaskData(List.of(target("GET", "/traffic", raw)));
            invoke(panel, "removeTarget");
            JList<?> list = (JList<?>) field(panel, "mTargetList");
            assertEquals(1, list.getModel().getSize());
            assertTrue(list.getSelectedValue().toString().endsWith("/second"));
            assertEquals(raw, ((JTextArea) field(panel, "mRequestTemplate")).getText());
            invoke(panel, "clearTargets");
            assertEquals(0, list.getModel().getSize());
            assertEquals("", ((JTextArea) field(panel, "mRequestTemplate")).getText());
            panel.updateTargets(List.of(target("GET", "/third", raw)), false);
            assertEquals(1, list.getModel().getSize());
            assertEquals(2, options.scans().size());
            assertEquals("/first", options.scans().get(0).target().getUrl());
            assertEquals(raw, new String(options.scans().get(0).requestTemplate(), StandardCharsets.UTF_8));
            assertEquals("running", ((javax.swing.JLabel) field(panel, "mStatus")).getText());
            assertEquals(2, ((javax.swing.JProgressBar) field(panel, "mProgressBar")).getValue());
            assertEquals(1, panel.getTrafficTable().getTaskCount());
            panel.close();
        });
    }

    @Test public void manuallyTypedMarkersRefreshOnDocumentEvents() throws Exception {
        Config.init(temporaryFolder.newFolder().getAbsolutePath() + File.separator);
        ParameterFuzzPanel[] panels = new ParameterFuzzPanel[1];
        onEdt(() -> {
            ParameterFuzzPanel panel = panels[0] = new ParameterFuzzPanel();
            String raw = "GET /?id=old HTTP/1.1\r\nHost: example.test\r\n\r\n";
            panel.updateTargets(List.of(target("GET", "/", raw)), false);
            ((JTextArea) field(panel, "mRequestTemplate")).setText(raw.replace("id=old", "$1$=$2$&$10$=$2$"));
        });
        onEdt(() -> {
            javax.swing.JTable positions = (javax.swing.JTable) field(panels[0], "mPositionTable");
            assertEquals(3, positions.getRowCount());
            assertEquals("$1$", positions.getValueAt(0, 0));
            assertEquals("$10$", positions.getValueAt(2, 0));
            panels[0].close();
        });
    }

    @Test public void mixedModesKeepIndependentControlsAndSubmitEveryEndpointRegardlessOfSelection() throws Exception {
        Config.init(temporaryFolder.newFolder().getAbsolutePath() + File.separator);
        WordlistManager.putList(WordlistManager.KEY_PAYLOAD, "names-a", List.of("debug"));
        WordlistManager.putList(WordlistManager.KEY_PAYLOAD, "values-a", List.of("a1", "a2"));
        WordlistManager.putList(WordlistManager.KEY_PAYLOAD, "values-b", List.of("b1"));
        onEdt(() -> {
            ParameterFuzzPanel panel = new ParameterFuzzPanel();
            String get = "GET /names HTTP/1.1\r\nHost: example.test\r\n\r\n";
            String post = "POST /values HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{\"id\":\"old\"}";
            String custom = "GET /positions?id=$1$ HTTP/1.1\r\nHost: example.test\r\n\r\n";
            panel.updateTargets(List.of(target("GET", "/names", get), target("POST", "/values", post),
                    target("GET", "/positions", custom)), false);
            JList<?> list = (JList<?>) field(panel, "mTargetList");
            JTextArea editor = (JTextArea) field(panel, "mRequestTemplate");
            javax.swing.JCheckBox scanGet = (javax.swing.JCheckBox) field(panel, "mGetMethod");
            javax.swing.JCheckBox scanPost = (javax.swing.JCheckBox) field(panel, "mPostMethod");
            javax.swing.JCheckBox browser = (javax.swing.JCheckBox) field(panel, "mUseBrowser");
            combo(panel, "mMode").setSelectedIndex(0);
            combo(panel, "mNameDictionary").setSelectedItem("names-a");
            combo(panel, "mValueDictionary").setSelectedItem("values-a");
            scanPost.setSelected(false);
            list.setSelectedIndex(1);
            combo(panel, "mMode").setSelectedIndex(1);
            combo(panel, "mNameDictionary").getModel().setSelectedItem("unused-removed-name-dictionary");
            combo(panel, "mValueDictionary").setSelectedItem("values-b");
            scanGet.setSelected(false); scanPost.setSelected(true); browser.setSelected(true);
            // A stale custom draft must not invalidate an automatic scan.
            editor.setText("obsolete $1$ template");
            list.setSelectedIndex(2);
            combo(panel, "mMode").setSelectedIndex(2);
            ((javax.swing.JTable) field(panel, "mPositionTable")).setValueAt("values-b", 0, 1);
            combo(panel, "mValueDictionary").getModel().setSelectedItem("unused-removed-value-dictionary");
            AtomicReference<ParameterFuzzScanOptions> submitted = new AtomicReference<>();
            panel.setScanHandler(submitted::set);
            for (int selected : new int[]{2, 0, 1, 2}) {
                list.setSelectedIndex(selected);
                invoke(panel, "startScan");
                var scans = submitted.get().scans();
                assertEquals(List.of(Mode.NAMES, Mode.VALUES, Mode.POSITIONS), scans.stream().map(o -> o.mode()).toList());
                assertEquals(List.of("debug"), scans.get(0).parameterNameCandidates());
                assertEquals(List.of("a1", "a2"), scans.get(0).parameterValues());
                assertEquals(List.of("b1"), scans.get(1).parameterValues());
                assertEquals(0, scans.get(1).requestTemplate().length);
                assertEquals(List.of("b1"), scans.get(2).positionValues().get("1"));
                assertTrue(scans.get(2).parameterValues().isEmpty());
                assertTrue(scans.get(0).scanGet()); assertFalse(scans.get(0).scanPost());
                assertFalse(scans.get(1).scanGet()); assertTrue(scans.get(1).scanPost());
                assertEquals(RequestMode.BROWSER, scans.get(1).requestMode());
                assertFalse(scans.get(1).browserId().isEmpty());
                assertEquals(RequestMode.BURP, scans.get(0).requestMode());
                assertEquals("", scans.get(0).browserId());
            }
            list.setSelectedIndex(0);
            assertEquals(0, combo(panel, "mMode").getSelectedIndex());
            assertEquals("names-a", combo(panel, "mNameDictionary").getSelectedItem());
            assertEquals("values-a", combo(panel, "mValueDictionary").getSelectedItem());
            assertFalse(browser.isSelected());
            list.setSelectedIndex(1);
            assertEquals(1, combo(panel, "mMode").getSelectedIndex());
            assertTrue(browser.isSelected());
            assertEquals("obsolete $1$ template", editor.getText());
            invoke(panel, "previewPlan");
            var results = (javax.swing.table.DefaultTableModel) field(panel, "mResultModel");
            assertEquals(3, results.getRowCount());
            assertEquals(2L, results.getValueAt(0, 3));
            assertEquals(1L, results.getValueAt(2, 3));
            assertFalse(results.getValueAt(0, 1).equals(results.getValueAt(1, 1)));
            assertFalse(results.getValueAt(1, 1).equals(results.getValueAt(2, 1)));
            // UI changes affect the next run, not the submitted batch.
            var previous = submitted.get();
            combo(panel, "mMode").setSelectedIndex(0);
            invoke(panel, "clearTargets");
            assertEquals(Mode.VALUES, previous.scans().get(1).mode());
            assertEquals(3, previous.scans().size());
            panel.close();
        });
    }

    @Test public void unmarkedCustomTargetDoesNotSuppressAutomaticTasksInTheSameBatch() throws Exception {
        Config.init(temporaryFolder.newFolder().getAbsolutePath() + File.separator);
        WordlistManager.putList(WordlistManager.KEY_PAYLOAD, "values", List.of("value"));
        onEdt(() -> {
            ParameterFuzzPanel panel = new ParameterFuzzPanel();
            String raw = "GET /?id=old HTTP/1.1\r\nHost: example.test\r\n\r\n";
            panel.updateTargets(List.of(target("GET", "/auto", raw), target("GET", "/custom", raw)), false);
            combo(panel, "mMode").setSelectedIndex(1);
            combo(panel, "mValueDictionary").setSelectedItem("values");
            ((JList<?>) field(panel, "mTargetList")).setSelectedIndex(1);
            combo(panel, "mMode").setSelectedIndex(2);
            var batch = (ParameterFuzzScanOptions) invoke(panel, "buildScanOptions");
            assertNotNull(batch);
            assertEquals(Mode.VALUES, batch.scans().get(0).mode());
            assertEquals(Mode.POSITIONS, batch.scans().get(1).mode());
            invoke(panel, "previewPlan");
            var results = (javax.swing.table.DefaultTableModel) field(panel, "mResultModel");
            assertEquals(0L, results.getValueAt(1, 3));
            panel.close();
        });
    }

    @Test public void applyAllCopiesSettingsButKeepsRequestAndPositionDictionariesLocal() throws Exception {
        Config.init(temporaryFolder.newFolder().getAbsolutePath() + File.separator);
        WordlistManager.putList(WordlistManager.KEY_PAYLOAD, "first", List.of("a"));
        WordlistManager.putList(WordlistManager.KEY_PAYLOAD, "second", List.of("b"));
        onEdt(() -> {
            ParameterFuzzPanel panel = new ParameterFuzzPanel();
            String raw = "GET /?id=$1$ HTTP/1.1\r\nHost: example.test\r\n\r\n";
            panel.updateTargets(List.of(target("GET", "/first", raw), target("GET", "/second", raw)), false);
            JList<?> targets = (JList<?>) field(panel, "mTargetList");
            javax.swing.JTable positions = (javax.swing.JTable) field(panel, "mPositionTable");
            combo(panel, "mMode").setSelectedIndex(2);
            positions.setValueAt("first", 0, 1);
            targets.setSelectedIndex(1);
            positions.setValueAt("second", 0, 1);
            JTextArea editor = (JTextArea) field(panel, "mRequestTemplate");
            String edited = raw.replace("/?", "/edited?");
            editor.setText(edited);
            targets.setSelectedIndex(0);
            invoke(panel, "applySettingsToAllTargets");
            var batch = (ParameterFuzzScanOptions) invoke(panel, "buildScanOptions");
            assertTrue(batch.scans().stream().allMatch(o -> o.customPositions()));
            assertEquals(List.of("a"), batch.scans().get(0).positionValues().get("1"));
            assertEquals(List.of("b"), batch.scans().get(1).positionValues().get("1"));
            assertEquals(edited, new String(batch.scans().get(1).requestTemplate(), StandardCharsets.UTF_8));
            panel.close();
        });
    }

    @Test public void dictionaryRefreshDoesNotOverwriteOtherTargetsOrSilentlyReplaceMissingSelections() throws Exception {
        Config.init(temporaryFolder.newFolder().getAbsolutePath() + File.separator);
        WordlistManager.putList(WordlistManager.KEY_PAYLOAD, "values", List.of("value"));
        onEdt(() -> {
            ParameterFuzzPanel panel = new ParameterFuzzPanel();
            String raw = "GET /?id=old HTTP/1.1\r\nHost: example.test\r\n\r\n";
            panel.updateTargets(List.of(target("GET", "/first", raw), target("GET", "/second", raw)), false);
            combo(panel, "mMode").setSelectedIndex(1);
            combo(panel, "mValueDictionary").getModel().setSelectedItem("removed");
            ((JList<?>) field(panel, "mTargetList")).setSelectedIndex(1);
            combo(panel, "mMode").setSelectedIndex(1);
            combo(panel, "mValueDictionary").setSelectedItem("values");
            WordlistManager.putList(WordlistManager.KEY_PAYLOAD, "new", List.of("new-value"));
            invoke(panel, "populateDictionaries");
            ((JList<?>) field(panel, "mTargetList")).setSelectedIndex(0);
            assertEquals("removed", combo(panel, "mValueDictionary").getSelectedItem());
            assertNull(invoke(panel, "buildScanOptions"));
            ((JList<?>) field(panel, "mTargetList")).setSelectedIndex(1);
            assertEquals("values", combo(panel, "mValueDictionary").getSelectedItem());
            panel.close();
        });
    }

    @Test public void importsPreserveTransportPerEndpointAndRemovalKeepsRemainingModeAligned() throws Exception {
        Config.init(temporaryFolder.newFolder().getAbsolutePath() + File.separator);
        onEdt(() -> {
            ParameterFuzzPanel panel = new ParameterFuzzPanel();
            String raw = "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
            TaskData first = target("GET", "/first", raw);
            TaskData second = target("GET", "/second", raw); second.setRequestScope("browser");
            panel.updateTargets(List.of(first, second), false);
            JList<?> targets = (JList<?>) field(panel, "mTargetList");
            combo(panel, "mMode").setSelectedIndex(1);
            assertFalse(((javax.swing.JCheckBox) field(panel, "mUseBrowser")).isSelected());
            targets.setSelectedIndex(1);
            combo(panel, "mMode").setSelectedIndex(2);
            assertTrue(((javax.swing.JCheckBox) field(panel, "mUseBrowser")).isSelected());
            String browserId = (String) field(panel, "mScanBrowserId");
            assertFalse(browserId.isEmpty());
            panel.updateTargets(List.of(second), false);
            assertEquals(2, targets.getModel().getSize());
            assertEquals(2, combo(panel, "mMode").getSelectedIndex());
            targets.setSelectedIndex(0);
            invoke(panel, "removeTarget");
            assertEquals(1, targets.getModel().getSize());
            assertEquals(2, combo(panel, "mMode").getSelectedIndex());
            assertTrue(((javax.swing.JCheckBox) field(panel, "mUseBrowser")).isSelected());
            assertEquals(browserId, field(panel, "mScanBrowserId"));
            panel.close();
        });
    }

    @FunctionalInterface private interface EdtAction { void run() throws Exception; }
    private static void onEdt(EdtAction action) throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            try { action.run(); } catch (Exception e) { throw new RuntimeException(e); }
        });
    }

    private static void markText(ParameterFuzzPanel panel, JTextArea editor, String text) throws Exception {
        int start = editor.getText().indexOf(text);
        assertTrue(start >= 0);
        editor.select(start, start + text.length());
        invoke(panel, "markPosition");
    }

    private static TaskData target(String method, String path, String request) {
        TaskData target = new TaskData();
        target.setMethod(method);
        target.setHost("https://example.test");
        target.setUrl(path);
        target.setStatus(200);
        target.setReqBytes(request.getBytes(StandardCharsets.UTF_8));
        return target;
    }

    private static Object field(ParameterFuzzPanel panel, String name) throws Exception {
        Field field = ParameterFuzzPanel.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(panel);
    }

    private static Object invoke(ParameterFuzzPanel panel, String name) throws Exception {
        Method method = ParameterFuzzPanel.class.getDeclaredMethod(name);
        method.setAccessible(true);
        return method.invoke(panel);
    }

    @SuppressWarnings("unchecked")
    private static JComboBox<String> combo(ParameterFuzzPanel panel, String fieldName) throws Exception {
        Field field = ParameterFuzzPanel.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        return (JComboBox<String>) field.get(panel);
    }
}
