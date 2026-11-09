package burp.vaycore.ost.ui.widget;

import burp.vaycore.common.filter.*;
import burp.vaycore.common.utils.GsonUtils;
import burp.vaycore.ost.bean.*;
import burp.vaycore.ost.common.Config;
import burp.vaycore.ost.common.L;
import burp.vaycore.ost.manager.FpManager;
import org.junit.*;
import org.junit.rules.TemporaryFolder;

import javax.swing.*;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.lang.reflect.Field;
import java.util.*;
import java.util.List;

import static org.junit.Assert.*;

public class TaskFilterTest {
    @Rule public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Before public void initialize() throws Exception {
        Config.init(temporaryFolder.newFolder("filter").getAbsolutePath() + File.separator);
        L.configure(L.LANGUAGE_ENGLISH);
    }

    @After public void restoreLanguage() {
        // Drain queued fingerprint saves before TemporaryFolder deletes this fixture.
        FpManager.saveNow();
        L.configure(L.LANGUAGE_AUTO);
    }

    @Test public void fingerprintEqualityMatchesIndividualHitsButNotSubstrings() throws Exception {
        onEdt(() -> {
            TaskTable table = table();
            filter(table, rule(-1, "fingerprint", FilterRule.OPERATE_EQUAL, "Tomcat"));
            assertEquals(1, table.getRowCount());
            assertEquals("admin", table.getValueAt(0, 10));
        });
    }

    @Test public void fingerprintExclusionsRequireEveryHitToBeExcluded() throws Exception {
        onEdt(() -> {
            TaskTable table = table();
            filter(table, rule(-1, "fingerprint", FilterRule.OPERATE_NOT_EQUAL, "Tomcat"));
            assertEquals(2, table.getRowCount());
            filter(table, rule(-1, "fingerprint", FilterRule.OPERATE_NOT_INCLUDE, "Tom"));
            assertEquals(1, table.getRowCount());
            filter(table, rule(-1, "fingerprint", FilterRule.OPERATE_INCLUDE, "Tom"));
            assertEquals(2, table.getRowCount());
        });
    }

    @Test public void combinesFingerprintProfileAndStatusFilters() throws Exception {
        onEdt(() -> {
            TaskTable table = table();
            filter(table, rule(-1, "fingerprint", FilterRule.OPERATE_INCLUDE, "Tom"),
                    rule(10, "profile", FilterRule.OPERATE_EQUAL, "admin"),
                    rule(7, null, FilterRule.OPERATE_EQUAL, "200"));
            assertEquals(1, table.getRowCount());
        });
    }

    @Test public void handlesMissingFingerprintAndProfile() throws Exception {
        onEdt(() -> {
            TaskTable table = table();
            filter(table, rule(-1, "fingerprint", FilterRule.OPERATE_EQUAL, ""));
            assertEquals(1, table.getRowCount());
            filter(table, rule(10, "profile", FilterRule.OPERATE_EQUAL, ""));
            assertEquals(1, table.getRowCount());
        });
    }

    @Test public void doesNotShortCircuitMixedLogicBeforeLaterConditions() throws Exception {
        onEdt(() -> {
            TaskTable table = table();
            FilterRule rule = rule(7, null, FilterRule.OPERATE_EQUAL, "404");
            rule.addRule(FilterRule.LOGIC_AND, FilterRule.OPERATE_EQUAL, "500");
            rule.addRule(FilterRule.LOGIC_OR, FilterRule.OPERATE_EQUAL, "200");
            filter(table, rule);
            assertEquals(3, table.getRowCount());
            rule = rule(7, null, FilterRule.OPERATE_EQUAL, "200");
            rule.addRule(FilterRule.LOGIC_OR, FilterRule.OPERATE_EQUAL, "404");
            rule.addRule(FilterRule.LOGIC_AND, FilterRule.OPERATE_EQUAL, "500");
            filter(table, rule);
            assertEquals(0, table.getRowCount());
        });
    }

    @Test public void readsLegacyJsonAndPersistsStableFieldIds() throws Exception {
        onEdt(() -> {
            FilterRule legacy = GsonUtils.toObject("{\"columnIndex\":10,\"items\":[{\"logic\":0,\"operate\":1,\"value\":\"admin\"}]}", FilterRule.class);
            TaskTable table = table();
            filter(table, legacy);
            assertEquals(1, table.getRowCount());
            TableFilterPanel panel = panel(new ArrayList<>(List.of(legacy)));
            FilterRule saved = panel.exportRules().get(0);
            assertEquals("profile", saved.getFieldKey());
            Config.put(Config.KEY_DATABOARD_FILTER_RULES, panel.exportRules());
            FilterRule restored = GsonUtils.toObject(GsonUtils.toJson(Config.getDataboardFilterRules().get(0)), FilterRule.class);
            assertEquals("profile", restored.getFieldKey());
            filter(table, restored);
            assertEquals(1, table.getRowCount());
        });
    }

    @Test public void fingerprintRulesRemainBoundAfterColumnChanges() throws Exception {
        onEdt(() -> {
            TaskTable table = table();
            String originalId = FpManager.getColumnId(0);
            FilterRule legacy = rule(12, null, FilterRule.OPERATE_EQUAL, "Tomcat,SpringBoot");
            FilterRule saved = panel(new ArrayList<>(List.of(legacy))).exportRules().get(0);
            assertEquals("param:" + originalId, saved.getFieldKey());
            FpColumn replacement = new FpColumn();
            replacement.setId("new-column");
            replacement.setName("Replacement");
            FpManager.setColumnsItem(0, replacement);
            table.refreshColumns();
            filter(table, saved);
            assertEquals(1, table.getRowCount());
            // Editor preserves removed fields instead of silently rebinding or deleting them.
            TableFilterPanel editor = panel(new ArrayList<>(List.of(saved)));
            assertEquals(saved.getFieldKey(), editor.exportRules().get(0).getFieldKey());
        });
    }

    @Test public void unknownFieldsFailClosedWithoutUsingTheirOldColumnIndex() throws Exception {
        onEdt(() -> {
            TaskTable table = table();
            filter(table, rule(7, "unknown", FilterRule.OPERATE_NOT_EQUAL, "404"));
            assertEquals(0, table.getRowCount());
        });
    }

    @Test public void profileAndFingerprintChoicesIncludeConfigurationAndHistory() throws Exception {
        onEdt(() -> {
            IdentityProfile profile = new IdentityProfile();
            profile.setName("configured");
            Config.put(Config.KEY_IDENTITY_PROFILES, List.of(profile));
            List<TaskData> history = List.of(task("historical", "OldFingerprint"));
            assertTrue(choiceValues(TaskFilterFields.choices("profile", history)).containsAll(List.of("", "configured", "historical")));
            assertTrue(choiceValues(TaskFilterFields.choices("fingerprint", history)).containsAll(List.of("", "Tomcat", "OldFingerprint")));
        });
    }

    @Test public void refreshesDropdownWithoutLosingTypedOrDeletedSelection() throws Exception {
        onEdt(() -> {
            TableFilterPanel panel = panel(new ArrayList<>());
            selectField(panel, "fingerprint");
            JComboBox<?> values = valueBox(panel);
            values.getEditor().setItem("my-custom-value");
            FpData fp = new FpData();
            fp.getRules().add(new ArrayList<>());
            fp.getParams().add(new FpData.Param(FpManager.getColumnId(0), "NewFingerprint"));
            FpManager.addItem(fp);
            refresh(values);
            assertTrue(boxValues(values).contains("NewFingerprint"));
            assertEquals("my-custom-value", ((FilterField.Choice) values.getSelectedItem()).value());
            values.setSelectedItem(new FilterField.Choice("NewFingerprint", "NewFingerprint"));
            FpManager.removeItem(FpManager.getCount() - 1);
            refresh(values);
            assertEquals("NewFingerprint", ((FilterField.Choice) values.getSelectedItem()).value());
            selectField(panel, "profile");
            values = valueBox(panel);
            IdentityProfile profile = new IdentityProfile();
            profile.setName("new-profile");
            Config.put(Config.KEY_IDENTITY_PROFILES, List.of(profile));
            refresh(values);
            assertTrue(boxValues(values).contains("new-profile"));
        });
    }

    @Test public void emptySelectionSavesRawValueInsteadOfTranslatedLabel() throws Exception {
        onEdt(() -> {
            TableFilterPanel panel = panel(new ArrayList<>());
            selectField(panel, "profile");
            operateBox(panel).setSelectedIndex(FilterRule.OPERATE_EQUAL);
            assertEquals("No profile", valueBox(panel).getEditor().getItem().toString());
            FilterRule saved = panel.exportRules().get(0);
            assertEquals("", saved.getItems().get(0).getValue());
            assertFalse(panel.exportRulesText().contains("No profile"));
        });
    }

    @Test public void cancelAndClearDoNotMutateOriginalRules() throws Exception {
        onEdt(() -> {
            ArrayList<FilterRule> original = new ArrayList<>(List.of(rule(10, "profile", 1, "admin")));
            TableFilterPanel panel = panel(original);
            selectField(panel, "profile");
            valueBox(panel).getEditor().setItem("changed");
            selectField(panel, "fingerprint");
            assertEquals("admin", original.get(0).getItems().get(0).getValue());
            selectField(panel, "profile");
            panel.actionPerformed(new ActionEvent(panel, 0, "clear-filter-item"));
            assertEquals(0, panel.exportRules().size());
            assertEquals(1, original.size());
        });
    }

    @Test public void unsettingOperatorRemovesOldRuleAndExportsCurrentEdits() throws Exception {
        onEdt(() -> {
            TableFilterPanel panel = panel(new ArrayList<>(List.of(rule(10, "profile", 1, "admin"))));
            selectField(panel, "profile");
            operateBox(panel).setSelectedIndex(0);
            assertTrue(panel.exportTableFilters().isEmpty());
            assertEquals("", panel.exportRulesText());
            operateBox(panel).setSelectedIndex(1);
            valueBox(panel).getEditor().setItem("guest");
            assertEquals("guest", panel.exportTableFilters().get(0).getRule().getItems().get(0).getValue());
        });
    }

    @Test public void savedFingerprintRuleSurvivesConfigReloadAndLanguageChange() throws Exception {
        FilterRule original = rule(-1, "fingerprint", FilterRule.OPERATE_EQUAL, "Tomcat");
        Config.put(Config.KEY_DATABOARD_FILTER_RULES, new ArrayList<>(List.of(original)));
        Config.init(Config.getWorkDir());
        L.configure(L.LANGUAGE_CHINESE);
        onEdt(() -> {
            TableFilterPanel panel = panel(Config.getDataboardFilterRules());
            TaskTable table = table();
            table.setRowFilter(panel.exportTableFilters());
            assertEquals(1, table.getRowCount());
            assertEquals("fingerprint", panel.exportRules().get(0).getFieldKey());
            assertEquals("Tomcat", panel.exportRules().get(0).getItems().get(0).getValue());
        });
    }

    @Test public void databoardAppliesFingerprintRulesToBothRequestSources() throws Exception {
        Config.put(Config.KEY_DATABOARD_FILTER_RULES,
                new ArrayList<>(List.of(rule(-1, "fingerprint", FilterRule.OPERATE_EQUAL, "Tomcat"))));
        onEdt(() -> {
            burp.vaycore.ost.ui.tab.DataBoardTab board = new burp.vaycore.ost.ui.tab.DataBoardTab();
            try {
                board.init(new JTextArea(), new JTextArea());
                assertEquals(2, board.getTaskTables().size());
                for (TaskTable table : board.getTaskTables()) {
                table.loadTaskData(List.of(task("admin", "Tomcat,SpringBoot"), task("guest", "Shiro")));
                assertEquals(1, table.getRowCount());
                ((TaskTable.TaskTableModel) table.getModel()).addAll(List.of(task("new", "Tomcat")));
                    assertEquals(2, table.getRowCount());
                }
            } finally {
                board.closeAutoSaveTimer();
                board.closeDataSaveExecutor();
                board.getParameterFuzzPanel().close();
            }
        });
    }

    @Test public void databoardMigratesLegacyProfileRulesWithoutOpeningEditor() throws Exception {
        Config.put(Config.KEY_DATABOARD_FILTER_RULES, new ArrayList<>(List.of(rule(10, null, 1, "admin"))));
        onEdt(() -> {
            burp.vaycore.ost.ui.tab.DataBoardTab board = new burp.vaycore.ost.ui.tab.DataBoardTab();
            try {
                board.init(new JTextArea(), new JTextArea());
                assertEquals("profile", Config.getDataboardFilterRules().get(0).getFieldKey());
            } finally {
                board.closeAutoSaveTimer();
                board.closeDataSaveExecutor();
                board.getParameterFuzzPanel().close();
            }
        });
    }

    private TableFilterPanel panel(ArrayList<FilterRule> rules) {
        return new TableFilterPanel(TaskFilterFields.create(List::of), rules);
    }

    private static List<String> choiceValues(List<FilterField.Choice> choices) {
        return choices.stream().map(FilterField.Choice::value).toList();
    }

    private static List<String> boxValues(JComboBox<?> box) {
        List<String> values = new ArrayList<>();
        for (int i = 0; i < box.getItemCount(); i++) values.add(((FilterField.Choice) box.getItemAt(i)).value());
        return values;
    }

    private static void refresh(JComboBox<?> box) {
        for (PopupMenuListener listener : box.getPopupMenuListeners()) {
            listener.popupMenuWillBecomeVisible(new PopupMenuEvent(box));
        }
    }

    private static void selectField(TableFilterPanel panel, String key) throws Exception {
        JComboBox<?> fields = (JComboBox<?>) member(panel, "mColumnList");
        for (int i = 0; i < fields.getItemCount(); i++) {
            if (key.equals(((FilterField) fields.getItemAt(i)).key())) {
                fields.setSelectedIndex(i);
                return;
            }
        }
        fail("Missing field " + key);
    }

    private static JComboBox<?> valueBox(TableFilterPanel panel) throws Exception {
        return (JComboBox<?>) conditionPanel(panel).getComponent(1);
    }

    private static JComboBox<?> operateBox(TableFilterPanel panel) throws Exception {
        return (JComboBox<?>) conditionPanel(panel).getComponent(0);
    }

    private static JPanel conditionPanel(TableFilterPanel panel) throws Exception {
        JPanel rules = (JPanel) member(panel, "mRulesPanel");
        return (JPanel) ((JPanel) rules.getComponent(0)).getComponent(1);
    }

    private static Object member(Object object, String name) throws Exception {
        Field field = object.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(object);
    }

    private static FilterRule rule(int column, String key, int operator, String value) {
        FilterRule rule = new FilterRule(column, key);
        rule.addRule(0, operator, value);
        return rule;
    }

    private static void filter(TaskTable table, FilterRule... rules) {
        ArrayList<TableFilter<AbstractTableModel>> filters = new ArrayList<>();
        for (FilterRule rule : rules) filters.add(new TableFilter<>(rule));
        table.setRowFilter(filters);
    }

    private TaskData task(String profile, String fingerprint) {
        TaskData data = new TaskData();
        data.setProfile(profile);
        data.setStatus(200);
        if (!fingerprint.isEmpty()) data.getParams().put(FpManager.getColumnId(0), fingerprint);
        return data;
    }

    private TaskTable table() {
        TaskTable table = new TaskTable();
        table.loadTaskData(List.of(task("admin", "Tomcat,SpringBoot"), task("guest", "TomcatX"), task("", "")));
        return table;
    }

    private interface CheckedRunnable { void run() throws Exception; }
    private void onEdt(CheckedRunnable action) throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            try { action.run(); } catch (Exception e) { throw new RuntimeException(e); }
        });
    }
}
