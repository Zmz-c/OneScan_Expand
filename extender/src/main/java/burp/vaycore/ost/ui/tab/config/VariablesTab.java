package burp.vaycore.ost.ui.tab.config;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.ost.bean.IdentityProfile;
import burp.vaycore.ost.bean.VariableDefinition;
import burp.vaycore.ost.common.Config;
import burp.vaycore.ost.common.L;
import burp.vaycore.ost.manager.WordlistManager;
import burp.vaycore.ost.ui.base.BaseConfigTab;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.regex.Pattern;

public class VariablesTab extends BaseConfigTab {

    private static final Pattern NAME_PATTERN = Pattern.compile("[A-Za-z0-9_.-]{1,64}");
    private ArrayList<VariableDefinition> variables;
    protected ArrayList<IdentityProfile> profiles;
    private VariableTableModel variableModel;
    private ProfileTableModel profileModel;

    @Override
    protected void initView() {
        variables = Config.getVariableDefinitions();
        profiles = Config.getIdentityProfiles();
        addVariablePanel();
        addWordListPanel(L.get("variable_dictionary"), L.get("variable_dictionary_sub_title"),
                WordlistManager.KEY_VARIABLES);
    }

    @Override
    public String getTitleName() {
        return L.get("tab_name.variables");
    }

    private void addVariablePanel() {
        variableModel = new VariableTableModel(variables);
        JTable table = new JTable(variableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setPreferredSize(new Dimension(850, 150));
        JPanel actions = actionPanel(
                () -> editVariable(table, -1),
                () -> editVariable(table, table.getSelectedRow()),
                () -> removeVariable(table));
        addConfigItem(L.get("named_variables"), L.get("named_variables_sub_title"), scrollPane, actions);
    }

    private void editVariable(JTable table, int row) {
        int modelRow = row >= 0 ? table.convertRowIndexToModel(row) : -1;
        VariableDefinition value = modelRow >= 0 ? variables.get(modelRow) : new VariableDefinition();
        JCheckBox enabled = new JCheckBox(L.get("enabled"), value.isEnabled());
        JTextField name = new JTextField(value.getName(), 24);
        JComboBox<String> strategy = new JComboBox<>(new String[]{
                VariableDefinition.STRATEGY_FIXED,
                VariableDefinition.STRATEGY_RANDOM,
                VariableDefinition.STRATEGY_ROUND_ROBIN
        });
        strategy.setSelectedItem(value.getStrategy());
        JComboBox<String> dictionary = new JComboBox<>(new Vector<>(
                WordlistManager.getItemList(WordlistManager.KEY_VARIABLES)));
        dictionary.setSelectedItem(value.getDictionary());
        JTextField fixedValue = new JTextField(value.getFixedValue(), 32);

        JPanel form = new JPanel(new GridLayout(0, 2, 8, 8));
        form.add(new JLabel(L.get("enabled")));
        form.add(enabled);
        form.add(new JLabel(L.get("variable_name")));
        form.add(name);
        form.add(new JLabel(L.get("variable_strategy")));
        form.add(strategy);
        form.add(new JLabel(L.get("variable_dictionary")));
        form.add(dictionary);
        form.add(new JLabel(L.get("variable_fixed_value")));
        form.add(fixedValue);
        int result = UIHelper.showCustomDialog(L.get("named_variables"), form);
        if (result != JOptionPane.OK_OPTION) {
            return;
        }
        String variableName = name.getText().trim();
        if (!NAME_PATTERN.matcher(variableName).matches()
                || duplicateVariableName(variableName, value)) {
            UIHelper.showTipsDialog(L.get("variable_name_invalid"));
            return;
        }
        value.setEnabled(enabled.isSelected());
        value.setName(variableName);
        value.setStrategy(String.valueOf(strategy.getSelectedItem()));
        value.setDictionary(String.valueOf(dictionary.getSelectedItem()));
        value.setFixedValue(fixedValue.getText());
        if (row < 0) {
            variables.add(value);
        }
        Config.put(Config.KEY_VARIABLE_DEFINITIONS, variables);
        variableModel.fireTableDataChanged();
    }

    private void removeVariable(JTable table) {
        int selected = table.getSelectedRow();
        if (selected < 0) {
            return;
        }
        int modelRow = table.convertRowIndexToModel(selected);
        variables.remove(modelRow);
        Config.put(Config.KEY_VARIABLE_DEFINITIONS, variables);
        variableModel.fireTableDataChanged();
    }

    private boolean duplicateVariableName(String name, VariableDefinition current) {
        return variables.stream().anyMatch(item -> item != current && name.equalsIgnoreCase(item.getName()));
    }

    protected void addProfilePanel() {
        profileModel = new ProfileTableModel(profiles);
        JTable table = new JTable(profileModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setPreferredSize(new Dimension(850, 180));
        JPanel actions = actionPanel(
                () -> editProfile(table, -1),
                () -> editProfile(table, table.getSelectedRow()),
                () -> removeSelected(table, profiles, profileModel, Config.KEY_IDENTITY_PROFILES));
        addConfigItem(L.get("identity_profiles"), L.get("identity_profiles_sub_title"), scrollPane, actions);
    }

    private void editProfile(JTable table, int row) {
        IdentityProfile value = row >= 0 ? profiles.get(table.convertRowIndexToModel(row)) : new IdentityProfile();
        JCheckBox enabled = new JCheckBox(L.get("enabled"), value.isEnabled());
        JTextField name = new JTextField(value.getName(), 24);
        JCheckBox replaceCookie = new JCheckBox(L.get("profile_replace_cookie"), value.isReplaceCookie());
        JTextArea cookie = area(value.getCookie());
        cookie.setEnabled(replaceCookie.isSelected());
        replaceCookie.addItemListener(event -> cookie.setEnabled(replaceCookie.isSelected()));
        JTextArea headers = area(formatMap(value.getHeaders()));
        JTextArea query = area(formatMap(value.getQuery()));
        JTextArea body = area(formatMap(value.getBody()));
        JTextArea profileVariables = area(formatMap(value.getVariables()));

        JPanel general = new JPanel(new VLayout(5));
        JPanel fields = new JPanel(new GridLayout(0, 2, 8, 8));
        fields.add(new JLabel(L.get("enabled")));
        fields.add(enabled);
        fields.add(new JLabel(L.get("profile_name")));
        fields.add(name);
        fields.add(new JLabel(L.get("profile_replace_cookie")));
        fields.add(replaceCookie);
        general.add(fields);
        general.add(new JLabel(L.get("profile_cookie_hint")));
        general.add(new JScrollPane(cookie), "1w");

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab(L.get("profile_general"), general);
        tabs.addTab(L.get("profile_headers"), mapPanel(headers));
        tabs.addTab(L.get("profile_query"), mapPanel(query));
        tabs.addTab(L.get("profile_body"), mapPanel(body));
        tabs.addTab(L.get("profile_variables"), mapPanel(profileVariables));
        tabs.setPreferredSize(new Dimension(620, 360));
        int result = UIHelper.showCustomDialog(L.get("identity_profiles"), tabs);
        if (result != JOptionPane.OK_OPTION) {
            return;
        }
        String profileName = name.getText().trim();
        if (!NAME_PATTERN.matcher(profileName).matches() || duplicateProfileName(profileName, value)) {
            UIHelper.showTipsDialog(L.get("profile_name_invalid"));
            return;
        }
        Map<String, String> parsedHeaders;
        Map<String, String> parsedQuery;
        Map<String, String> parsedBody;
        Map<String, String> parsedVariables;
        try {
            parsedHeaders = parseMap(headers.getText());
            parsedQuery = parseMap(query.getText());
            parsedBody = parseMap(body.getText());
            parsedVariables = parseMap(profileVariables.getText());
        } catch (IllegalArgumentException e) {
            UIHelper.showTipsDialog(e.getMessage());
            return;
        }
        value.setEnabled(enabled.isSelected());
        value.setName(profileName);
        value.setReplaceCookie(replaceCookie.isSelected());
        value.setCookie(cookie.getText().trim());
        value.setHeaders(parsedHeaders);
        value.setQuery(parsedQuery);
        value.setBody(parsedBody);
        value.setVariables(parsedVariables);
        if (row < 0) {
            profiles.add(value);
        }
        Config.put(Config.KEY_IDENTITY_PROFILES, profiles);
        profileModel.fireTableDataChanged();
    }

    private boolean duplicateProfileName(String name, IdentityProfile current) {
        return profiles.stream().anyMatch(item -> item != current && name.equalsIgnoreCase(item.getName()));
    }

    private JPanel actionPanel(Runnable add, Runnable edit, Runnable remove) {
        JPanel panel = new JPanel(new HLayout(5));
        JButton addButton = new JButton(L.get("add"));
        addButton.addActionListener(e -> add.run());
        JButton editButton = new JButton(L.get("edit"));
        editButton.addActionListener(e -> edit.run());
        JButton removeButton = new JButton(L.get("remove"));
        removeButton.addActionListener(e -> remove.run());
        panel.add(addButton);
        panel.add(editButton);
        panel.add(removeButton);
        return panel;
    }

    private <T> void removeSelected(JTable table, List<T> values, AbstractTableModel model, String configKey) {
        int selected = table.getSelectedRow();
        if (selected < 0) {
            return;
        }
        values.remove(table.convertRowIndexToModel(selected));
        Config.put(configKey, values);
        model.fireTableDataChanged();
    }

    private JTextArea area(String value) {
        JTextArea result = new JTextArea(value, 8, 48);
        result.setLineWrap(false);
        return result;
    }

    private JPanel mapPanel(JTextArea area) {
        JPanel panel = new JPanel(new VLayout(5));
        panel.add(new JLabel(L.get("profile_map_hint")));
        panel.add(new JScrollPane(area), "1w");
        return panel;
    }

    private String formatMap(Map<String, String> values) {
        StringBuilder result = new StringBuilder();
        for (Map.Entry<String, String> entry : values.entrySet()) {
            if (!result.isEmpty()) {
                result.append('\n');
            }
            result.append(entry.getKey()).append('=').append(entry.getValue());
        }
        return result.toString();
    }

    private Map<String, String> parseMap(String text) {
        LinkedHashMap<String, String> result = new LinkedHashMap<>();
        if (StringUtils.isEmpty(text)) {
            return result;
        }
        for (String line : text.split("\\R")) {
            if (line.isBlank()) {
                continue;
            }
            int separator = line.indexOf('=');
            if (separator <= 0) {
                throw new IllegalArgumentException(L.get("profile_map_invalid", line));
            }
            String key = line.substring(0, separator).trim();
            if (StringUtils.isEmpty(key)) {
                throw new IllegalArgumentException(L.get("profile_map_invalid", line));
            }
            result.put(key, line.substring(separator + 1));
        }
        return result;
    }

    private static class VariableTableModel extends AbstractTableModel {
        private final List<VariableDefinition> values;
        private final String[] columns = {L.get("enabled"), L.get("variable_name"),
                L.get("variable_strategy"), L.get("variable_source"), L.get("variable_placeholder")};

        private VariableTableModel(List<VariableDefinition> values) {
            this.values = values;
        }

        public int getRowCount() { return values.size(); }
        public int getColumnCount() { return columns.length; }
        public String getColumnName(int column) { return columns[column]; }
        public Class<?> getColumnClass(int column) { return column == 0 ? Boolean.class : String.class; }

        public Object getValueAt(int row, int column) {
            VariableDefinition value = values.get(row);
            return switch (column) {
                case 0 -> value.isEnabled();
                case 1 -> value.getName();
                case 2 -> value.getStrategy();
                case 3 -> VariableDefinition.STRATEGY_FIXED.equals(value.getStrategy())
                        ? value.getFixedValue() : value.getDictionary();
                default -> value.placeholder();
            };
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            return column == 0;
        }

        @Override
        public void setValueAt(Object value, int row, int column) {
            if (column != 0 || !(value instanceof Boolean enabled)
                    || row < 0 || row >= values.size()) {
                return;
            }
            values.get(row).setEnabled(enabled);
            Config.put(Config.KEY_VARIABLE_DEFINITIONS, values);
            fireTableCellUpdated(row, column);
        }
    }
    private static class ProfileTableModel extends AbstractTableModel {
        private final List<IdentityProfile> values;
        private final String[] columns = {L.get("enabled"), L.get("profile_name"),
                L.get("profile_cookie"), L.get("profile_headers"), L.get("profile_query"), L.get("profile_body")};

        private ProfileTableModel(List<IdentityProfile> values) {
            this.values = values;
        }

        public int getRowCount() { return values.size(); }
        public int getColumnCount() { return columns.length; }
        public String getColumnName(int column) { return columns[column]; }
        public Class<?> getColumnClass(int column) { return column == 0 ? Boolean.class : String.class; }

        @Override
        public boolean isCellEditable(int row, int column) {
            return column == 0;
        }

        public Object getValueAt(int row, int column) {
            IdentityProfile value = values.get(row);
            return switch (column) {
                case 0 -> value.isEnabled();
                case 1 -> value.getName();
                case 2 -> value.isReplaceCookie() ? value.getCookie() : "-";
                case 3 -> value.getHeaders().size();
                case 4 -> value.getQuery().size();
                default -> value.getBody().size();
            };
        }

        @Override
        public void setValueAt(Object value, int row, int column) {
            if (column != 0 || !(value instanceof Boolean enabled)) {
                return;
            }
            values.get(row).setEnabled(enabled);
            Config.put(Config.KEY_IDENTITY_PROFILES, values);
            fireTableCellUpdated(row, column);
        }
    }
}
