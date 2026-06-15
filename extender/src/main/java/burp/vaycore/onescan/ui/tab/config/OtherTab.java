package burp.vaycore.onescan.ui.tab.config;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.common.Config;
import burp.vaycore.onescan.common.L;
import burp.vaycore.onescan.common.NumberFilter;
import burp.vaycore.onescan.manager.TaskPersistenceManager;
import burp.vaycore.onescan.ui.base.BaseConfigTab;
import burp.vaycore.onescan.ui.widget.TaskFieldSelectionPanel;

import javax.swing.*;
import java.awt.*;

/**
 * Other设置
 * <p>
 * Created by vaycore on 2022-08-21.
 */
public class OtherTab extends BaseConfigTab {

    public static final String EVENT_UNLOAD_PLUGIN = "event-unload-plugin";
    public static final String EVENT_REFRESH_DATA_PERSISTENCE = "event-refresh-data-persistence";
    public static final String EVENT_REFRESH_MCP_SERVER = "event-refresh-mcp-server";

    private JCheckBox mMcpEnabled;
    private JTextField mMcpEndpointField;
    private JTextField mMcpHealthField;
    private JLabel mMcpStatusLabel;

    protected void initView() {
        // 请求响应最大长度
        addTextConfigPanel(L.get("maximum_display_length"), L.get("maximum_display_length_sub_title"),
                20, Config.KEY_MAX_DISPLAY_LENGTH).addKeyListener(new NumberFilter(8));
        addMcpServerPanel();
        addDataPersistencePanel();
        addDirectoryConfigPanel(L.get("collect_directory"), L.get("collect_directory_sub_title"), Config.KEY_COLLECT_PATH);
        addDirectoryConfigPanel(L.get("wordlist_directory"), L.get("wordlist_directory_sub_title"), Config.KEY_WORDLIST_PATH);
    }

    private void addMcpServerPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        mMcpEnabled = new JCheckBox(L.get("mcp_server_enabled"), Config.getBoolean(Config.KEY_ENABLE_MCP));
        mMcpEnabled.setAlignmentX(Component.LEFT_ALIGNMENT);
        mMcpEnabled.addActionListener(e -> {
            Config.put(Config.KEY_ENABLE_MCP, String.valueOf(mMcpEnabled.isSelected()));
            sendTabEvent(EVENT_REFRESH_MCP_SERVER);
        });
        panel.add(mMcpEnabled);

        mMcpStatusLabel = new JLabel();
        mMcpStatusLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(mMcpStatusLabel);

        JPanel endpointPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 3));
        endpointPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        endpointPanel.add(new JLabel(L.get("mcp_server_endpoint")));
        mMcpEndpointField = new JTextField(38);
        mMcpEndpointField.setEditable(false);
        endpointPanel.add(mMcpEndpointField);
        panel.add(endpointPanel);

        JPanel healthPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 3));
        healthPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        healthPanel.add(new JLabel(L.get("mcp_server_health")));
        mMcpHealthField = new JTextField(38);
        mMcpHealthField.setEditable(false);
        healthPanel.add(mMcpHealthField);
        panel.add(healthPanel);

        refreshMcpServerInfo(false, "");
        addConfigItem(L.get("mcp_server"), L.get("mcp_server_sub_title"), panel);
    }

    public void refreshMcpServerInfo(boolean running, String endpoint) {
        boolean enabled = Config.getBoolean(Config.KEY_ENABLE_MCP);
        if (mMcpEnabled != null && mMcpEnabled.isSelected() != enabled) {
            mMcpEnabled.setSelected(enabled);
        }
        if (mMcpStatusLabel != null) {
            String statusText = running
                    ? L.get("mcp_server_status_running")
                    : (enabled ? L.get("mcp_server_status_not_running") : L.get("mcp_server_status_stopped"));
            mMcpStatusLabel.setText(L.get("mcp_server_status", statusText));
        }
        String safeEndpoint = endpoint == null ? "" : endpoint;
        if (mMcpEndpointField != null) {
            mMcpEndpointField.setText(safeEndpoint);
        }
        if (mMcpHealthField != null) {
            String health = safeEndpoint.endsWith("/mcp")
                    ? safeEndpoint.substring(0, safeEndpoint.length() - "/mcp".length()) + "/health"
                    : "";
            mMcpHealthField.setText(health);
        }
    }

    private void addDataPersistencePanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        JCheckBox enabled = new JCheckBox(L.get("data_persistence_enabled"),
                Config.getBoolean(Config.KEY_DATA_PERSISTENCE_ENABLED));
        enabled.setAlignmentX(Component.LEFT_ALIGNMENT);
        enabled.addActionListener(e -> {
            Config.put(Config.KEY_DATA_PERSISTENCE_ENABLED, String.valueOf(enabled.isSelected()));
            refreshDataBoardAutoSaveTimer();
        });
        panel.add(enabled);

        JPanel pathPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 3));
        pathPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JTextField pathField = new JTextField(Config.getFilePath(Config.KEY_DATA_PERSISTENCE_DB_PATH), 35);
        pathPanel.add(pathField);
        JButton selectButton = new JButton(L.get("select_file"));
        selectButton.addActionListener(e -> {
            String selected = UIHelper.selectFileDialog(L.get("select_a_file"), pathField.getText());
            if (!StringUtils.isEmpty(selected)) {
                pathField.setText(selected);
                Config.put(Config.KEY_DATA_PERSISTENCE_DB_PATH, selected);
                UIHelper.showTipsDialog(L.get("save_success"));
            }
        });
        pathPanel.add(selectButton);
        JButton savePathButton = new JButton(L.get("save"));
        savePathButton.addActionListener(e -> {
            String path = pathField.getText().trim();
            if (StringUtils.isEmpty(path)) {
                UIHelper.showTipsDialog(L.get("data_persistence_db_path_invalid"));
                return;
            }
            Config.put(Config.KEY_DATA_PERSISTENCE_DB_PATH, path);
            UIHelper.showTipsDialog(L.get("save_success"));
        });
        pathPanel.add(savePathButton);
        panel.add(pathPanel);

        JPanel autoSavePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 3));
        autoSavePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        autoSavePanel.add(new JLabel(L.get("data_persistence_auto_save_interval")));
        JTextField autoSaveField = new JTextField(String.valueOf(TaskPersistenceManager.getAutoSaveIntervalSeconds()), 8);
        autoSaveField.addKeyListener(new NumberFilter(8));
        autoSavePanel.add(autoSaveField);
        JButton saveAutoSaveButton = new JButton(L.get("save"));
        saveAutoSaveButton.addActionListener(e -> {
            int seconds = StringUtils.parseInt(autoSaveField.getText().trim(), -1);
            if (seconds < 0) {
                UIHelper.showTipsDialog(L.get("data_persistence_auto_save_interval_invalid"));
                return;
            }
            TaskPersistenceManager.saveAutoSaveIntervalSeconds(seconds);
            refreshDataBoardAutoSaveTimer();
            UIHelper.showTipsDialog(L.get("save_success"));
        });
        autoSavePanel.add(saveAutoSaveButton);
        panel.add(autoSavePanel);

        JButton selectFieldsButton = new JButton(L.get("data_persistence_select_fields"));
        selectFieldsButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        selectFieldsButton.addActionListener(e -> showFieldSelectionDialog());
        panel.add(selectFieldsButton);

        addConfigItem(L.get("data_persistence"), L.get("data_persistence_sub_title"), panel);
    }

    private void showFieldSelectionDialog() {
        TaskFieldSelectionPanel fieldPanel = new TaskFieldSelectionPanel(TaskPersistenceManager.getConfiguredFieldKeys());
        JScrollPane scrollPane = new JScrollPane(fieldPanel);
        scrollPane.setPreferredSize(new Dimension(420, 220));
        int ret = JOptionPane.showConfirmDialog(this, scrollPane, L.get("data_persistence_select_fields"),
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (ret != JOptionPane.OK_OPTION) {
            return;
        }
        TaskPersistenceManager.saveConfiguredFieldKeys(fieldPanel.getSelectedFieldKeys());
        UIHelper.showTipsDialog(L.get("save_success"));
    }

    private void refreshDataBoardAutoSaveTimer() {
        sendTabEvent(EVENT_REFRESH_DATA_PERSISTENCE);
    }

    @Override
    public String getTitleName() {
        return L.get("tab_name.other");
    }

    @Override
    protected boolean onTextConfigSave(String configKey, String text) {
        int value = StringUtils.parseInt(text, -1);
        if (Config.KEY_MAX_DISPLAY_LENGTH.equals(configKey)) {
            if (value == 0) {
                text = String.valueOf(value);
                Config.put(configKey, text);
                return true;
            }
            if (value < 100000 || value > 99999999) {
                UIHelper.showTipsDialog(L.get("maximum_display_length_value_invalid"));
                return false;
            }
            text = String.valueOf(value);
            Config.put(configKey, text);
            return true;
        }
        return super.onTextConfigSave(configKey, text);
    }
}
