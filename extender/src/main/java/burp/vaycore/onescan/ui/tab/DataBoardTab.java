package burp.vaycore.onescan.ui.tab;

import burp.vaycore.common.filter.FilterRule;
import burp.vaycore.common.filter.TableFilter;
import burp.vaycore.common.filter.TableFilterPanel;
import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.utils.IPUtils;
import burp.vaycore.common.utils.Utils;
import burp.vaycore.common.widget.HintTextField;
import burp.vaycore.onescan.bean.FpData;
import burp.vaycore.onescan.bean.TaskData;
import burp.vaycore.onescan.common.*;
import burp.vaycore.onescan.manager.FpManager;
import burp.vaycore.onescan.manager.TaskPersistenceManager;
import burp.vaycore.onescan.ui.base.BaseTab;
import burp.vaycore.onescan.ui.widget.DividerLine;
import burp.vaycore.onescan.ui.widget.ImportUrlWindow;
import burp.vaycore.onescan.ui.widget.TaskFieldSelectionPanel;
import burp.vaycore.onescan.ui.widget.TaskTable;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class DataBoardTab extends BaseTab implements ImportUrlWindow.OnImportUrlListener, OnFpColumnModifyListener,
        ActionListener {

    public static final String EVENT_IMPORT_URL = "event-import-url";
    public static final String EVENT_STOP_TASK = "event-stop-task";
    public static final String EVENT_CONTINUE_TASK = "event-continue-task";
    public static final String EVENT_CLEAR_ALL_TASK = "event-clear-all-task";

    private TaskTable mBurpTaskTable;
    private TaskTable mBrowserTaskTable;
    private JTabbedPane mTaskTabbedPane;
    private JCheckBox mListenProxyMessage;
    private AbstractButton mRemoveHeader;
    private AbstractButton mReplaceHeader;
    private JCheckBox mDirScan;
    private ArrayList<FilterRule> mLastFilters;
    private HintTextField mFilterRuleText;
    private AbstractButton mPayloadProcessing;
    private JPopupMenu mRequestProcessingMenu;
    private ImportUrlWindow mImportUrlWindow;
    private JComboBox<RequestScopeItem> mTaskControlScope;
    private Boolean mListenProxyMessageBeforePause;
    private JLabel mTaskStatus;
    private JLabel mLFTaskStatus;
    private JLabel mFpCacheStatus;
    private JLabel mTaskHistoryStatus;
    private Timer mAutoSaveTimer;
    private long mLastAutoSavedVersion = -1L;
    private long mLastAutoSaveQueuedVersion = -1L;
    private final ExecutorService mSaveExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread thread = new Thread(r, "OneScan-data-save");
        thread.setDaemon(true);
        return thread;
    });

    @Override
    protected void initData() {
        FpManager.addOnFpColumnModifyListener(this);
    }

    @Override
    protected void initView() {
    }

    public String getTitleName() {
        return L.get("tab_name.databoard");
    }

    public void testInit() {
        init(new JTextArea(L.get("request")), new JTextArea(L.get("response")));
        for (int i = 0; i < 100; i++) {
            TaskData data = new TaskData();
            data.setMethod(i % 12 == 0 ? "POST" : "GET");
            data.setHost("https://www.baidu.com");
            data.setUrl("/?s=" + i);
            data.setTitle("baidu");
            data.setIp(IPUtils.randomIPv4());
            data.setStatus(200);
            data.setLength(Utils.randomInt(99999));
            FpData fp = Utils.getRandomItem(FpManager.getList());
            if (fp != null) {
                List<FpData> list = new ArrayList<>();
                list.add(fp);
                data.setFingerprint(list);
            }
            data.setFrom("Proxy");
            data.setReqResp(new Object());
            addTaskData(data, i % 2 == 0 ? RequestMode.BURP : RequestMode.BROWSER);
        }
    }

    public void init(Component requestTextEditor, Component responseTextEditor) {
        if (requestTextEditor == null || responseTextEditor == null) {
            return;
        }
        setLayout(new VLayout(0));
        initControlPanel();

        JSplitPane mainSplitPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplitPanel.setResizeWeight(0.55D);
        mainSplitPanel.setDividerSize(3);

        mBurpTaskTable = new TaskTable();
        mBrowserTaskTable = new TaskTable();
        mTaskTabbedPane = new JTabbedPane();
        mTaskTabbedPane.addTab(L.get("request_scope_burp"), new JScrollPane(mBurpTaskTable));
        mTaskTabbedPane.addTab(L.get("request_scope_browser"), new JScrollPane(mBrowserTaskTable));
        mTaskTabbedPane.addChangeListener(e -> refreshTaskHistoryStatus());
        mTaskTabbedPane.setPreferredSize(new Dimension(mTaskTabbedPane.getWidth(), 0));

        JSplitPane dataSplitPanel = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        dataSplitPanel.setResizeWeight(0.5D);
        dataSplitPanel.setDividerSize(3);
        dataSplitPanel.add(requestTextEditor, JSplitPane.LEFT);
        dataSplitPanel.add(responseTextEditor, JSplitPane.RIGHT);

        mainSplitPanel.add(mTaskTabbedPane, JSplitPane.LEFT);
        mainSplitPanel.add(dataSplitPanel, JSplitPane.RIGHT);
        add(mainSplitPanel, "1w");

        initStatusPanel();
        loadFilterRules();
    }

    private void initControlPanel() {
        JPanel panel = new JPanel(new HLayout(5, true));
        panel.setBorder(new EmptyBorder(0, 0, 0, 5));
        panel.setFocusable(false);
        add(panel);

        mListenProxyMessage = newJCheckBox(panel, L.get("listen_proxy"), Config.KEY_ENABLE_LISTEN_PROXY);
        mDirScan = newJCheckBox(panel, L.get("dir_scan"), Config.KEY_ENABLE_DIR_SCAN);

        initRequestProcessingMenu();
        JButton requestProcessingBtn = new JButton(L.get("request_processing"));
        requestProcessingBtn.setToolTipText(L.get("request_processing"));
        requestProcessingBtn.addActionListener(e -> showRequestProcessingMenu(requestProcessingBtn));
        panel.add(requestProcessingBtn);

        JButton importUrlBtn = new JButton(L.get("import_url"));
        importUrlBtn.setToolTipText(L.get("import_url"));
        importUrlBtn.setActionCommand("import-url");
        importUrlBtn.addActionListener(this);
        panel.add(importUrlBtn);

        mTaskControlScope = new JComboBox<>(new RequestScopeItem[]{
                new RequestScopeItem(L.get("request_scope_all"), RequestScope.ALL),
                new RequestScopeItem(L.get("request_scope_burp"), RequestScope.BURP),
                new RequestScopeItem(L.get("request_scope_browser"), RequestScope.BROWSER)
        });
        mTaskControlScope.setToolTipText(L.get("request_scope"));
        panel.add(mTaskControlScope);

        JButton stopBtn = new JButton(L.get("stop"));
        stopBtn.setToolTipText(L.get("stop_all_task"));
        stopBtn.setActionCommand("stop-task");
        stopBtn.addActionListener(this);
        panel.add(stopBtn);

        JButton continueBtn = new JButton(L.get("continue_task"));
        continueBtn.setToolTipText(L.get("continue_task"));
        continueBtn.setActionCommand("continue-task");
        continueBtn.addActionListener(this);
        panel.add(continueBtn);

        JButton clearAllTaskBtn = new JButton(L.get("clear_all_task"));
        clearAllTaskBtn.setToolTipText(L.get("clear_all_task_tip"));
        clearAllTaskBtn.setActionCommand("clear-all-task");
        clearAllTaskBtn.addActionListener(this);
        panel.add(clearAllTaskBtn);

        JButton clearBtn = new JButton(L.get("clear_record"));
        clearBtn.setToolTipText(L.get("clear_history"));
        clearBtn.setActionCommand("clear-history");
        clearBtn.addActionListener(this);
        panel.add(clearBtn);

        JButton dataProcessingBtn = new JButton(L.get("data_processing"));
        dataProcessingBtn.setToolTipText(L.get("data_processing"));
        dataProcessingBtn.addActionListener(e -> showDataProcessingMenu(dataProcessingBtn));
        panel.add(dataProcessingBtn);

        panel.add(new JPanel(), "1w");

        mFilterRuleText = new HintTextField();
        mFilterRuleText.setEditable(false);
        mFilterRuleText.setHintText(L.get("no_filter_rules"));
        panel.add(mFilterRuleText, "2w");

        JButton filterBtn = new JButton(L.get("filter"));
        filterBtn.setToolTipText(L.get("filter_data"));
        filterBtn.setActionCommand("filter-data");
        filterBtn.addActionListener(this);
        panel.add(filterBtn, "65px");
    }

    private void initStatusPanel() {
        add(DividerLine.h());
        JPanel panel = new JPanel(new HLayout(10));
        panel.setBorder(new EmptyBorder(5, 10, 5, 10));
        panel.setFocusable(false);
        panel.add(new JPanel(), "1w");
        add(panel);

        mTaskStatus = addStatusInfoPanel(panel);
        mLFTaskStatus = addStatusInfoPanel(panel);
        mTaskHistoryStatus = addStatusInfoPanel(panel);
        mFpCacheStatus = addStatusInfoPanel(panel);

        refreshTaskStatus(0, 0);
        refreshLFTaskStatus(0, 0);
        refreshTaskHistoryStatus();
        refreshFpCacheStatus();
    }

    private JLabel addStatusInfoPanel(JPanel panel) {
        panel.add(DividerLine.v());
        JLabel label = new JLabel();
        panel.add(label);
        return label;
    }

    private void loadFilterRules() {
        ArrayList<FilterRule> rules = Config.getDataboardFilterRules();
        if (rules == null) {
            return;
        }
        TableFilterPanel panel = new TableFilterPanel(TaskTable.getColumnNames(), rules);
        ArrayList<TableFilter<AbstractTableModel>> filters = panel.exportTableFilters();
        String rulesText = panel.exportRulesText();
        setRowFilterForAll(filters);
        mFilterRuleText.setText(rulesText);
        mLastFilters = rules;
    }

    private JCheckBox newJCheckBox(JPanel panel, String text, String configKey) {
        JCheckBox checkBox = new JCheckBox(text, Config.getBoolean(configKey));
        checkBox.setFocusable(false);
        checkBox.setMargin(new Insets(5, 5, 5, 5));
        panel.add(checkBox);
        checkBox.addActionListener(e -> {
            boolean configSelected = Config.getBoolean(configKey);
            boolean selected = checkBox.isSelected();
            if (selected != configSelected) {
                Config.put(configKey, String.valueOf(selected));
            }
        });
        return checkBox;
    }

    private void initRequestProcessingMenu() {
        mRequestProcessingMenu = new JPopupMenu();
        mRemoveHeader = newRequestProcessingMenuItem(L.get("remove_header"), Config.KEY_ENABLE_REMOVE_HEADER);
        mReplaceHeader = newRequestProcessingMenuItem(L.get("replace_header"), Config.KEY_ENABLE_REPLACE_HEADER);
        mPayloadProcessing = newRequestProcessingMenuItem(L.get("databoard_payload_processing"),
                Config.KEY_ENABLE_PAYLOAD_PROCESSING);
        mRequestProcessingMenu.add(mRemoveHeader);
        mRequestProcessingMenu.add(mReplaceHeader);
        mRequestProcessingMenu.add(mPayloadProcessing);
    }

    private JCheckBoxMenuItem newRequestProcessingMenuItem(String text, String configKey) {
        JCheckBoxMenuItem item = new JCheckBoxMenuItem(text, Config.getBoolean(configKey));
        item.addActionListener(e -> {
            boolean configSelected = Config.getBoolean(configKey);
            boolean selected = item.isSelected();
            if (selected != configSelected) {
                Config.put(configKey, String.valueOf(selected));
            }
        });
        return item;
    }

    private void showRequestProcessingMenu(Component anchor) {
        if (mRequestProcessingMenu != null) {
            mRequestProcessingMenu.show(anchor, 0, anchor.getHeight());
        }
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        switch (e.getActionCommand()) {
            case "import-url":
                importUrl();
                break;
            case "stop-task":
                stopTask();
                break;
            case "continue-task":
                continueTask();
                break;
            case "clear-all-task":
                clearAllTask();
                break;
            case "clear-history":
                clearHistory();
                break;
            case "filter-data":
                showSetupFilterDialog();
                break;
            case "data-processing-menu":
                showDataProcessingMenu((Component) e.getSource());
                break;
            case "export-stored-data":
                exportStoredData();
                break;
            case "import-stored-data":
                importStoredData();
                break;
            case "save-stored-data":
                saveStoredData(true);
                break;
        }
    }

    private void showDataProcessingMenu(Component anchor) {
        JPopupMenu menu = new JPopupMenu();
        addDataProcessingMenuItem(menu, L.get("save"), L.get("save_stored_data"), "save-stored-data");
        addDataProcessingMenuItem(menu, L.get("import_data_short"), L.get("import_stored_data"), "import-stored-data");
        addDataProcessingMenuItem(menu, L.get("export_data_short"), L.get("export_stored_data"), "export-stored-data");
        menu.show(anchor, 0, anchor.getHeight());
    }

    private void addDataProcessingMenuItem(JPopupMenu menu, String text, String tooltip, String actionCommand) {
        JMenuItem item = new JMenuItem(text);
        item.setToolTipText(tooltip);
        item.setActionCommand(actionCommand);
        item.addActionListener(this);
        menu.add(item);
    }

    private void importUrl() {
        if (mImportUrlWindow == null) {
            mImportUrlWindow = new ImportUrlWindow();
            mImportUrlWindow.setOnImportUrlListener(this);
        }
        mImportUrlWindow.showWindow();
    }

    public void closeImportUrlWindow() {
        if (mImportUrlWindow != null) {
            mImportUrlWindow.closeWindow();
        }
    }

    @Override
    public void onImportUrl(List<String> data, RequestMode requestMode) {
        if (data == null || data.isEmpty()) {
            return;
        }
        sendTabEvent(EVENT_IMPORT_URL, data, requestMode);
    }

    @Override
    public void onFpColumnModify() {
        for (TaskTable table : getTaskTables()) {
            table.refreshColumns();
        }
    }

    private void stopTask() {
        RequestScope scope = getTaskControlScope();
        if (scope == RequestScope.ALL || scope == RequestScope.BURP) {
            if (mListenProxyMessage != null) {
                mListenProxyMessageBeforePause = mListenProxyMessage.isSelected();
                mListenProxyMessage.setSelected(false);
            }
        }
        sendTabEvent(EVENT_STOP_TASK, scope);
        forEachTableByScope(scope, TaskTable::stopAddTaskData);
    }

    private void continueTask() {
        RequestScope scope = getTaskControlScope();
        if ((scope == RequestScope.ALL || scope == RequestScope.BURP)
                && mListenProxyMessageBeforePause != null
                && mListenProxyMessage != null) {
            mListenProxyMessage.setSelected(mListenProxyMessageBeforePause);
            mListenProxyMessageBeforePause = null;
        }
        sendTabEvent(EVENT_CONTINUE_TASK, scope);
        forEachTableByScope(scope, TaskTable::startAddTaskData);
    }

    private void clearAllTask() {
        int ret = UIHelper.showOkCancelDialog(L.get("clear_all_task"), L.get("clear_all_task_confirm"));
        if (ret != JOptionPane.OK_OPTION) {
            return;
        }
        // 恢复监听代理复选框状态（停止时可能被临时关闭）
        if (mListenProxyMessageBeforePause != null && mListenProxyMessage != null) {
            mListenProxyMessage.setSelected(mListenProxyMessageBeforePause);
            mListenProxyMessageBeforePause = null;
        }
        // 通知扩展端清空并丢弃所有正在执行和排队中的任务
        sendTabEvent(EVENT_CLEAR_ALL_TASK);
        // 恢复 UI 表格的任务加载（停止时可能被暂停）
        forEachTableByScope(RequestScope.ALL, TaskTable::startAddTaskData);
    }

    private RequestScope getTaskControlScope() {
        if (mTaskControlScope == null || !(mTaskControlScope.getSelectedItem() instanceof RequestScopeItem item)) {
            return RequestScope.ALL;
        }
        return item.value;
    }

    private void clearHistory() {
        TaskTable table = getTaskTable();
        if (table == null) {
            return;
        }
        table.clearAll();
        refreshTaskHistoryStatus();
    }

    private void saveStoredData(boolean showTips) {
        try {
            TaskSnapshot snapshot = getPersistSnapshot(showTips);
            if (!showTips && snapshot.version() == mLastAutoSavedVersion) {
                return;
            }
            if (!showTips && snapshot.version() == mLastAutoSaveQueuedVersion) {
                return;
            }
            List<TaskData> items = snapshot.items();
            if (items.isEmpty()) {
                if (showTips) {
                    UIHelper.showTipsDialog(L.get("data_persistence_no_current_data"));
                }
                return;
            }
            if (!showTips) {
                mLastAutoSaveQueuedVersion = snapshot.version();
            }
            Runnable task = () -> {
                try {
                    TaskPersistenceManager.SaveResult result = TaskPersistenceManager.persistSnapshot(items);
                    if (showTips) {
                        SwingUtilities.invokeLater(() -> showSaveResult(result));
                    } else {
                        mLastAutoSavedVersion = snapshot.version();
                        mLastAutoSaveQueuedVersion = snapshot.version();
                    }
                } catch (Exception ex) {
                    if (!showTips) {
                        mLastAutoSaveQueuedVersion = mLastAutoSavedVersion;
                    }
                    if (showTips) {
                        SwingUtilities.invokeLater(() -> UIHelper.showTipsDialog(L.get("error_hint", ex.getMessage())));
                    }
                }
            };
            mSaveExecutor.execute(task);
        } catch (Exception ex) {
            if (showTips) {
                UIHelper.showTipsDialog(L.get("error_hint", ex.getMessage()));
            }
        }
    }

    private void showSaveResult(TaskPersistenceManager.SaveResult result) {
        if (result.count() <= 0) {
            UIHelper.showTipsDialog(L.get("data_persistence_disabled_hint"));
        } else {
            UIHelper.showTipsDialog(L.get("save_stored_data_success", result.label(), result.count()));
        }
    }

    private void exportStoredData() {
        TaskFieldSelectionPanel fieldPanel = new TaskFieldSelectionPanel(TaskPersistenceManager.getConfiguredFieldKeys());
        JScrollPane scrollPane = new JScrollPane(fieldPanel);
        scrollPane.setPreferredSize(new Dimension(420, 220));
        int ret = JOptionPane.showConfirmDialog(this, scrollPane, L.get("export_stored_data"),
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (ret != JOptionPane.OK_OPTION) {
            return;
        }
        String defaultPath = new File(Config.getWorkDir(), "onescan-export.csv").getAbsolutePath();
        String selectedPath = UIHelper.selectFileDialog(L.get("select_a_file"), defaultPath);
        if (selectedPath == null || selectedPath.isEmpty()) {
            return;
        }
        try {
            int count = TaskPersistenceManager.exportCsv(new File(selectedPath), fieldPanel.getSelectedFieldKeys());
            UIHelper.showTipsDialog(L.get("export_stored_data_success", count, selectedPath));
        } catch (Exception ex) {
            UIHelper.showTipsDialog(L.get("error_hint", ex.getMessage()));
        }
    }

    private void importStoredData() {
        TaskTable table = getTaskTable();
        if (table == null) {
            return;
        }
        try {
            List<TaskPersistenceManager.HistoryLabel> labels = TaskPersistenceManager.listLabels();
            if (labels.isEmpty()) {
                UIHelper.showTipsDialog(L.get("data_persistence_no_history"));
                return;
            }
            JComboBox<TaskPersistenceManager.HistoryLabel> labelBox = new JComboBox<>(
                    labels.toArray(new TaskPersistenceManager.HistoryLabel[0]));
            JPanel panel = new JPanel(new BorderLayout(5, 5));
            panel.add(new JLabel(L.get("select_data_label")), BorderLayout.NORTH);
            panel.add(labelBox, BorderLayout.CENTER);
            int ret = JOptionPane.showConfirmDialog(this, panel, L.get("import_stored_data"),
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
            if (ret != JOptionPane.OK_OPTION) {
                return;
            }
            TaskPersistenceManager.HistoryLabel selected =
                    (TaskPersistenceManager.HistoryLabel) labelBox.getSelectedItem();
            if (selected == null) {
                return;
            }
            List<TaskData> items = TaskPersistenceManager.loadTaskDataByLabel(selected.label());
            table.loadTaskData(items);
            refreshTaskHistoryStatus();
            UIHelper.showTipsDialog(L.get("import_stored_data_success", selected.label(), items.size()));
        } catch (Exception ex) {
            UIHelper.showTipsDialog(L.get("error_hint", ex.getMessage()));
        }
    }

    public void addTaskData(TaskData data, RequestMode requestMode) {
        TaskTable table = requestMode == RequestMode.BROWSER ? mBrowserTaskTable : mBurpTaskTable;
        if (table != null) {
            table.addTaskData(data);
        }
    }

    public TaskTable getTaskTable() {
        if (mTaskTabbedPane != null && mTaskTabbedPane.getSelectedIndex() == 1) {
            return mBrowserTaskTable;
        }
        return mBurpTaskTable;
    }

    private TaskSnapshot getPersistSnapshot(boolean currentTableOnly) {
        if (currentTableOnly) {
            TaskTable table = getTaskTable();
            if (table == null) {
                return new TaskSnapshot(new ArrayList<>(), -1L);
            }
            TaskTable.TaskSnapshot snapshot = table.getTaskSnapshot();
            return new TaskSnapshot(snapshot.items(), snapshot.version());
        }
        ArrayList<TaskData> items = new ArrayList<>();
        long version = 0L;
        for (TaskTable table : getTaskTables()) {
            TaskTable.TaskSnapshot snapshot = table.getTaskSnapshot();
            items.addAll(snapshot.items());
            version = 31L * version + snapshot.version();
        }
        return new TaskSnapshot(items, version);
    }

    public TaskTable getBurpTaskTable() {
        return mBurpTaskTable;
    }

    public TaskTable getBrowserTaskTable() {
        return mBrowserTaskTable;
    }

    public List<TaskTable> getTaskTables() {
        ArrayList<TaskTable> tables = new ArrayList<>();
        if (mBurpTaskTable != null) {
            tables.add(mBurpTaskTable);
        }
        if (mBrowserTaskTable != null) {
            tables.add(mBrowserTaskTable);
        }
        return tables;
    }

    private void forEachTableByScope(RequestScope scope, TableAction action) {
        if (action == null) {
            return;
        }
        if ((scope == null || scope == RequestScope.ALL || scope == RequestScope.BURP) && mBurpTaskTable != null) {
            action.accept(mBurpTaskTable);
        }
        if ((scope == null || scope == RequestScope.ALL || scope == RequestScope.BROWSER) && mBrowserTaskTable != null) {
            action.accept(mBrowserTaskTable);
        }
    }

    private void setRowFilterForAll(ArrayList<TableFilter<AbstractTableModel>> filters) {
        for (TaskTable table : getTaskTables()) {
            table.setRowFilter(filters);
        }
    }

    public boolean hasListenProxyMessage() {
        return mListenProxyMessage != null && mListenProxyMessage.isSelected();
    }

    public boolean hasRemoveHeader() {
        return mRemoveHeader != null && mRemoveHeader.isSelected();
    }

    public boolean hasReplaceHeader() {
        return mReplaceHeader != null && mReplaceHeader.isSelected();
    }

    public boolean hasDirScan() {
        return mDirScan != null && mDirScan.isSelected();
    }

    public boolean hasPayloadProcessing() {
        return mPayloadProcessing != null && mPayloadProcessing.isSelected();
    }

    public void refreshTaskStatus(int over, int commit) {
        if (mTaskStatus != null) {
            mTaskStatus.setText(L.get("status_bar_task", over, commit));
        }
    }

    public void refreshLFTaskStatus(int over, int commit) {
        if (mLFTaskStatus != null) {
            mLFTaskStatus.setText(L.get("status_bar_low_frequency_task", over, commit));
        }
    }

    public void refreshTaskHistoryStatus() {
        if (mTaskHistoryStatus == null) {
            return;
        }
        int count = 0;
        for (TaskTable table : getTaskTables()) {
            count += table.getTaskCount();
        }
        mTaskHistoryStatus.setText(L.get("status_bar_task_history", count));
    }

    public void refreshFpCacheStatus() {
        if (mFpCacheStatus != null) {
            mFpCacheStatus.setText(L.get("status_bar_fingerprint_cache", FpManager.getCacheCount()));
        }
    }

    public void refreshAutoSaveTimer() {
        int interval = TaskPersistenceManager.getAutoSaveIntervalSeconds();
        if (!TaskPersistenceManager.isEnabled() || interval <= 0) {
            stopAutoSaveTimer();
            return;
        }
        int delay = interval * 1000;
        if (mAutoSaveTimer != null && mAutoSaveTimer.getDelay() == delay) {
            if (!mAutoSaveTimer.isRunning()) {
                mAutoSaveTimer.start();
            }
            return;
        }
        stopAutoSaveTimer();
        mAutoSaveTimer = new Timer(delay, e -> saveStoredData(false));
        mAutoSaveTimer.setInitialDelay(delay);
        mAutoSaveTimer.start();
    }

    public void closeAutoSaveTimer() {
        stopAutoSaveTimer();
    }

    private void stopAutoSaveTimer() {
        if (mAutoSaveTimer != null) {
            mAutoSaveTimer.stop();
            mAutoSaveTimer = null;
        }
    }

    public void closeDataSaveExecutor() {
        mSaveExecutor.shutdownNow();
    }

    private void showSetupFilterDialog() {
        TableFilterPanel panel = new TableFilterPanel(TaskTable.getColumnNames(), mLastFilters);
        panel.showDialog(new DialogCallbackAdapter() {

            @Override
            public void onConfirm(ArrayList<FilterRule> filterRules,
                                  ArrayList<TableFilter<AbstractTableModel>> filters,
                                  String rulesText) {
                setRowFilterForAll(filters);
                mFilterRuleText.setText(rulesText);
                mLastFilters = filterRules;
                Config.put(Config.KEY_DATABOARD_FILTER_RULES, filterRules);
            }

            @Override
            public void onReset() {
                setRowFilterForAll(null);
                mFilterRuleText.setText("");
                mLastFilters = null;
                Config.put(Config.KEY_DATABOARD_FILTER_RULES, new ArrayList<>());
            }
        });
    }

    private interface TableAction {
        void accept(TaskTable table);
    }

    private record TaskSnapshot(List<TaskData> items, long version) {
    }

    private static class RequestScopeItem {

        private final String label;
        private final RequestScope value;

        private RequestScopeItem(String label, RequestScope value) {
            this.label = label;
            this.value = value;
        }

        @Override
        public String toString() {
            return label;
        }
    }
}
