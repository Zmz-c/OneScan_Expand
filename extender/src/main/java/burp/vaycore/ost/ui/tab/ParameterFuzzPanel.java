package burp.vaycore.ost.ui.tab;

import burp.IHttpRequestResponse;
import burp.IBurpExtenderCallbacks;
import burp.vaycore.ost.bean.TaskData;
import burp.vaycore.ost.browser.BrowserRequest;
import burp.vaycore.ost.common.L;
import burp.vaycore.ost.common.ParameterFuzzRequestBuilder;
import burp.vaycore.ost.common.RequestMode;
import burp.vaycore.ost.manager.WordlistManager;
import burp.vaycore.ost.ui.widget.HttpMessageView;
import burp.vaycore.ost.ui.widget.TaskTable;
import burp.vaycore.ost.ui.tab.ParameterFuzzScanOptions.Mode;
import burp.vaycore.ost.ui.tab.ParameterFuzzScanOptions.TargetOptions;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.concurrent.Executor;

/** Endpoint-scoped parameter scan UI; all probe data comes from OST dictionaries. */
public class ParameterFuzzPanel extends JPanel {

    private final DefaultListModel<String> mTargetModel = new DefaultListModel<>();
    private final JList<String> mTargetList = new JList<>(mTargetModel);
    private final JComboBox<String> mMode = new JComboBox<String>(new String[]{
            L.get("parameter_fuzz.mode.names"), L.get("parameter_fuzz.mode.values"),
            L.get("parameter_fuzz.mode.positions")
    });
    private final JComboBox<String> mNameDictionary = new JComboBox<>();
    private final JComboBox<String> mValueDictionary = new JComboBox<>();
    private final JLabel mNameDictionaryLabel = new JLabel(L.get("parameter_fuzz.name_dictionary"));
    private final JCheckBox mGetMethod = new JCheckBox(L.get("parameter_fuzz.method.get"), true);
    private final JCheckBox mPostMethod = new JCheckBox(L.get("parameter_fuzz.method.post"), true);
    private final JTextArea mRequestTemplate = new JTextArea(10, 60);
    private final DefaultTableModel mPositionModel = new DefaultTableModel(
            new Object[]{L.get("parameter_fuzz.position"), L.get("parameter_fuzz.dictionary")}, 0) {
        @Override public boolean isCellEditable(int row, int column) { return column == 1; }
    };
    private final JTable mPositionTable = new JTable(mPositionModel);
    private final List<Map<String, String>> mPositionDictionaries = new ArrayList<>();
    private final List<Map<String, String>> mPositionOriginals = new ArrayList<>();
    private boolean mSyncingPositions;
    private boolean mPositionSyncQueued;
    private boolean mUpdatingTargets;
    private boolean mLoadingSettings;
    private final List<TargetSettings> mTargetSettings = new ArrayList<>();

    private record TargetSettings(Mode mode, String nameDictionary, String valueDictionary,
                                  boolean scanGet, boolean scanPost, boolean onlyExistingRoutes,
                                  boolean useBrowser) { }
    private JPanel mDictionaryRow;
    private JPanel mPositionPanel;
    private JSplitPane mContentSplit;
    private final JTabbedPane mWorkspaceTabs = new JTabbedPane();
    private final TaskTable mTrafficTable = new TaskTable();
    private final JPanel mTrafficDetails = new JPanel(new BorderLayout());
    private final JLabel mTrafficCount = new JLabel();
    private final JButton mStart = new JButton(L.get("parameter_fuzz.start"));
    private HttpMessageView mTrafficMessageView;
    private volatile boolean mScanRunning;
    private final List<String> mRequestDrafts = new ArrayList<>();
    private final List<Charset> mRequestCharsets = new ArrayList<>();
    private int mEditingTarget = -1;
    private final JCheckBox mOnlyExistingRoutes = new JCheckBox(L.get("parameter_fuzz.route_filter"), true);
    private final JCheckBox mUseBrowser = new JCheckBox(L.get("parameter_fuzz.use_browser"), false);
    private final JLabel mBrowserId = new JLabel(L.get("parameter_fuzz.browser_id_none"));
    private final JLabel mStatus = new JLabel(L.get("parameter_fuzz.status_empty"));
    private final JProgressBar mProgressBar = new JProgressBar(0, 1000);
    private final DefaultTableModel mResultModel = new DefaultTableModel(
            new Object[]{L.get("parameter_fuzz.result.route"), L.get("parameter_fuzz.result.location"),
                    L.get("parameter_fuzz.result.parameter"), L.get("parameter_fuzz.result.probe"),
                    L.get("parameter_fuzz.result.outcome")}, 0) {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };

    private final List<TaskData> mTargets = new ArrayList<>();
    private final List<Boolean> mTargetBrowserSources = new ArrayList<>();
    private String mScanBrowserId = "";
    private Consumer<ParameterFuzzScanOptions> mScanHandler;
    private final Timer mDictionaryRefreshTimer;

    public ParameterFuzzPanel() {
        setLayout(new BorderLayout(8, 8));
        setBorder(new EmptyBorder(8, 8, 6, 8));
        populateDictionaries();
        add(buildConfigurationPanel(), BorderLayout.NORTH);
        mPositionPanel = buildPositionPanel();
        mContentSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, mPositionPanel, buildResultPanel());
        mContentSplit.setResizeWeight(0.7);
        mWorkspaceTabs.addTab(L.get("parameter_fuzz.request_preview"), mContentSplit);
        mWorkspaceTabs.addTab(L.get("parameter_fuzz.traffic"), buildTrafficPanel());
        add(mWorkspaceTabs, BorderLayout.CENTER);
        add(buildStatusPanel(), BorderLayout.SOUTH);

        mTargetList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        mTargetList.addListSelectionListener(e -> {
            if (!mUpdatingTargets && !mLoadingSettings && !e.getValueIsAdjusting()) {
                selectTarget(mTargetList.getSelectedIndex());
            }
        });
        mRequestTemplate.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        mRequestTemplate.setToolTipText(L.get("parameter_fuzz.template_tooltip"));
        mRequestTemplate.addCaretListener(e -> mPositionTable.clearSelection());
        mRequestTemplate.getDocument().addDocumentListener(new DocumentListener() {
            private void changed() {
                if (mPositionSyncQueued) return;
                mPositionSyncQueued = true;
                SwingUtilities.invokeLater(() -> {
                    mPositionSyncQueued = false;
                    syncPositionRows();
                });
            }
            @Override public void insertUpdate(DocumentEvent e) { changed(); }
            @Override public void removeUpdate(DocumentEvent e) { changed(); }
            @Override public void changedUpdate(DocumentEvent e) { changed(); }
        });
        mPositionModel.addTableModelListener(e -> {
            if (!mSyncingPositions && mEditingTarget >= 0 && e.getColumn() == 1 && e.getFirstRow() >= 0) {
                int row = e.getFirstRow();
                String marker = (String) mPositionModel.getValueAt(row, 0);
                mPositionDictionaries.get(mEditingTarget).put(marker.substring(1, marker.length() - 1),
                        (String) mPositionModel.getValueAt(row, 1));
            }
        });
        mMode.addActionListener(e -> { updateModeControls(); saveTargetSettings(); });
        mNameDictionary.addActionListener(e -> saveTargetSettings());
        mValueDictionary.addActionListener(e -> saveTargetSettings());
        mGetMethod.addActionListener(e -> saveTargetSettings());
        mPostMethod.addActionListener(e -> saveTargetSettings());
        mOnlyExistingRoutes.addActionListener(e -> saveTargetSettings());
        mUseBrowser.addActionListener(e -> { updateBrowserId(); saveTargetSettings(); });
        mDictionaryRefreshTimer = new Timer(1000, e -> populateDictionaries());
        mProgressBar.setStringPainted(true);
        mProgressBar.setString("");
        updateModeControls();
        updateTargets(List.of(), false);
    }

    @Override
    public void addNotify() {
        super.addNotify();
        populateDictionaries();
        mDictionaryRefreshTimer.start();
    }

    @Override
    public void removeNotify() {
        mDictionaryRefreshTimer.stop();
        super.removeNotify();
    }

    private void populateDictionaries() {
        List<String> dictionaries = WordlistManager.getItemList(WordlistManager.KEY_PAYLOAD);
        if (dictionaries.equals(comboItems(mNameDictionary))
                && dictionaries.equals(comboItems(mValueDictionary))) {
            return;
        }
        commitPositionEdit();
        String selectedNameDictionary = (String) mNameDictionary.getSelectedItem();
        String selectedValueDictionary = (String) mValueDictionary.getSelectedItem();
        boolean wasLoading = mLoadingSettings;
        mLoadingSettings = true;
        try {
            mNameDictionary.setModel(new DefaultComboBoxModel<>(new Vector<>(dictionaries)));
            mValueDictionary.setModel(new DefaultComboBoxModel<>(new Vector<>(dictionaries)));
            String fallback = WordlistManager.getItem(WordlistManager.KEY_PAYLOAD);
            // Keep missing selections visible; never silently scan with a different dictionary.
            mNameDictionary.getModel().setSelectedItem(selectedNameDictionary == null ? fallback : selectedNameDictionary);
            mValueDictionary.getModel().setSelectedItem(selectedValueDictionary == null ? fallback : selectedValueDictionary);
            mPositionTable.getColumnModel().getColumn(1).setCellEditor(new DefaultCellEditor(
                    new JComboBox<>(new Vector<>(dictionaries))));
        } finally { mLoadingSettings = wasLoading; }
    }

    private List<String> comboItems(JComboBox<String> combo) {
        List<String> result = new ArrayList<>();
        for (int index = 0; index < combo.getItemCount(); index++) {
            result.add(combo.getItemAt(index));
        }
        return result;
    }

    private JPanel buildConfigurationPanel() {
        JPanel targets = new JPanel(new BorderLayout(4, 4));
        targets.setBorder(new TitledBorder(L.get("parameter_fuzz.targets")));
        targets.setPreferredSize(new Dimension(300, 155));
        targets.add(new JScrollPane(mTargetList), BorderLayout.CENTER);
        JPanel targetActions = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        JButton removeTarget = new JButton(L.get("parameter_fuzz.remove_target"));
        removeTarget.addActionListener(e -> removeTarget());
        JButton clearTargets = new JButton(L.get("parameter_fuzz.clear_targets"));
        clearTargets.addActionListener(e -> clearTargets());
        targetActions.add(removeTarget);
        targetActions.add(clearTargets);
        targets.add(targetActions, BorderLayout.SOUTH);

        JPanel options = new JPanel();
        options.setLayout(new BoxLayout(options, BoxLayout.Y_AXIS));
        options.setBorder(new TitledBorder(L.get("parameter_fuzz.options")));

        JPanel firstRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        firstRow.add(new JLabel(L.get("parameter_fuzz.mode")));
        mMode.setPreferredSize(new Dimension(220, 25));
        firstRow.add(mMode);
        firstRow.add(mGetMethod);
        firstRow.add(mPostMethod);
        firstRow.add(mOnlyExistingRoutes);
        options.add(firstRow);

        JPanel dictionaryRow = mDictionaryRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        dictionaryRow.add(mNameDictionaryLabel);
        mNameDictionary.setPreferredSize(new Dimension(150, 25));
        dictionaryRow.add(mNameDictionary);
        dictionaryRow.add(new JLabel(L.get("parameter_fuzz.value_dictionary")));
        mValueDictionary.setPreferredSize(new Dimension(150, 25));
        dictionaryRow.add(mValueDictionary);
        options.add(dictionaryRow);

        JPanel executionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        executionRow.add(mUseBrowser);
        executionRow.add(mBrowserId);
        options.add(executionRow);

        JButton preview = new JButton(L.get("parameter_fuzz.preview"));
        preview.addActionListener(e -> previewPlan());
        mStart.addActionListener(e -> startScan());
        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));
        JButton applyAll = new JButton(L.get("parameter_fuzz.apply_all"));
        applyAll.addActionListener(e -> applySettingsToAllTargets());
        actionRow.add(applyAll);
        actionRow.add(preview);
        actionRow.add(mStart);
        options.add(actionRow);

        JPanel result = new JPanel(new BorderLayout(8, 0));
        result.add(targets, BorderLayout.WEST);
        result.add(options, BorderLayout.CENTER);
        return result;
    }

    private JPanel buildTrafficPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        JButton clear = new JButton(L.get("parameter_fuzz.clear_traffic"));
        clear.addActionListener(e -> mTrafficTable.clearAll());
        toolbar.add(clear);
        toolbar.add(mTrafficCount);
        mTrafficCount.setText(L.get("parameter_fuzz.traffic_count", 0));
        mTrafficTable.getModel().addTableModelListener(e -> {
            Runnable update = () -> mTrafficCount.setText(L.get("parameter_fuzz.traffic_count", mTrafficTable.getTaskCount()));
            if (SwingUtilities.isEventDispatchThread()) update.run();
            else SwingUtilities.invokeLater(update);
        });
        mTrafficTable.setParameterFuzzRequestedHandler(targets -> {
            updateTargets(targets, targets.stream().allMatch(target -> "browser".equalsIgnoreCase(target.getRequestScope())));
            mWorkspaceTabs.setSelectedIndex(0);
        });
        mTrafficDetails.add(new JLabel(L.get("parameter_fuzz.select_traffic")), BorderLayout.CENTER);
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(mTrafficTable), mTrafficDetails);
        split.setResizeWeight(0.5);
        split.setDividerLocation(180);
        panel.add(toolbar, BorderLayout.NORTH);
        panel.add(split, BorderLayout.CENTER);
        return panel;
    }

    public void initTrafficView(IBurpExtenderCallbacks callbacks, Executor loader,
                                Function<TaskData, IHttpRequestResponse> resolver,
                                TaskTable.OnTaskTableEventListener actions) {
        mTrafficMessageView = new HttpMessageView(callbacks, loader);
        JSplitPane details = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                mTrafficMessageView.requestComponent(), mTrafficMessageView.responseComponent());
        details.setResizeWeight(0.5);
        mTrafficDetails.removeAll();
        mTrafficDetails.add(details, BorderLayout.CENTER);
        mTrafficTable.setOnTaskTableEventListener(new TaskTable.OnTaskTableEventListener() {
            @Override public void onChangeSelection(TaskData data) {
                mTrafficMessageView.showMessage(data == null ? null : resolver.apply(data));
            }
            @Override public void onSendToRepeater(ArrayList<TaskData> items) { actions.onSendToRepeater(items); }
            @Override public byte[] getBodyByTaskData(TaskData data) { return actions.getBodyByTaskData(data); }
            @Override public void addHostToBlocklist(ArrayList<String> hosts) { actions.addHostToBlocklist(hosts); }
        });
        mTrafficDetails.revalidate();
        mTrafficDetails.repaint();
    }

    public TaskTable getTrafficTable() { return mTrafficTable; }

    public IHttpRequestResponse currentMessage() {
        return mTrafficMessageView == null ? null : mTrafficMessageView.currentMessage();
    }

    public void showTraffic() {
        if (SwingUtilities.isEventDispatchThread()) mWorkspaceTabs.setSelectedIndex(1);
        else SwingUtilities.invokeLater(() -> mWorkspaceTabs.setSelectedIndex(1));
    }

    public void setScanRunning(boolean running) {
        mScanRunning = running;
        Runnable update = () -> {
            mStart.setEnabled(!mScanRunning);
            if (!mScanRunning) mProgressBar.setIndeterminate(false);
        };
        if (SwingUtilities.isEventDispatchThread()) update.run();
        else SwingUtilities.invokeLater(update);
    }

    public void close() {
        mDictionaryRefreshTimer.stop();
        if (mTrafficMessageView != null) mTrafficMessageView.showMessage(null);
    }

    private JPanel buildPositionPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.setBorder(new TitledBorder(L.get("parameter_fuzz.custom_template")));
        JButton mark = new JButton(L.get("parameter_fuzz.mark_position"));
        mark.addActionListener(e -> markPosition());
        JButton remove = new JButton(L.get("parameter_fuzz.remove_position"));
        remove.addActionListener(e -> removePosition());
        JButton clear = new JButton(L.get("parameter_fuzz.clear_positions"));
        clear.addActionListener(e -> clearPositions());
        JButton reset = new JButton(L.get("parameter_fuzz.reset_request"));
        reset.addActionListener(e -> {
            if (mEditingTarget >= 0) {
                commitPositionEdit();
                mPositionDictionaries.get(mEditingTarget).clear();
                mPositionOriginals.get(mEditingTarget).clear();
                mSyncingPositions = true;
                try { mPositionModel.setRowCount(0); }
                finally { mSyncingPositions = false; }
                mRequestTemplate.setText(originalRequestText(mEditingTarget));
                mRequestTemplate.setCaretPosition(0);
                syncPositionRows();
            }
        });
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        toolbar.add(mark);
        toolbar.add(remove);
        toolbar.add(clear);
        toolbar.add(reset);
        panel.add(toolbar, BorderLayout.NORTH);
        mPositionTable.getTableHeader().setReorderingAllowed(false);
        mPositionTable.setFillsViewportHeight(true);
        mPositionTable.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);
        JPanel dictionaries = new JPanel(new BorderLayout());
        dictionaries.setBorder(new TitledBorder(L.get("parameter_fuzz.position_dictionaries")));
        dictionaries.add(new JScrollPane(mPositionTable), BorderLayout.CENTER);
        dictionaries.add(new JLabel(L.get("parameter_fuzz.all_combinations")), BorderLayout.SOUTH);
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                new JScrollPane(mRequestTemplate), dictionaries);
        split.setResizeWeight(0.7);
        split.setDividerLocation(0.7);
        dictionaries.setPreferredSize(new Dimension(260, 140));
        panel.add(split, BorderLayout.CENTER);
        return panel;
    }

    private void commitPositionEdit() {
        if (mPositionTable.isEditing()) mPositionTable.getCellEditor().stopCellEditing();
    }

    /** Keep manually typed markers in sync without destroying an in-progress dictionary edit. */
    private void syncPositionRows() {
        List<String> ids = mEditingTarget < 0 ? List.of()
                : ParameterFuzzRequestBuilder.payloadPositionIds(mRequestTemplate.getText());
        boolean sameRows = mPositionModel.getRowCount() == ids.size();
        for (int i = 0; sameRows && i < ids.size(); i++) {
            sameRows = ("$" + ids.get(i) + "$").equals(mPositionModel.getValueAt(i, 0));
        }
        if (sameRows) return;
        commitPositionEdit();
        mSyncingPositions = true;
        try {
            mPositionModel.setRowCount(0);
            if (mEditingTarget < 0) return;
            Map<String, String> dictionaries = mPositionDictionaries.get(mEditingTarget);
            for (String id : ids) {
                if (!dictionaries.containsKey(id)) dictionaries.put(id, (String) mValueDictionary.getSelectedItem());
                mPositionModel.addRow(new Object[]{"$" + id + "$", dictionaries.get(id)});
            }
        } finally {
            mSyncingPositions = false;
        }
    }

    private void markPosition() {
        if (mEditingTarget < 0) return;
        commitPositionEdit();
        String text = mRequestTemplate.getText();
        int start = mRequestTemplate.getSelectionStart(), end = mRequestTemplate.getSelectionEnd();
        // Do not create nested/partial markers when the selection overlaps an existing one.
        var matcher = java.util.regex.Pattern.compile("\\$[1-9][0-9]*\\$").matcher(text);
        while (matcher.find()) {
            if (start < matcher.end() && end > matcher.start()
                    || start == end && start > matcher.start() && start < matcher.end()) return;
        }
        List<String> ids = ParameterFuzzRequestBuilder.payloadPositionIds(text);
        int next = 1;
        while (ids.contains(String.valueOf(next))) next++;
        String id = String.valueOf(next);
        String marker = "$" + id + "$";
        mPositionOriginals.get(mEditingTarget).put(id, text.substring(start, end));
        mPositionDictionaries.get(mEditingTarget).put(id, (String) mValueDictionary.getSelectedItem());
        mRequestTemplate.replaceSelection(marker);
        syncPositionRows();
        for (int row = 0; row < mPositionModel.getRowCount(); row++) {
            if (marker.equals(mPositionModel.getValueAt(row, 0))) mPositionTable.setRowSelectionInterval(row, row);
        }
        mRequestTemplate.setCaretPosition(start + marker.length());
        mRequestTemplate.requestFocusInWindow();
    }

    private void removePosition() {
        if (mEditingTarget < 0) return;
        commitPositionEdit();
        syncPositionRows();
        Map<String, String> replacements = new LinkedHashMap<>();
        for (int row : mPositionTable.getSelectedRows()) {
            String marker = (String) mPositionModel.getValueAt(row, 0);
            String id = marker.substring(1, marker.length() - 1);
            replacements.put(id, mPositionOriginals.get(mEditingTarget).getOrDefault(id, ""));
        }
        if (replacements.isEmpty()) {
            var matcher = java.util.regex.Pattern.compile("\\$([1-9][0-9]*)\\$").matcher(mRequestTemplate.getText());
            int start = mRequestTemplate.getSelectionStart(), end = mRequestTemplate.getSelectionEnd();
            while (matcher.find()) {
                boolean selected = start == end ? start >= matcher.start() && start <= matcher.end()
                        : start < matcher.end() && end > matcher.start();
                if (selected) {
                    String id = matcher.group(1);
                    replacements.put(id, mPositionOriginals.get(mEditingTarget).getOrDefault(id, ""));
                    if (start == end) break;
                }
            }
        }
        removePositions(replacements);
    }

    private void clearPositions() {
        if (mEditingTarget < 0) return;
        commitPositionEdit();
        Map<String, String> replacements = new LinkedHashMap<>();
        for (String id : ParameterFuzzRequestBuilder.payloadPositionIds(mRequestTemplate.getText())) {
            replacements.put(id, mPositionOriginals.get(mEditingTarget).getOrDefault(id, ""));
        }
        removePositions(replacements);
    }

    private void removePositions(Map<String, String> replacements) {
        if (replacements.isEmpty()) return;
        String text = ParameterFuzzRequestBuilder.replacePositionText(mRequestTemplate.getText(), replacements);
        replacements.keySet().forEach(id -> {
            mPositionDictionaries.get(mEditingTarget).remove(id);
            mPositionOriginals.get(mEditingTarget).remove(id);
        });
        mRequestTemplate.setText(text);
        syncPositionRows();
    }

    private void saveRequestDraft() {
        saveTargetSettings();
        commitPositionEdit();
        syncPositionRows();
        if (mEditingTarget >= 0 && mEditingTarget < mRequestDrafts.size()) {
            mRequestDrafts.set(mEditingTarget, mRequestTemplate.getText());
        }
    }

    private void selectTarget(int index) {
        saveRequestDraft();
        mEditingTarget = index;
        if (index >= 0) loadTargetSettings(mTargetSettings.get(index));
        // Identical marker IDs on two URLs still need distinct table contents.
        mSyncingPositions = true;
        try { mPositionModel.setRowCount(0); }
        finally { mSyncingPositions = false; }
        mRequestTemplate.setText(index < 0 ? "" : mRequestDrafts.get(index));
        mRequestTemplate.setEditable(index >= 0);
        mRequestTemplate.setCaretPosition(0);
        syncPositionRows();
    }

    private TargetSettings readTargetSettings() {
        return new TargetSettings(Mode.values()[mMode.getSelectedIndex()],
                (String) mNameDictionary.getSelectedItem(), (String) mValueDictionary.getSelectedItem(),
                mGetMethod.isSelected(), mPostMethod.isSelected(), mOnlyExistingRoutes.isSelected(), mUseBrowser.isSelected());
    }

    private void saveTargetSettings() {
        if (mLoadingSettings || mEditingTarget < 0 || mEditingTarget >= mTargetSettings.size()) return;
        mTargetSettings.set(mEditingTarget, readTargetSettings());
        updateTargetLabel(mEditingTarget);
    }

    private void loadTargetSettings(TargetSettings settings) {
        mLoadingSettings = true;
        try {
            mMode.setSelectedIndex(settings.mode().ordinal());
            mNameDictionary.getModel().setSelectedItem(settings.nameDictionary());
            mValueDictionary.getModel().setSelectedItem(settings.valueDictionary());
            mGetMethod.setSelected(settings.scanGet());
            mPostMethod.setSelected(settings.scanPost());
            mOnlyExistingRoutes.setSelected(settings.onlyExistingRoutes());
            mUseBrowser.setSelected(settings.useBrowser());
        } finally { mLoadingSettings = false; }
        updateModeControls();
        updateBrowserId();
    }

    private void applySettingsToAllTargets() {
        saveRequestDraft();
        TargetSettings settings = readTargetSettings();
        for (int i = 0; i < mTargetSettings.size(); i++) {
            mTargetSettings.set(i, settings);
            updateTargetLabel(i);
        }
        // Request drafts and per-position dictionaries are intentionally endpoint-local.
        targetsChanged();
    }

    private String modeLabel(Mode mode) {
        return L.get(switch (mode) {
            case NAMES -> "parameter_fuzz.mode.names";
            case VALUES -> "parameter_fuzz.mode.values";
            case POSITIONS -> "parameter_fuzz.mode.positions";
        });
    }

    private void updateTargetLabel(int index) {
        TaskData target = mTargets.get(index);
        TargetSettings settings = mTargetSettings.get(index);
        String label = modeLabel(settings.mode()) + " | " + (settings.useBrowser() ? "Browser" : "HTTP") + " | "
                + target.getMethod() + " " + target.getHost() + target.getUrl();
        if (label.equals(mTargetModel.get(index))) return;
        boolean wasLoading = mLoadingSettings;
        mLoadingSettings = true;
        try { mTargetModel.set(index, label); }
        finally { mLoadingSettings = wasLoading; }
    }

    private byte[] originalRequest(TaskData target) {
        byte[] request = target.getReqBytes();
        if ((request == null || request.length == 0) && target.getReqResp() instanceof IHttpRequestResponse message) {
            request = message.getRequest();
        }
        return request == null ? new byte[0] : request;
    }

    private String originalRequestText(int index) {
        return new String(originalRequest(mTargets.get(index)), mRequestCharsets.get(index));
    }

    private JPanel buildResultPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.setBorder(new TitledBorder(L.get("parameter_fuzz.results")));
        JTable resultTable = new JTable(mResultModel);
        resultTable.setFillsViewportHeight(true);
        resultTable.getTableHeader().setReorderingAllowed(false);
        panel.add(new JScrollPane(resultTable), BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildStatusPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 4));
        panel.setBorder(new EmptyBorder(2, 2, 0, 2));
        panel.add(mProgressBar, BorderLayout.NORTH);
        panel.add(mStatus, BorderLayout.CENTER);
        return panel;
    }

    public void setScanHandler(Consumer<ParameterFuzzScanOptions> handler) {
        mScanHandler = handler;
    }

    public void updateTargets(List<TaskData> targets, boolean browserSource) {
        saveRequestDraft();
        TargetSettings defaults = readTargetSettings();
        Map<String, TaskData> unique = new LinkedHashMap<>();
        for (int i = 0; i < mTargets.size(); i++) {
            unique.put(targetKey(mTargets.get(i), mTargetBrowserSources.get(i)), mTargets.get(i));
        }
        int firstBrowserTarget = -1;
        if (targets != null) {
            for (TaskData target : targets) {
                if (target == null) continue;
                boolean isBrowserSource = browserSource || "browser".equalsIgnoreCase(target.getRequestScope());
                String key = targetKey(target, isBrowserSource);
                if (unique.containsKey(key)) {
                    if (browserSource && firstBrowserTarget < 0) {
                        for (int i = 0; i < mTargets.size(); i++) {
                            if (key.equals(targetKey(mTargets.get(i), mTargetBrowserSources.get(i)))) {
                                firstBrowserTarget = i;
                                break;
                            }
                        }
                    }
                    continue;
                }
                unique.put(key, target);
                if (browserSource && firstBrowserTarget < 0) firstBrowserTarget = mTargets.size();
                byte[] request = originalRequest(target);
                Charset charset = StandardCharsets.UTF_8;
                try {
                    charset.newDecoder().decode(ByteBuffer.wrap(request));
                } catch (CharacterCodingException e) {
                    charset = StandardCharsets.ISO_8859_1;
                }
                mTargets.add(target);
                mTargetBrowserSources.add(isBrowserSource);
                mRequestCharsets.add(charset);
                mRequestDrafts.add(new String(request, charset));
                mPositionDictionaries.add(new LinkedHashMap<>());
                mPositionOriginals.add(new LinkedHashMap<>());
                mTargetSettings.add(new TargetSettings(defaults.mode(), defaults.nameDictionary(), defaults.valueDictionary(),
                        defaults.scanGet(), defaults.scanPost(), defaults.onlyExistingRoutes(),
                        isBrowserSource));
                mTargetModel.addElement("");
                updateTargetLabel(mTargets.size() - 1);
            }
        }
        if (firstBrowserTarget >= 0) mTargetList.setSelectedIndex(firstBrowserTarget);
        else if (mTargetList.getSelectedIndex() < 0 && !mTargets.isEmpty()) mTargetList.setSelectedIndex(0);
        targetsChanged();
        updateBrowserId();
    }

    private String targetKey(TaskData target, boolean browserSource) {
        return (browserSource ? "browser\n" : "burp\n") + String.valueOf(target.getMethod()).toUpperCase(java.util.Locale.ROOT) + "\n"
                + target.getHost() + "\n" + target.getUrl();
    }

    private void removeTarget() {
        int index = mTargetList.getSelectedIndex();
        if (index < 0) return;
        saveRequestDraft();
        mUpdatingTargets = true;
        mEditingTarget = -1;
        try {
            mTargets.remove(index);
            mTargetBrowserSources.remove(index);
            mRequestDrafts.remove(index);
            mRequestCharsets.remove(index);
            mPositionDictionaries.remove(index);
            mPositionOriginals.remove(index);
            mTargetSettings.remove(index);
            mTargetModel.remove(index);
            mTargetList.setSelectedIndex(mTargets.isEmpty() ? -1 : Math.min(index, mTargets.size() - 1));
        } finally { mUpdatingTargets = false; }
        selectTarget(mTargetList.getSelectedIndex());
        targetsChanged();
    }

    private void clearTargets() {
        commitPositionEdit();
        mUpdatingTargets = true;
        mEditingTarget = -1;
        try {
            mTargets.clear();
            mTargetBrowserSources.clear();
            mRequestDrafts.clear();
            mRequestCharsets.clear();
            mPositionDictionaries.clear();
            mPositionOriginals.clear();
            mTargetSettings.clear();
            mTargetModel.clear();
        } finally { mUpdatingTargets = false; }
        selectTarget(-1);
        targetsChanged();
    }

    private void targetsChanged() {
        mResultModel.setRowCount(0);
        if (!mScanRunning) mStatus.setText(L.get("parameter_fuzz.ready_status", mTargets.size()));
    }

    private void updateModeControls() {
        mNameDictionaryLabel.setEnabled(mMode.getSelectedIndex() == 0);
        mNameDictionary.setEnabled(mMode.getSelectedIndex() == 0);
        boolean custom = mMode.getSelectedIndex() == 2;
        mDictionaryRow.setVisible(!custom);
        mPositionPanel.setVisible(custom);
        mContentSplit.setDividerSize(custom ? 5 : 0);
        mContentSplit.setDividerLocation(custom ? 0.7 : 0.0);
        revalidate();
    }

    private void updateBrowserId() {
        if (!mUseBrowser.isSelected()) {
            mBrowserId.setText(L.get("parameter_fuzz.browser_id_none"));
            return;
        }
        if (mScanBrowserId.isEmpty()) {
            mScanBrowserId = BrowserRequest.newParameterFuzzBrowserId();
        }
        mBrowserId.setText(L.get("parameter_fuzz.browser_id", mScanBrowserId));
    }

    private ParameterFuzzScanOptions buildScanOptions() {
        populateDictionaries();
        saveRequestDraft();
        if (mTargets.isEmpty()) {
            setStatus(L.get("parameter_fuzz.no_targets"));
            return null;
        }
        List<TargetOptions> scans = new ArrayList<>();
        Map<String, List<String>> dictionaryCache = new LinkedHashMap<>();
        List<String> availableDictionaries = comboItems(mValueDictionary);
        boolean hasAutomatic = false;
        boolean hasPositions = false;
        for (int i = 0; i < mTargets.size(); i++) {
            TargetSettings settings = mTargetSettings.get(i);
            TaskData target = mTargets.get(i);
            if (!settings.scanGet() && !settings.scanPost()) {
                targetError(i, L.get("parameter_fuzz.plan_missing_options"));
                return null;
            }
            List<String> names = List.of(), values = List.of();
            byte[] template = new byte[0];
            Map<String, List<String>> positions = new LinkedHashMap<>();
            boolean eligible = ParameterFuzzRequestBuilder.isSelectedMethod(target.getMethod(), settings.scanGet(), settings.scanPost())
                    && (!settings.onlyExistingRoutes() || ParameterFuzzRequestBuilder.isExistingRoute(target.getStatus()));
            if (settings.mode() == Mode.POSITIONS) {
                String draft = mRequestDrafts.get(i);
                List<String> ids = ParameterFuzzRequestBuilder.payloadPositionIds(draft);
                hasPositions |= !ids.isEmpty();
                try {
                    if (!ids.isEmpty()) draft = ParameterFuzzRequestBuilder.normalizeRequestTemplate(draft);
                    ByteBuffer encoded = mRequestCharsets.get(i).newEncoder().encode(CharBuffer.wrap(draft));
                    template = new byte[encoded.remaining()];
                    encoded.get(template);
                } catch (IllegalArgumentException | CharacterCodingException e) {
                    targetError(i, L.get("parameter_fuzz.template_invalid"));
                    return null;
                }
                eligible &= ParameterFuzzRequestBuilder.isSelectedMethod(
                        ParameterFuzzRequestBuilder.requestMethod(template), settings.scanGet(), settings.scanPost());
                if (eligible) {
                    Map<String, String> selections = mPositionDictionaries.get(i);
                    for (String id : ids) {
                        if (!selections.containsKey(id)) selections.put(id, settings.valueDictionary());
                        List<String> entries = dictionaryValues(selections.get(id), availableDictionaries, dictionaryCache);
                        if (entries.isEmpty()) {
                            setStatus(L.get("parameter_fuzz.position_dictionary_missing", i + 1, "$" + id + "$"));
                            return null;
                        }
                        positions.put(id, entries);
                    }
                }
            } else {
                hasAutomatic = true;
                if (eligible) {
                    values = dictionaryValues(settings.valueDictionary(), availableDictionaries, dictionaryCache);
                    if (values.isEmpty()) {
                        targetError(i, L.get("parameter_fuzz.no_dictionary_values"));
                        return null;
                    }
                    if (settings.mode() == Mode.NAMES) {
                        names = dictionaryValues(settings.nameDictionary(), availableDictionaries, dictionaryCache).stream()
                                .map(String::trim).filter(name -> !name.isEmpty()).distinct().toList();
                        if (names.isEmpty()) {
                            targetError(i, L.get("parameter_fuzz.no_dictionary_names"));
                            return null;
                        }
                    }
                }
            }
            if (settings.useBrowser() && mScanBrowserId.isEmpty()) mScanBrowserId = BrowserRequest.newParameterFuzzBrowserId();
            scans.add(new TargetOptions(target, settings.mode(), names, values, template, positions,
                    settings.scanGet(), settings.scanPost(), settings.onlyExistingRoutes(),
                    settings.useBrowser() ? RequestMode.BROWSER : RequestMode.BURP,
                    settings.useBrowser() ? mScanBrowserId : ""));
        }
        if (!hasAutomatic && !hasPositions) {
            setStatus(L.get("parameter_fuzz.template_missing_placeholder"));
            return null;
        }
        updateBrowserId();
        return new ParameterFuzzScanOptions(scans);
    }

    private List<String> dictionaryValues(String name, List<String> available, Map<String, List<String>> cache) {
        if (name == null || !available.contains(name)) return List.of();
        return cache.computeIfAbsent(name, key -> WordlistManager.getPayload(key).stream()
                .filter(value -> value != null && !value.isEmpty()).distinct().toList());
    }

    private void targetError(int index, String message) {
        setStatus(L.get("parameter_fuzz.target_error", index + 1, message));
    }

    private void previewPlan() {
        ParameterFuzzScanOptions batch = buildScanOptions();
        if (batch == null) return;
        mWorkspaceTabs.setSelectedIndex(0);
        mResultModel.setRowCount(0);
        long requestCount = 0;
        boolean hasExistingValues = false;
        for (TargetOptions options : batch.scans()) {
            TaskData target = options.target();
            long count = 0;
            Object parameters;
            if (options.customPositions()) {
                byte[] template = options.requestTemplate();
                parameters = ParameterFuzzRequestBuilder.countPayloadPositions(template);
                if (options.eligible()) count = ParameterFuzzRequestBuilder.positionPlan(template, options.positionValues()).count();
            } else {
                parameters = options.discoverParameterNames() ? options.parameterNameCandidates().size()
                        : L.get("parameter_fuzz.existing_parameters");
                if (options.eligible()) {
                    if (options.discoverParameterNames()) {
                        count = (long) options.parameterValues().size() * options.parameterNameCandidates().size()
                                * ("POST".equalsIgnoreCase(target.getMethod()) ? 2 : 1);
                    } else hasExistingValues = true;
                }
            }
            requestCount = requestCount > Long.MAX_VALUE - count ? Long.MAX_VALUE : requestCount + count;
            boolean unknownCount = options.mode() == Mode.VALUES && options.eligible();
            mResultModel.addRow(new Object[]{target.getMethod() + " " + target.getHost() + target.getUrl(),
                    modeLabel(options.mode()), parameters,
                    unknownCount ? L.get("parameter_fuzz.count_existing") : count,
                    L.get(!unknownCount && count == 0 ? "parameter_fuzz.plan_skipped" : "parameter_fuzz.plan_only")});
        }
        boolean onlyCustom = batch.scans().stream().allMatch(TargetOptions::customPositions);
        if (!mScanRunning) setStatus(onlyCustom && requestCount > ParameterFuzzRequestBuilder.MAX_REQUESTS
                ? L.get("parameter_fuzz.scan_limit", ParameterFuzzRequestBuilder.MAX_REQUESTS)
                : hasExistingValues ? L.get("parameter_fuzz.preview_mixed_status", batch.scans().size())
                : L.get("parameter_fuzz.preview_status", batch.scans().size(), requestCount));
    }

    private void startScan() {
        ParameterFuzzScanOptions options = buildScanOptions();
        if (options == null) {
            return;
        }
        if (mScanHandler == null) {
            setStatus(L.get("parameter_fuzz.scan_unavailable"));
            return;
        }
        mScanHandler.accept(options);
    }

    public void setScanStatus(String status) {
        if (SwingUtilities.isEventDispatchThread()) {
            mStatus.setText(status);
        } else {
            SwingUtilities.invokeLater(() -> mStatus.setText(status));
        }
    }

    public void setScanProgress(int completed, int total, String status) {
        Runnable update = () -> {
            int safeTotal = Math.max(0, total);
            int safeCompleted = Math.max(0, Math.min(completed, safeTotal));
            mProgressBar.setIndeterminate(mScanRunning && safeTotal == 0);
            mProgressBar.setMaximum(Math.max(1, safeTotal));
            mProgressBar.setValue(safeCompleted);
            mProgressBar.setString(L.get("parameter_fuzz.progress_bar", safeCompleted, safeTotal));
            mStatus.setText(status);
        };
        if (SwingUtilities.isEventDispatchThread()) {
            update.run();
        } else {
            SwingUtilities.invokeLater(update);
        }
    }

    private void setStatus(String status) {
        mStatus.setText(status);
    }
}
