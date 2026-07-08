package burp.vaycore.onescan.ui.widget;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.onescan.common.L;
import burp.vaycore.onescan.manager.TaskPersistenceManager;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 历史数据管理窗口
 * <p>
 * 支持：一键删除全部、按时间标签删除、按站点删除
 */
public class HistoryManagerWindow {

    private JDialog mDialog;
    private OnDeleteListener mOnDeleteListener;

    /** 打开管理窗口 */
    public void show(Component parent) {
        if (mDialog == null || !mDialog.isDisplayable()) {
            buildDialog(parent);
        }
        loadLabels();
        loadHosts();
        mDialog.setVisible(true);
    }

    public void setOnDeleteListener(OnDeleteListener l) {
        this.mOnDeleteListener = l;
    }

    // ── 内部 UI ──────────────────────────────────────────────

    private DefaultListModel<TaskPersistenceManager.HistoryLabel> mLabelListModel;
    private JList<TaskPersistenceManager.HistoryLabel> mLabelList;

    private DefaultListModel<String> mHostListModel;
    private JList<String> mHostList;
    private JTextField mHostFilterText;

    private JLabel mStatusLabel;

    private void buildDialog(Component parent) {
        Window owner = parent == null ? null : SwingUtilities.getWindowAncestor(parent);
        mDialog = new JDialog(owner, L.get("history_manager.title"), Dialog.ModalityType.APPLICATION_MODAL);
        mDialog.setSize(620, 500);
        mDialog.setLocationRelativeTo(owner);
        mDialog.setDefaultCloseOperation(JDialog.HIDE_ON_CLOSE);
        mDialog.setLayout(new VLayout(5));

        JPanel contentPanel = new JPanel(new VLayout(8));
        contentPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // ─── 一键删除全部 ────────────────────────────────────────
        JPanel deleteAllPanel = buildDeleteAllPanel();
        contentPanel.add(deleteAllPanel);

        // ─── 按时间（标签）删除 ──────────────────────────────────
        JPanel byTimePanel = buildByTimePanel();
        contentPanel.add(byTimePanel, "1w");

        // ─── 按站点删除 ─────────────────────────────────────────
        JPanel bySitePanel = buildBySitePanel();
        contentPanel.add(bySitePanel, "1w");

        // ─── 状态栏 ──────────────────────────────────────────────
        mStatusLabel = new JLabel(" ");
        mStatusLabel.setForeground(new Color(0x0060A0));
        JPanel statusPanel = new JPanel(new HLayout(0));
        statusPanel.add(mStatusLabel, "1w");
        contentPanel.add(statusPanel);

        mDialog.add(contentPanel, "1w");
    }

    private JPanel buildDeleteAllPanel() {
        JPanel panel = new JPanel(new HLayout(8, true));
        panel.setBorder(new TitledBorder(L.get("history_manager.delete_all")));
        panel.setBorder(BorderFactory.createTitledBorder(L.get("history_manager.delete_all")));

        JLabel hint = new JLabel(L.get("history_manager.delete_all_hint"));
        panel.add(hint, "1w");

        JButton deleteAllBtn = new JButton(L.get("history_manager.btn_delete_all"));
        deleteAllBtn.addActionListener(e -> doDeleteAll());
        panel.add(deleteAllBtn);
        return panel;
    }

    private JPanel buildByTimePanel() {
        JPanel panel = new JPanel(new VLayout(5));
        panel.setBorder(BorderFactory.createTitledBorder(L.get("history_manager.by_time")));

        mLabelListModel = new DefaultListModel<>();
        mLabelList = new JList<>(mLabelListModel);
        mLabelList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        JScrollPane scroll = new JScrollPane(mLabelList);
        scroll.setPreferredSize(new Dimension(0, 120));
        panel.add(scroll, "1w");

        JPanel btnPanel = new JPanel(new HLayout(5, true));
        JButton refreshBtn = new JButton(L.get("reload"));
        refreshBtn.addActionListener(e -> loadLabels());
        JButton deleteBtn = new JButton(L.get("history_manager.btn_delete_selected"));
        deleteBtn.addActionListener(e -> doDeleteByLabels());
        btnPanel.add(refreshBtn);
        btnPanel.add(new JPanel(), "1w");
        btnPanel.add(deleteBtn);
        panel.add(btnPanel);
        return panel;
    }

    private JPanel buildBySitePanel() {
        JPanel panel = new JPanel(new VLayout(5));
        panel.setBorder(BorderFactory.createTitledBorder(L.get("history_manager.by_site")));

        // 输入过滤文本
        JPanel filterPanel = new JPanel(new HLayout(5));
        filterPanel.add(new JLabel(L.get("history_manager.site_filter") + ":"));
        mHostFilterText = new JTextField();
        filterPanel.add(mHostFilterText, "1w");
        JButton filterBtn = new JButton(L.get("search"));
        filterBtn.addActionListener(e -> loadHosts());
        filterPanel.add(filterBtn);
        panel.add(filterPanel);

        mHostListModel = new DefaultListModel<>();
        mHostList = new JList<>(mHostListModel);
        mHostList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        JScrollPane scroll = new JScrollPane(mHostList);
        scroll.setPreferredSize(new Dimension(0, 100));
        panel.add(scroll, "1w");

        JPanel btnPanel = new JPanel(new HLayout(5, true));
        JButton refreshBtn = new JButton(L.get("reload"));
        refreshBtn.addActionListener(e -> loadHosts());
        JButton deleteBtn = new JButton(L.get("history_manager.btn_delete_selected_sites"));
        deleteBtn.addActionListener(e -> doDeleteBySites());
        btnPanel.add(refreshBtn);
        btnPanel.add(new JPanel(), "1w");
        btnPanel.add(deleteBtn);
        panel.add(btnPanel);
        return panel;
    }

    // ── 数据加载 ─────────────────────────────────────────────

    private void loadLabels() {
        SwingUtilities.invokeLater(() -> {
            mLabelListModel.clear();
            try {
                List<TaskPersistenceManager.HistoryLabel> labels = TaskPersistenceManager.listLabels();
                for (TaskPersistenceManager.HistoryLabel lbl : labels) {
                    mLabelListModel.addElement(lbl);
                }
            } catch (Exception e) {
                setStatus(L.get("error_hint", e.getMessage()));
            }
        });
    }

    private void loadHosts() {
        String keyword = mHostFilterText == null ? "" : mHostFilterText.getText().trim();
        SwingUtilities.invokeLater(() -> {
            mHostListModel.clear();
            try {
                List<String> hosts = TaskPersistenceManager.listDistinctHosts();
                for (String h : hosts) {
                    if (keyword.isEmpty() || h.contains(keyword)) {
                        mHostListModel.addElement(h);
                    }
                }
            } catch (Exception e) {
                setStatus(L.get("error_hint", e.getMessage()));
            }
        });
    }

    // ── 删除操作 ─────────────────────────────────────────────

    private void doDeleteAll() {
        int ret = UIHelper.showOkCancelDialog(
                L.get("history_manager.delete_all"),
                L.get("history_manager.confirm_delete_all"));
        if (ret != JOptionPane.OK_OPTION) {
            return;
        }
        int count = TaskPersistenceManager.deleteAll();
        setStatus(L.get("history_manager.deleted_count", count));
        loadLabels();
        loadHosts();
        notifyDeleted();
    }

    private void doDeleteByLabels() {
        List<TaskPersistenceManager.HistoryLabel> selected = mLabelList.getSelectedValuesList();
        if (selected.isEmpty()) {
            UIHelper.showTipsDialog(L.get("history_manager.no_selection"));
            return;
        }
        int ret = UIHelper.showOkCancelDialog(
                L.get("history_manager.by_time"),
                L.get("history_manager.confirm_delete_labels", selected.size()));
        if (ret != JOptionPane.OK_OPTION) {
            return;
        }
        List<String> labels = new ArrayList<>();
        for (TaskPersistenceManager.HistoryLabel lbl : selected) {
            labels.add(lbl.label());
        }
        int count = TaskPersistenceManager.deleteByLabels(labels);
        setStatus(L.get("history_manager.deleted_count", count));
        loadLabels();
        notifyDeleted();
    }

    private void doDeleteBySites() {
        List<String> selected = mHostList.getSelectedValuesList();
        if (selected.isEmpty()) {
            UIHelper.showTipsDialog(L.get("history_manager.no_selection"));
            return;
        }
        int ret = UIHelper.showOkCancelDialog(
                L.get("history_manager.by_site"),
                L.get("history_manager.confirm_delete_sites", selected.size()));
        if (ret != JOptionPane.OK_OPTION) {
            return;
        }
        int total = 0;
        for (String host : selected) {
            // 精确匹配 host 字段值
            total += TaskPersistenceManager.deleteByHostPattern(host);
        }
        setStatus(L.get("history_manager.deleted_count", total));
        loadLabels();
        loadHosts();
        notifyDeleted();
    }

    private void setStatus(String text) {
        if (mStatusLabel != null) {
            SwingUtilities.invokeLater(() -> mStatusLabel.setText(text));
        }
    }

    private void notifyDeleted() {
        if (mOnDeleteListener != null) {
            mOnDeleteListener.onDeleted();
        }
    }

    // ── 监听接口 ─────────────────────────────────────────────

    public interface OnDeleteListener {
        void onDeleted();
    }
}
