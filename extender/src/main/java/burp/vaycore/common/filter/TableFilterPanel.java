package burp.vaycore.common.filter;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VFlowLayout;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.ost.common.L;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.ArrayList;
import java.util.Vector;
import java.util.List;

/**
 * 表过滤面板
 * <p>
 * Created by vaycore on 2023-02-27.
 */
public class TableFilterPanel extends JPanel implements ItemListener, ActionListener {

    private JComboBox<FilterField> mColumnList;
    private JPanel mRulesPanel;

    private final ArrayList<FilterRule> mRules;
    private int mLastColumnIndex = 0;
    private final List<FilterField> mFields;
    private JScrollPane mRulesScrollPanel;

    public TableFilterPanel(Vector<String> columns, ArrayList<FilterRule> rules) {
        this(FilterField.fromColumns(columns), rules);
    }

    public TableFilterPanel(List<FilterField> fields, ArrayList<FilterRule> rules) {
        if (fields == null || fields.isEmpty()) {
            throw new IllegalArgumentException("filter fields are empty");
        }
        mFields = new ArrayList<>(fields);
        mRules = new ArrayList<>();
        if (rules != null) {
            for (FilterRule rule : rules) {
                FilterField field = mFields.stream().filter(f -> f.matches(rule)).findFirst().orElse(null);
                if (field == null) {
                    field = new FilterField(rule.getColumnIndex(), rule.getFieldKey(),
                            L.get("table_filter.unavailable_field", rule.getFieldKey() == null
                                    ? String.valueOf(rule.getColumnIndex()) : rule.getFieldKey()), null);
                    mFields.add(field);
                }
                FilterRule copy = new FilterRule(field.columnIndex(), field.key());
                copy.getItems().addAll(rule.getItems());
                mRules.add(copy);
            }
        }
        initView();
        setupData();
    }

    private void initView() {
        setPreferredSize(new Dimension(700, 320));
        setLayout(new VLayout(10));
        // 选择过滤字段，添加、清除字段过滤规则
        JPanel columnPanel = new JPanel(new HLayout(5, true));
        add(columnPanel);
        JLabel filterLabel = new JLabel(L.get("table_filter.select_column"));
        columnPanel.add(filterLabel);
        mColumnList = new JComboBox<>(new Vector<>(mFields));
        mColumnList.setSelectedIndex(mLastColumnIndex);
        mColumnList.addItemListener(this);
        columnPanel.add(mColumnList, "1w");
        // 添加过滤
        JButton addItemBtn = new JButton(L.get("table_filter.add_filter"));
        addItemBtn.setToolTipText(L.get("table_filter.add_filter"));
        addItemBtn.setActionCommand("add-filter-item");
        addItemBtn.addActionListener(this);
        columnPanel.add(addItemBtn, "20%");
        // 清除过滤
        JButton clearBtn = new JButton(L.get("table_filter.clear"));
        clearBtn.setToolTipText(L.get("table_filter.clear"));
        clearBtn.setActionCommand("clear-filter-item");
        clearBtn.addActionListener(this);
        columnPanel.add(clearBtn, "15%");
        // 规则设置
        mRulesScrollPanel = new JScrollPane();
        mRulesScrollPanel.getVerticalScrollBar().setUnitIncrement(30);
        add(mRulesScrollPanel, "1w");
        mRulesPanel = new JPanel();
        mRulesScrollPanel.setViewportView(mRulesPanel);
        mRulesPanel.setLayout(new VFlowLayout());
    }

    private void setupData() {
        mRulesPanel.removeAll();
        int index = indexOfByColumnIndex(mLastColumnIndex);
        // 如果不存在规则配置
        if (index == -1) {
            // 添加默认显示的UI
            addRuleItem(0, 0, null);
        } else {
            FilterRule rule = mRules.get(index);
            ArrayList<FilterRule.Item> items = rule.getItems();
            // 遍历添加数据
            for (FilterRule.Item item : items) {
                addRuleItem(item.getLogic(), item.getOperate(), item.getValue());
            }
        }
        UIHelper.refreshUI(mRulesScrollPanel);
    }

    private void addRuleItem(int logic, int operate, String value) {
        JPanel panel = new JPanel(new VLayout());
        mRulesPanel.add(panel);
        if (logic == 0) {
            panel.setPreferredSize(new Dimension(0, 31));
        } else {
            panel.setPreferredSize(new Dimension(0, 62));
        }
        // 过滤规则 AND、OR 选项
        JPanel radioBtnPanel = new JPanel(new HLayout(10));
        radioBtnPanel.setBorder(new EmptyBorder(0, 5, 0, 0));
        panel.add(radioBtnPanel);
        JRadioButton andRadioBtn = new JRadioButton(L.get("table_filter.and"));
        andRadioBtn.setFocusable(false);
        andRadioBtn.setSelected(logic == FilterRule.LOGIC_AND);
        JRadioButton orRadioBtn = new JRadioButton(L.get("table_filter.or"));
        orRadioBtn.setFocusable(false);
        orRadioBtn.setSelected(logic == FilterRule.LOGIC_OR);
        UIHelper.createRadioGroup(andRadioBtn, orRadioBtn);
        radioBtnPanel.add(andRadioBtn);
        radioBtnPanel.add(orRadioBtn);
        radioBtnPanel.setVisible(logic > 0);
        // 过滤规则条件
        JPanel rulePanel = new JPanel(new HLayout(5, true));
        panel.add(rulePanel);
        JComboBox<String> operateBox = new JComboBox<>(FilterRule.getOperateItems());
        operateBox.setSelectedIndex(operate);
        rulePanel.add(operateBox);
        rulePanel.add(createValueInput(mFields.get(mLastColumnIndex), value), "1w");
        JButton delBtn = new JButton(L.get("table_filter.x"));
        delBtn.setMargin(new Insets(2, 6, 2, 6));
        rulePanel.add(delBtn, "40px");
        delBtn.setEnabled(logic > 0);
        delBtn.addActionListener(e -> {
            mRulesPanel.remove(panel);
            UIHelper.refreshUI(mRulesScrollPanel);
        });
    }

    private JComponent createValueInput(FilterField field, String value) {
        if (field.choices() == null) {
            return new JTextField(value);
        }
        JComboBox<FilterField.Choice> box = new JComboBox<>();
        box.setEditable(true);
        box.setMaximumRowCount(16);
        refreshChoices(box, field, value == null ? "" : value);
        box.addPopupMenuListener(new PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                refreshChoices(box, field, readValue(box));
            }
            @Override public void popupMenuWillBecomeInvisible(PopupMenuEvent e) { }
            @Override public void popupMenuCanceled(PopupMenuEvent e) { }
        });
        return box;
    }

    private void refreshChoices(JComboBox<FilterField.Choice> box, FilterField field, String value) {
        List<FilterField.Choice> choices = new ArrayList<>(field.choices().get());
        FilterField.Choice selected = choices.stream().filter(c -> c.value().equals(value)).findFirst()
                .orElseGet(() -> new FilterField.Choice(value, value));
        if (!choices.contains(selected)) choices.add(selected);
        box.setModel(new DefaultComboBoxModel<>(choices.toArray(new FilterField.Choice[0])));
        box.setSelectedItem(selected);
    }

    private String readValue(Component input) {
        if (input instanceof JComboBox<?> box) {
            Object value = box.getEditor().getItem();
            return value instanceof FilterField.Choice choice ? choice.value()
                    : value == null ? "" : value.toString();
        }
        return ((JTextField) input).getText();
    }

    @Override
    public void itemStateChanged(ItemEvent e) {
        if (mColumnList == null) {
            return;
        }
        int index = mColumnList.getSelectedIndex();
        if (mLastColumnIndex == index) {
            return;
        }
        // 切换前先保存数据
        saveColumnRuleItem(mLastColumnIndex);
        mLastColumnIndex = index;
        // 切换后刷新页面数据
        setupData();
    }

    private void saveColumnRuleItem(int lastColumnIndex) {
        int index = indexOfByColumnIndex(lastColumnIndex);
        FilterField field = mFields.get(lastColumnIndex);
        FilterRule rule = new FilterRule(field.columnIndex(), field.key());
        int ruleCount = mRulesPanel.getComponentCount();
        // 遍历组件数据，填充到对象
        for (int i = 0; i < ruleCount; i++) {
            JPanel panel = (JPanel) mRulesPanel.getComponent(i);
            // 获取逻辑运算符
            int logic = 0;
            JPanel radioBtnPanel = (JPanel) panel.getComponent(0);
            if (radioBtnPanel.isVisible()) {
                JRadioButton andRadioBtn = (JRadioButton) radioBtnPanel.getComponent(0);
                logic = andRadioBtn.isSelected() ? FilterRule.LOGIC_AND : FilterRule.LOGIC_OR;
            }
            // 获取操作符
            JPanel rulePanel = (JPanel) panel.getComponent(1);
            JComboBox<String> operateBox = (JComboBox<String>) rulePanel.getComponent(0);
            int operate = operateBox.getSelectedIndex();
            // 获取值
            String value = readValue(rulePanel.getComponent(1));
            try {
                rule.addRule(rule.getItems().isEmpty() ? 0 : logic == 0 ? FilterRule.LOGIC_AND : logic, operate, value);
            } catch (Exception e) {
                // 如果添加规则失败，舍弃该规则
            }
        }
        // 如果存在规则，将规则保存到内存
        if (!rule.getItems().isEmpty()) {
            if (index >= 0) {
                mRules.set(index, rule);
            } else {
                mRules.add(rule);
            }
        } else if (index >= 0) {
            mRules.remove(index);
        }
    }

    /**
     * 获取规则配置在列表中的下标
     *
     * @param columnIndex 规则配置下标
     * @return 返回规则配置所在的下标，不存在返回-1
     */
    private int indexOfByColumnIndex(int columnIndex) {
        if (mRules.isEmpty()) {
            return -1;
        }
        for (int i = 0; i < mRules.size(); i++) {
            FilterRule rule = mRules.get(i);
            if (mFields.get(columnIndex).matches(rule)) {
                return i;
            }
        }
        return -1;
    }

    /**
     * 导出过滤规则
     *
     * @return 过滤规则数据
     */
    public ArrayList<FilterRule> exportRules() {
        // 导出前保存一下当前数据
        saveColumnRuleItem(mLastColumnIndex);
        return mRules;
    }

    /**
     * 导出过滤规则表达式
     *
     * @return 返回过滤规则表达式
     */
    public String exportRulesText() {
        saveColumnRuleItem(mLastColumnIndex);
        StringBuilder result = new StringBuilder();
        if (mRules == null || mRules.isEmpty()) {
            return result.toString();
        }
        for (FilterRule rule : mRules) {
            String columnName = mFields.stream().filter(f -> f.matches(rule))
                    .map(FilterField::label).findFirst().orElse("");
            ArrayList<FilterRule.Item> items = rule.getItems();
            // 规则与规则之间是并且的关系
            if (!StringUtils.isEmpty(result)) {
                result.append(" && ");
            }
            StringBuilder expression = new StringBuilder();
            for (FilterRule.Item item : items) {
                int logic = item.getLogic();
                int operate = item.getOperate();
                String value = item.getValue();
                if (expression.length() > 0) {
                    expression.insert(0, "(").append(")");
                    expression.append(logic == FilterRule.LOGIC_AND ? " && " : " || ");
                }
                expression.append(columnName);
                String operateStr = FilterRule.OPERATE_CHAR[operate];
                // 拼接操作符，区分运算符和方法处理
                if (operate < FilterRule.OPERATE_START) {
                    // 处理一下空串和非数字的显示格式
                    if (StringUtils.isEmpty(value)) {
                        value = "''";
                    } else {
                        if (!StringUtils.isNumeric(value)) {
                            value = "'" + value + "'";
                        }
                    }
                    expression.append(" ").append(operateStr).append(" ");
                    expression.append(value);
                } else {
                    value = "'" + value + "'";
                    expression.append(".").append(operateStr).append("(");
                    expression.append(value).append(")");
                }
            }
            result.append("(").append(expression).append(")");
        }
        return result.toString();
    }

    /**
     * 导出为表过滤器规则
     *
     * @return 表过滤器规则数据
     */
    public ArrayList<TableFilter<AbstractTableModel>> exportTableFilters() {
        saveColumnRuleItem(mLastColumnIndex);
        ArrayList<TableFilter<AbstractTableModel>> filters = new ArrayList<>();
        for (FilterRule rule : mRules) {
            TableFilter<AbstractTableModel> filter = new TableFilter<>(rule);
            filters.add(filter);
        }
        return filters;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        switch (e.getActionCommand()) {
            case "add-filter-item":
                // 规则添加事件
                addRuleItem(1, 0, null);
                UIHelper.refreshUI(mRulesScrollPanel);
                break;
            case "clear-filter-item":
                // 规则清除事件
                int ruleIndex = indexOfByColumnIndex(mLastColumnIndex);
                if (ruleIndex != -1) {
                    mRules.remove(ruleIndex);
                }
                // 刷新
                setupData();
                break;
        }
    }

    /**
     * 显示设置对话框
     *
     * @param callback 对话框回调接口
     */
    public void showDialog(DialogCallback callback) {
        int state = UIHelper.showCustomDialog(L.get("table_filter_dialog.title"),
                new String[]{L.get("ok"), L.get("cancel"), L.get("reset")}, this);
        if (state == JOptionPane.YES_OPTION) {
            ArrayList<FilterRule> filterRules = exportRules();
            ArrayList<TableFilter<AbstractTableModel>> filters = exportTableFilters();
            String rulesText = exportRulesText();
            if (callback != null) {
                callback.onConfirm(filterRules, filters, rulesText);
            }
        } else if (callback != null) {
            if (state == 2) {
                callback.onReset();
            } else {
                callback.onCancel();
            }
        }
    }

    public interface DialogCallback {

        /**
         * 点击 Ok 按钮回调
         *
         * @param filterRules 过滤规则
         * @param filters     处理成Swing直接使用的过滤规则
         * @param rulesText   规则表达式
         */
        void onConfirm(ArrayList<FilterRule> filterRules,
                       ArrayList<TableFilter<AbstractTableModel>> filters,
                       String rulesText);

        /**
         * 点击 Reset 按钮回调
         */
        void onReset();

        /**
         * 点击 Cancel 按钮回调
         */
        void onCancel();
    }
}
