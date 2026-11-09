package burp.vaycore.common.filter;

import burp.vaycore.common.utils.StringUtils;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class TableFilter<T extends AbstractTableModel> extends RowFilter<T, Object> {

    private final FilterRule rule;

    public TableFilter(FilterRule rule) {
        if (rule == null) {
            throw new IllegalArgumentException("rule is null");
        }
        if (rule.getItems().isEmpty()) {
            throw new IllegalArgumentException("rule condition is null");
        }
        this.rule = rule;
    }

    public FilterRule getRule() {
        return rule;
    }

    @Override
    public boolean include(Entry<? extends T, ?> entry) {
        T model = entry.getModel();
        Integer rowIndex = (Integer) entry.getIdentifier();
        if (rowIndex < 0 || rowIndex >= model.getRowCount()) {
            return false;
        }
        List<String> values;
        if (rule.getFieldKey() != null) {
            if (!(model instanceof ValueProvider provider)) {
                return false;
            }
            values = provider.getFilterValues(rowIndex, rule.getFieldKey());
            // Unknown fields fail closed instead of binding to a different column.
            if (values == null) {
                return false;
            }
        } else {
            int columnIndex = rule.getColumnIndex();
            if (columnIndex < 0 || columnIndex >= model.getColumnCount()) {
                return false;
            }
            Object value = model.getValueAt(rowIndex, columnIndex);
            values = List.of(value == null ? "" : String.valueOf(value));
        }
        if (values.isEmpty()) {
            values = List.of("");
        }
        ArrayList<FilterRule.Item> items = rule.getItems();
        boolean result = false;
        // Rules are folded in display order. Do not short-circuit across later OR/AND items.
        for (int i = 0; i < items.size(); i++) {
            FilterRule.Item item = items.get(i);
            boolean check = checkValues(values, item);
            if (i == 0) {
                result = check;
            } else if (item.getLogic() == FilterRule.LOGIC_OR) {
                result = result || check;
            } else {
                result = result && check;
            }
        }
        return result;
    }

    /** A model may expose virtual or stable fields without adding visible table columns. */
    public interface ValueProvider {
        List<String> getFilterValues(int rowIndex, String fieldKey);
    }

    private boolean checkValues(List<String> values, FilterRule.Item item) {
        boolean negative = item.getOperate() == FilterRule.OPERATE_NOT_EQUAL
                || item.getOperate() == FilterRule.OPERATE_NOT_START
                || item.getOperate() == FilterRule.OPERATE_NOT_END
                || item.getOperate() == FilterRule.OPERATE_NOT_INCLUDE;
        // Positive: any fingerprint matches. Negative: no fingerprint matches.
        for (String value : values) {
            boolean check = checkRuleItem(value == null ? "" : value, item);
            if (negative && !check) return false;
            if (!negative && check) return true;
        }
        return negative;
    }

    private boolean checkRuleItem(String value, FilterRule.Item item) {
        int operate = item.getOperate();
        if (operate >= FilterRule.OPERATE_GT && operate <= FilterRule.OPERATE_LT_EQUAL) {
            int left = StringUtils.parseInt(value);
            int right = StringUtils.parseInt(item.getValue());
            return switch (operate) {
                case FilterRule.OPERATE_GT -> left > right;
                case FilterRule.OPERATE_GT_EQUAL -> left >= right;
                case FilterRule.OPERATE_LT -> left < right;
                case FilterRule.OPERATE_LT_EQUAL -> left <= right;
                default -> false;
            };
        }

        String right = item.getValue();
        return switch (operate) {
            case FilterRule.OPERATE_EQUAL -> value.equals(right);
            case FilterRule.OPERATE_NOT_EQUAL -> !value.equals(right);
            case FilterRule.OPERATE_START -> value.startsWith(right);
            case FilterRule.OPERATE_NOT_START -> !value.startsWith(right);
            case FilterRule.OPERATE_END -> value.endsWith(right);
            case FilterRule.OPERATE_NOT_END -> !value.endsWith(right);
            case FilterRule.OPERATE_INCLUDE -> value.contains(right);
            case FilterRule.OPERATE_NOT_INCLUDE -> !value.contains(right);
            default -> false;
        };
    }
}
