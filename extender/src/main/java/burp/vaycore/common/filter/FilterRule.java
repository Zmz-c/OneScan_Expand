package burp.vaycore.common.filter;

import burp.vaycore.ost.common.L;

import java.util.ArrayList;

public class FilterRule {

    public static final int LOGIC_AND = 1;
    public static final int LOGIC_OR = 2;

    public static final int OPERATE_EQUAL = 1;
    public static final int OPERATE_NOT_EQUAL = 2;
    public static final int OPERATE_GT = 3;
    public static final int OPERATE_GT_EQUAL = 4;
    public static final int OPERATE_LT = 5;
    public static final int OPERATE_LT_EQUAL = 6;
    public static final int OPERATE_START = 7;
    public static final int OPERATE_NOT_START = 8;
    public static final int OPERATE_END = 9;
    public static final int OPERATE_NOT_END = 10;
    public static final int OPERATE_INCLUDE = 11;
    public static final int OPERATE_NOT_INCLUDE = 12;

    public static String[] getOperateItems() {
        return new String[]{
                L.get("table_filter_rule.please_select"),
                L.get("table_filter_rule.equal_to"),
                L.get("table_filter_rule.not_equal_to"),
                L.get("table_filter_rule.greater_than"),
                L.get("table_filter_rule.greater_than_or_equal_to"),
                L.get("table_filter_rule.less_than"),
                L.get("table_filter_rule.less_than_or_equal_to"),
                L.get("table_filter_rule.starts_with"),
                L.get("table_filter_rule.not_starts_with"),
                L.get("table_filter_rule.ends_with"),
                L.get("table_filter_rule.not_ends_with"),
                L.get("table_filter_rule.contains"),
                L.get("table_filter_rule.not_contains"),
        };
    }

    public static final String[] OPERATE_CHAR = {"",
            "==", "!=", ">", ">=", "<", "<=",
            "startsWith", "noStartsWith", "endsWith",
            "noEndsWith", "contains", "noContains"};

    private final int columnIndex;
    // Optional stable field identifier; absent in legacy index-based configurations.
    private final String fieldKey;
    private final ArrayList<Item> items;

    public FilterRule(int columnIndex) {
        this(columnIndex, null);
    }

    public FilterRule(int columnIndex, String fieldKey) {
        this.columnIndex = columnIndex;
        this.fieldKey = fieldKey;
        this.items = new ArrayList<>();
    }

    public int getColumnIndex() {
        return columnIndex;
    }

    public String getFieldKey() {
        return fieldKey;
    }

    public ArrayList<Item> getItems() {
        return items;
    }

    public void addRule(int logic, int operate, String value) {
        if (!items.isEmpty() && logic <= 0) {
            throw new IllegalArgumentException("logic is 0");
        }
        if (operate <= 0 || operate >= OPERATE_CHAR.length) {
            throw new IllegalArgumentException("operate is 0");
        }
        items.add(new Item(logic, operate, value));
    }

    public record Item(int logic, int operate, String value) {
        public Item {
            value = value == null ? "" : value;
        }

        public int getLogic() {
            return logic;
        }

        public int getOperate() {
            return operate;
        }

        public String getValue() {
            return value;
        }
    }
}
