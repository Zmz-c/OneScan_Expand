package burp.vaycore.common.filter;

import java.util.ArrayList;
import java.util.List;
import java.util.Vector;
import java.util.function.Supplier;

/** Editor metadata. Labels are presentation only; keys and choice values are persisted. */
public record FilterField(int columnIndex, String key, String label, Supplier<List<Choice>> choices) {
    public record Choice(String value, String label) {
        @Override
        public String toString() { return label; }
    }

    public boolean matches(FilterRule rule) {
        return rule.getFieldKey() == null ? columnIndex == rule.getColumnIndex()
                : rule.getFieldKey().equals(key);
    }

    @Override
    public String toString() { return label; }

    public static List<FilterField> fromColumns(Vector<String> columns) {
        if (columns == null) throw new IllegalArgumentException("columns param is null.");
        List<FilterField> fields = new ArrayList<>();
        for (int i = 0; i < columns.size(); i++) {
            fields.add(new FilterField(i, null, columns.get(i), null));
        }
        return fields;
    }
}
