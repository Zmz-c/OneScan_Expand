package burp.vaycore.ost.ui.widget;

import burp.vaycore.common.filter.FilterField;
import burp.vaycore.ost.bean.FpColumn;
import burp.vaycore.ost.bean.FpData;
import burp.vaycore.ost.bean.IdentityProfile;
import burp.vaycore.ost.bean.TaskData;
import burp.vaycore.ost.common.Config;
import burp.vaycore.ost.common.L;
import burp.vaycore.ost.manager.FpManager;

import java.util.*;
import java.util.function.Supplier;

/** Reuses fingerprint definitions, profiles and recorded rows; no separate filter dictionary. */
public final class TaskFilterFields {
    public static final String FINGERPRINT = "fingerprint";
    public static final String PROFILE = "profile";
    private static final String PARAM_PREFIX = "param:";

    private TaskFilterFields() { }

    public static List<FilterField> create(Supplier<List<TaskData>> history) {
        List<FilterField> fields = new ArrayList<>();
        Vector<String> names = TaskTable.getColumnNames();
        for (int i = 0; i < TaskTable.getBaseColumnCount(); i++) {
            fields.add(new FilterField(i, i == 10 ? PROFILE : null, names.get(i),
                    i == 10 ? () -> choices(PROFILE, history.get()) : null));
        }
        int index = TaskTable.getBaseColumnCount();
        for (FpColumn column : FpManager.getColumns()) {
            String key = PARAM_PREFIX + column.getId();
            fields.add(new FilterField(index++, key, column.getName(), () -> choices(key, history.get())));
        }
        // Virtual field: never inserts a column or shifts legacy persisted indexes.
        fields.add(new FilterField(-1, FINGERPRINT, L.get("table_filter.fingerprint"),
                () -> choices(FINGERPRINT, history.get())));
        return fields;
    }

    static List<FilterField.Choice> choices(String key, List<TaskData> history) {
        Set<String> values = new TreeSet<>();
        if (PROFILE.equals(key)) {
            for (IdentityProfile profile : Config.getIdentityProfiles()) {
                values.add(profile.getName());
            }
        } else {
            for (FpData data : FpManager.getList()) {
                for (FpData.Param param : data.getParams()) {
                    if (FINGERPRINT.equals(key) || key.equals(PARAM_PREFIX + param.getK())) {
                        if (FINGERPRINT.equals(key)) addFingerprintValues(values, param.getV());
                        else if (param.getV() != null) values.add(param.getV());
                    }
                }
            }
        }
        for (TaskData data : history) {
            List<String> recorded = values(data, key);
            if (recorded != null) values.addAll(recorded);
        }
        values.remove("");
        List<FilterField.Choice> choices = new ArrayList<>();
        choices.add(new FilterField.Choice("", L.get(PROFILE.equals(key)
                ? "table_filter.no_profile" : "table_filter.no_fingerprint")));
        for (String value : values) choices.add(new FilterField.Choice(value, value));
        return choices;
    }

    public static List<String> values(TaskData data, String key) {
        if (data == null) return List.of("");
        if (PROFILE.equals(key)) return List.of(data.getProfile());
        if (key.startsWith(PARAM_PREFIX)) {
            // Keep existing per-column string comparison semantics, but bind by stable ID.
            String value = data.getParams().get(key.substring(PARAM_PREFIX.length()));
            return List.of(value == null ? "" : value);
        }
        if (FINGERPRINT.equals(key)) {
            Set<String> values = new LinkedHashSet<>();
            for (String value : data.getParams().values()) addFingerprintValues(values, value);
            return new ArrayList<>(values);
        }
        return null;
    }

    private static void addFingerprintValues(Set<String> values, String combined) {
        if (combined == null || combined.isEmpty()) return;
        // TaskData stores multiple hits in each fingerprint column separated by commas.
        for (String value : combined.split(",")) {
            if (!value.isEmpty()) values.add(value);
        }
    }
}
