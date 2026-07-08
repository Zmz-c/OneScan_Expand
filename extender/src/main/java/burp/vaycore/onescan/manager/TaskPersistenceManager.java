package burp.vaycore.onescan.manager;

import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.FileUtils;
import burp.vaycore.common.utils.GsonUtils;
import burp.vaycore.common.utils.PathUtils;
import burp.vaycore.common.utils.StringUtils;

import java.util.Base64;
import burp.vaycore.onescan.bean.FpColumn;
import burp.vaycore.onescan.bean.TaskData;
import burp.vaycore.onescan.common.Config;
import burp.vaycore.onescan.common.L;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class TaskPersistenceManager {

    public static final String FIELD_FROM = "from";
    public static final String FIELD_METHOD = "method";
    public static final String FIELD_HOST = "host";
    public static final String FIELD_URL = "url";
    public static final String FIELD_TITLE = "title";
    public static final String FIELD_IP = "ip";
    public static final String FIELD_STATUS = "status";
    public static final String FIELD_LENGTH = "length";
    public static final String FIELD_COLOR = "color";
    public static final String FIELD_PARAMS = "params";
    public static final String FIELD_REQ_BYTES = "req_bytes";
    public static final String FIELD_RESP_BYTES = "resp_bytes";
    public static final String DEFAULT_DATA_LABEL = "default";
    private static final DateTimeFormatter LABEL_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

    private static final List<FieldDef> BASE_FIELDS = List.of(
            new FieldDef(FIELD_FROM, L.get("task_table_columns.from")),
            new FieldDef(FIELD_METHOD, L.get("task_table_columns.method")),
            new FieldDef(FIELD_HOST, L.get("task_table_columns.host")),
            new FieldDef(FIELD_URL, L.get("task_table_columns.url")),
            new FieldDef(FIELD_TITLE, L.get("task_table_columns.title")),
            new FieldDef(FIELD_IP, L.get("task_table_columns.ip")),
            new FieldDef(FIELD_STATUS, L.get("task_table_columns.status")),
            new FieldDef(FIELD_LENGTH, L.get("task_table_columns.length")),
            new FieldDef(FIELD_COLOR, L.get("task_table_columns.color")),
            new FieldDef(FIELD_PARAMS, L.get("data_persistence_fields.params"))
    );
    private static final Object EXECUTOR_LOCK = new Object();
    private static final Object DB_LOCK = new Object();
    private static ExecutorService sExecutor = createExecutor();

    private TaskPersistenceManager() {
        throw new IllegalAccessError("TaskPersistenceManager class not support create instance.");
    }

    public static List<FieldDef> getBaseFields() {
        return BASE_FIELDS;
    }

    public static List<FieldDef> getSelectableFields() {
        ArrayList<FieldDef> result = new ArrayList<>(BASE_FIELDS);
        for (FpColumn column : FpManager.getColumns()) {
            if (column != null && StringUtils.isNotEmpty(column.getId())) {
                String label = StringUtils.isNotEmpty(column.getName()) ? column.getName() : column.getId();
                result.add(new FieldDef("param:" + column.getId(), label));
            }
        }
        return result;
    }

    public static List<String> getConfiguredFieldKeys() {
        String value = Config.get(Config.KEY_DATA_PERSISTENCE_FIELDS);
        if (StringUtils.isEmpty(value)) {
            return defaultFieldKeys();
        }
        ArrayList<String> result = new ArrayList<>();
        for (String item : value.split(",")) {
            String key = item.trim();
            if (StringUtils.isNotEmpty(key) && !result.contains(key)) {
                result.add(key);
            }
        }
        return result.isEmpty() ? defaultFieldKeys() : result;
    }

    public static void saveConfiguredFieldKeys(List<String> keys) {
        Config.put(Config.KEY_DATA_PERSISTENCE_FIELDS, String.join(",", normalizeFieldKeys(keys)));
    }

    public static List<String> normalizeFieldKeys(List<String> keys) {
        ArrayList<String> result = new ArrayList<>();
        if (keys != null) {
            for (String key : keys) {
                if (StringUtils.isNotEmpty(key) && !result.contains(key)) {
                    result.add(key);
                }
            }
        }
        return result.isEmpty() ? defaultFieldKeys() : result;
    }

    public static List<String> defaultFieldKeys() {
        return List.of(FIELD_FROM, FIELD_METHOD, FIELD_HOST, FIELD_URL, FIELD_TITLE,
                FIELD_IP, FIELD_STATUS, FIELD_LENGTH, FIELD_COLOR);
    }

    public static boolean isEnabled() {
        return Config.getBoolean(Config.KEY_DATA_PERSISTENCE_ENABLED);
    }

    public static String getDatabasePath() {
        return Config.getFilePath(Config.KEY_DATA_PERSISTENCE_DB_PATH);
    }

    public static int getAutoSaveIntervalSeconds() {
        return Math.max(0, Config.getInt(Config.KEY_DATA_PERSISTENCE_AUTO_SAVE_INTERVAL));
    }

    public static void saveAutoSaveIntervalSeconds(int seconds) {
        Config.put(Config.KEY_DATA_PERSISTENCE_AUTO_SAVE_INTERVAL, String.valueOf(Math.max(0, seconds)));
    }

    public static String nextTimestampLabel() {
        return LABEL_FORMATTER.format(LocalDateTime.now());
    }

    public static SaveResult persistSnapshot(List<TaskData> items) {
        if (!isEnabled()) {
            return new SaveResult("", 0);
        }
        return persistSnapshot(items, getConfiguredFieldKeys(), nextTimestampLabel());
    }

    public static SaveResult persistSnapshot(List<TaskData> items, List<String> fieldKeys, String label) {
        if (items == null || items.isEmpty()) {
            return new SaveResult(normalizeLabel(label), 0);
        }
        ArrayList<TaskData> validItems = new ArrayList<>();
        for (TaskData item : items) {
            if (item != null) {
                validItems.add(item);
            }
        }
        if (validItems.isEmpty()) {
            return new SaveResult(normalizeLabel(label), 0);
        }
        String dataLabel = normalizeLabel(label);
        List<String> fields = normalizeFieldKeys(fieldKeys);
        persistSnapshotNow(validItems, fields, dataLabel);
        return new SaveResult(dataLabel, validItems.size());
    }

    public static void persist(TaskData data, List<String> fieldKeys, String label) {
        if (data == null) {
            return;
        }
        List<String> fields = normalizeFieldKeys(fieldKeys);
        executor().execute(() -> persistNow(data, fields, label));
    }

    public static void persistNow(TaskData data, List<String> fieldKeys) {
        persistNow(data, fieldKeys, nextTimestampLabel());
    }

    public static void persistNow(TaskData data, List<String> fieldKeys, String label) {
        List<String> fields = normalizeFieldKeys(fieldKeys);
        String dataLabel = normalizeLabel(label);
        synchronized (DB_LOCK) {
            try (Connection conn = openConnection()) {
                ensureSchema(conn);
                conn.setAutoCommit(false);
                long recordId = insertRecord(conn, data, dataLabel);
                insertFields(conn, recordId, data, fields);
                conn.commit();
            } catch (Exception e) {
                Logger.error("Persist task data failed: %s", e.getMessage());
            }
        }
    }

    private static void persistSnapshotNow(List<TaskData> items, List<String> fields, String label) {
        synchronized (DB_LOCK) {
            try (Connection conn = openConnection()) {
                ensureSchema(conn);
                conn.setAutoCommit(false);
                for (TaskData data : items) {
                    long recordId = insertRecord(conn, data, label);
                    insertFields(conn, recordId, data, fields);
                }
                conn.commit();
            } catch (Exception e) {
                Logger.error("Persist task snapshot failed: %s", e.getMessage());
            }
        }
    }

    public static List<HistoryLabel> listLabels() throws Exception {
        flush();
        synchronized (DB_LOCK) {
            try (Connection conn = openConnection()) {
                ensureSchema(conn);
                LinkedHashMap<String, Integer> counts = new LinkedHashMap<>();
                try (PreparedStatement ps = conn.prepareStatement("""
                        SELECT data_label, COUNT(*) AS count
                        FROM task_records
                        GROUP BY data_label
                        ORDER BY MAX(id) DESC
                        """);
                     ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        String label = normalizeLabel(rs.getString("data_label"));
                        counts.merge(label, rs.getInt("count"), Integer::sum);
                    }
                }
                ArrayList<HistoryLabel> result = new ArrayList<>();
                for (Map.Entry<String, Integer> entry : counts.entrySet()) {
                    result.add(new HistoryLabel(entry.getKey(), entry.getValue()));
                }
                return result;
            }
        }
    }

    public static List<TaskData> loadTaskDataByLabel(String label) throws Exception {
        String dataLabel = normalizeLabel(label);
        flush();
        synchronized (DB_LOCK) {
            try (Connection conn = openConnection()) {
                ensureSchema(conn);
                LinkedHashMap<Long, TaskData> tasks = loadTaskRecords(conn, dataLabel);
                if (tasks.isEmpty()) {
                    return new ArrayList<>();
                }
                LinkedHashMap<Long, Map<String, String>> rows = loadAllFieldRows(conn, dataLabel);
                ArrayList<TaskData> result = new ArrayList<>();
                for (Map.Entry<Long, TaskData> entry : tasks.entrySet()) {
                    Map<String, String> fields = rows.getOrDefault(entry.getKey(), new LinkedHashMap<>());
                    applyFields(entry.getValue(), fields);
                    result.add(entry.getValue());
                }
                return result;
            }
        }
    }

    public static int exportCsv(File file, List<String> fieldKeys) throws Exception {
        return exportCsv(file, fieldKeys, null);
    }

    public static int exportCsv(File file, List<String> fieldKeys, String label) throws Exception {
        flush();
        List<String> fields = normalizeFieldKeys(fieldKeys);
        File parent = file.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("create export directory failed");
        }
        synchronized (DB_LOCK) {
            try (Connection conn = openConnection()) {
                ensureSchema(conn);
                List<Map<String, String>> rows = loadRows(conn, fields, label);
                try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                        new FileOutputStream(file), StandardCharsets.UTF_8))) {
                    writeCsvLine(writer, labelsByKeys(fields));
                    for (Map<String, String> row : rows) {
                        ArrayList<String> values = new ArrayList<>();
                        for (String field : fields) {
                            values.add(row.getOrDefault(field, ""));
                        }
                        writeCsvLine(writer, values);
                    }
                }
                return rows.size();
            }
        }
    }

    public static void flush() {
        ExecutorService oldExecutor;
        synchronized (EXECUTOR_LOCK) {
            oldExecutor = sExecutor;
            oldExecutor.shutdown();
            sExecutor = createExecutor();
        }
        try {
            if (!oldExecutor.awaitTermination(30, TimeUnit.SECONDS)) {
                Logger.error("Flush task persistence timeout");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public static void close() {
        ExecutorService executor;
        synchronized (EXECUTOR_LOCK) {
            executor = sExecutor;
            sExecutor = createExecutor();
        }
        executor.shutdown();
        try {
            if (!executor.awaitTermination(30, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    private static ExecutorService executor() {
        synchronized (EXECUTOR_LOCK) {
            if (sExecutor.isShutdown() || sExecutor.isTerminated()) {
                sExecutor = createExecutor();
            }
            return sExecutor;
        }
    }

    private static ExecutorService createExecutor() {
        return Executors.newSingleThreadExecutor(r -> {
            Thread thread = new Thread(r, "OneScan-task-persistence");
            thread.setDaemon(true);
            return thread;
        });
    }

    private static Connection openConnection() throws Exception {
        String dbPath = getDatabasePath();
        File dbFile = new File(dbPath);
        File dir = PathUtils.getParentFile(dbPath);
        if (dir != null && !dir.exists() && !FileUtils.mkdirs(dir)) {
            throw new IllegalStateException("create sqlite directory failed");
        }
        Class.forName("org.sqlite.JDBC");
        return DriverManager.getConnection("jdbc:sqlite:" + dbFile.getAbsolutePath());
    }

    private static void ensureSchema(Connection conn) throws SQLException {
        try (Statement st = conn.createStatement()) {
            st.execute("""
                    CREATE TABLE IF NOT EXISTS task_records (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
                        data_label TEXT NOT NULL DEFAULT '',
                        task_id INTEGER
                    )
                    """);
            if (!hasColumn(conn, "task_records", "data_label")) {
                st.execute("ALTER TABLE task_records ADD COLUMN data_label TEXT NOT NULL DEFAULT ''");
            }
            st.execute("""
                    CREATE TABLE IF NOT EXISTS task_fields (
                        record_id INTEGER NOT NULL,
                        field_key TEXT NOT NULL,
                        field_value TEXT,
                        PRIMARY KEY (record_id, field_key),
                        FOREIGN KEY (record_id) REFERENCES task_records(id) ON DELETE CASCADE
                    )
                    """);
            st.execute("CREATE INDEX IF NOT EXISTS idx_task_records_label ON task_records(data_label)");
            st.execute("CREATE INDEX IF NOT EXISTS idx_task_fields_key ON task_fields(field_key)");
        }
    }

    private static boolean hasColumn(Connection conn, String tableName, String columnName) throws SQLException {
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("PRAGMA table_info(" + tableName + ")")) {
            while (rs.next()) {
                if (columnName.equalsIgnoreCase(rs.getString("name"))) {
                    return true;
                }
            }
        }
        return false;
    }

    private static long insertRecord(Connection conn, TaskData data, String label) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO task_records (data_label, task_id) VALUES (?, ?)", Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, normalizeLabel(label));
            ps.setInt(2, data.getId());
            ps.executeUpdate();
            try (ResultSet rs = ps.getGeneratedKeys()) {
                if (rs.next()) {
                    return rs.getLong(1);
                }
            }
        }
        throw new SQLException("insert record id not returned");
    }

    private static void insertFields(Connection conn, long recordId, TaskData data, List<String> fields) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT OR REPLACE INTO task_fields (record_id, field_key, field_value) VALUES (?, ?, ?)")) {
            for (String field : fields) {
                ps.setLong(1, recordId);
                ps.setString(2, field);
                ps.setString(3, getFieldValue(data, field));
                ps.addBatch();
            }
            // 始终持久化原始请求/响应字节（不受字段配置影响）
            for (String bytesKey : new String[]{FIELD_REQ_BYTES, FIELD_RESP_BYTES}) {
                if (!fields.contains(bytesKey)) {
                    String value = getFieldValue(data, bytesKey);
                    if (!value.isEmpty()) {
                        ps.setLong(1, recordId);
                        ps.setString(2, bytesKey);
                        ps.setString(3, value);
                        ps.addBatch();
                    }
                }
            }
            ps.executeBatch();
        }
    }

    private static LinkedHashMap<Long, TaskData> loadTaskRecords(Connection conn, String label) throws SQLException {
        LinkedHashMap<Long, TaskData> result = new LinkedHashMap<>();
        try (PreparedStatement ps = conn.prepareStatement("""
                SELECT id, task_id
                FROM task_records
                WHERE %s
                ORDER BY id ASC
                """.formatted(labelWhereSql(label)))) {
            setLabelParameter(ps, 1, label);
            try (ResultSet rs = ps.executeQuery()) {
                int fallbackId = 0;
                while (rs.next()) {
                    TaskData data = new TaskData();
                    int taskId = rs.getInt("task_id");
                    data.setId(rs.wasNull() ? fallbackId : taskId);
                    result.put(rs.getLong("id"), data);
                    fallbackId++;
                }
            }
        }
        return result;
    }

    private static LinkedHashMap<Long, Map<String, String>> loadAllFieldRows(Connection conn, String label)
            throws SQLException {
        LinkedHashMap<Long, Map<String, String>> result = new LinkedHashMap<>();
        try (PreparedStatement ps = conn.prepareStatement("""
                SELECT f.record_id, f.field_key, f.field_value
                FROM task_fields f
                INNER JOIN task_records r ON r.id = f.record_id
                WHERE %s
                ORDER BY f.record_id ASC
                """.formatted(labelWhereSql(label)))) {
            setLabelParameter(ps, 1, label);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    long recordId = rs.getLong("record_id");
                    Map<String, String> row = result.computeIfAbsent(recordId, key -> new LinkedHashMap<>());
                    row.put(rs.getString("field_key"), rs.getString("field_value"));
                }
            }
        }
        return result;
    }

    private static List<Map<String, String>> loadRows(Connection conn, List<String> fields, String label)
            throws SQLException {
        LinkedHashMap<Long, Map<String, String>> result = new LinkedHashMap<>();
        boolean filterLabel = StringUtils.isNotEmpty(label);
        String sql = filterLabel ? """
                SELECT id
                FROM task_records
                WHERE %s
                ORDER BY id ASC
                """.formatted(labelWhereSql(label)) : """
                SELECT id
                FROM task_records
                ORDER BY id ASC
                """;
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            if (filterLabel) {
                setLabelParameter(ps, 1, label);
            }
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    result.put(rs.getLong("id"), new LinkedHashMap<>());
                }
            }
        }
        if (result.isEmpty()) {
            return new ArrayList<>();
        }
        String fieldPlaceholders = String.join(",", Collections.nCopies(fields.size(), "?"));
        String fieldSql = filterLabel ? """
                SELECT f.record_id, f.field_key, f.field_value
                FROM task_fields f
                INNER JOIN task_records r ON r.id = f.record_id
                WHERE %s AND f.field_key IN (%s)
                ORDER BY f.record_id ASC
                """.formatted(labelWhereSql(label), fieldPlaceholders) : """
                SELECT f.record_id, f.field_key, f.field_value
                FROM task_fields f
                WHERE f.field_key IN (%s)
                ORDER BY f.record_id ASC
                """.formatted(fieldPlaceholders);
        try (PreparedStatement ps = conn.prepareStatement(fieldSql)) {
            int index = 1;
            if (filterLabel) {
                setLabelParameter(ps, index++, label);
            }
            for (String field : fields) {
                ps.setString(index++, field);
            }
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    Map<String, String> row = result.get(rs.getLong("record_id"));
                    if (row != null) {
                        row.put(rs.getString("field_key"), rs.getString("field_value"));
                    }
                }
            }
        }
        return new ArrayList<>(result.values());
    }

    private static String labelWhereSql(String label) {
        String dataLabel = normalizeLabel(label);
        if (DEFAULT_DATA_LABEL.equals(dataLabel)) {
            return "(data_label = ? OR data_label = '')";
        }
        return "data_label = ?";
    }

    private static void setLabelParameter(PreparedStatement ps, int parameterIndex, String label) throws SQLException {
        ps.setString(parameterIndex, normalizeLabel(label));
    }

    private static void applyFields(TaskData data, Map<String, String> fields) {
        data.setFrom(safe(fields.get(FIELD_FROM)));
        data.setMethod(safe(fields.get(FIELD_METHOD)));
        data.setHost(safe(fields.get(FIELD_HOST)));
        data.setUrl(safe(fields.get(FIELD_URL)));
        data.setTitle(safe(fields.get(FIELD_TITLE)));
        data.setIp(safe(fields.get(FIELD_IP)));
        data.setStatus(parseInt(fields.get(FIELD_STATUS)));
        data.setLength(parseInt(fields.get(FIELD_LENGTH)));
        data.setHighlight(safe(fields.get(FIELD_COLOR)));

        LinkedHashMap<String, String> params = new LinkedHashMap<>();
        Map<String, Object> jsonParams = GsonUtils.toMap(fields.get(FIELD_PARAMS));
        if (jsonParams != null) {
            for (Map.Entry<String, Object> entry : jsonParams.entrySet()) {
                params.put(entry.getKey(), entry.getValue() == null ? "" : String.valueOf(entry.getValue()));
            }
        }
        for (Map.Entry<String, String> entry : fields.entrySet()) {
            String key = entry.getKey();
            if (key.startsWith("param:")) {
                params.put(key.substring("param:".length()), safe(entry.getValue()));
            }
        }
        data.setParams(params);

        // 恢复原始请求/响应字节
        data.setReqBytes(base64ToBytes(fields.get(FIELD_REQ_BYTES)));
        data.setRespBytes(base64ToBytes(fields.get(FIELD_RESP_BYTES)));
    }

    public static String getFieldValue(TaskData data, String key) {
        if (data == null || key == null) {
            return "";
        }
        return switch (key) {
            case FIELD_FROM -> safe(data.getFrom());
            case FIELD_METHOD -> safe(data.getMethod());
            case FIELD_HOST -> safe(data.getHost());
            case FIELD_URL -> safe(data.getUrl());
            case FIELD_TITLE -> safe(data.getTitle());
            case FIELD_IP -> safe(data.getIp());
            case FIELD_STATUS -> String.valueOf(data.getStatus());
            case FIELD_LENGTH -> String.valueOf(data.getLength());
            case FIELD_COLOR -> safe(data.getHighlight());
            case FIELD_PARAMS -> GsonUtils.toJson(data.getParams());
            case FIELD_REQ_BYTES -> bytesToBase64(data.getReqBytes());
            case FIELD_RESP_BYTES -> bytesToBase64(data.getRespBytes());
            default -> {
                if (key.startsWith("param:")) {
                    yield safe(data.getParams().get(key.substring("param:".length())));
                }
                yield "";
            }
        };
    }

    // ──────────────── 历史数据管理删除接口 ────────────────

    /** 删除所有历史记录 */
    public static int deleteAll() {
        flush();
        synchronized (DB_LOCK) {
            try (Connection conn = openConnection()) {
                ensureSchema(conn);
                try (Statement st = conn.createStatement()) {
                    return st.executeUpdate("DELETE FROM task_records");
                }
            } catch (Exception e) {
                Logger.error("deleteAll failed: %s", e.getMessage());
                return 0;
            }
        }
    }

    /** 删除指定标签列表的历史记录 */
    public static int deleteByLabels(List<String> labels) {
        if (labels == null || labels.isEmpty()) {
            return 0;
        }
        flush();
        synchronized (DB_LOCK) {
            try (Connection conn = openConnection()) {
                ensureSchema(conn);
                int total = 0;
                for (String label : labels) {
                    String dataLabel = normalizeLabel(label);
                    String sql = "DELETE FROM task_records WHERE " + labelWhereSql(dataLabel);
                    try (PreparedStatement ps = conn.prepareStatement(sql)) {
                        setLabelParameter(ps, 1, dataLabel);
                        total += ps.executeUpdate();
                    }
                }
                return total;
            } catch (Exception e) {
                Logger.error("deleteByLabels failed: %s", e.getMessage());
                return 0;
            }
        }
    }

    /**
     * 按站点（host 字段模糊匹配）删除历史记录
     *
     * @param hostPattern 站点关键字，支持 SQL LIKE 语法（例如 "%example.com%"）
     * @return 删除条数
     */
    public static int deleteByHostPattern(String hostPattern) {
        if (StringUtils.isEmpty(hostPattern)) {
            return 0;
        }
        flush();
        synchronized (DB_LOCK) {
            try (Connection conn = openConnection()) {
                ensureSchema(conn);
                // 先找到 host 字段匹配的 record_id
                String sql = """
                        DELETE FROM task_records
                        WHERE id IN (
                            SELECT DISTINCT r.id FROM task_records r
                            INNER JOIN task_fields f ON f.record_id = r.id
                            WHERE f.field_key = 'host' AND f.field_value LIKE ?
                        )
                        """;
                try (PreparedStatement ps = conn.prepareStatement(sql)) {
                    ps.setString(1, hostPattern);
                    return ps.executeUpdate();
                }
            } catch (Exception e) {
                Logger.error("deleteByHostPattern failed: %s", e.getMessage());
                return 0;
            }
        }
    }

    /** 列出所有不同的 host 值（用于按站点删除的下拉选择） */
    public static List<String> listDistinctHosts() {
        flush();
        synchronized (DB_LOCK) {
            try (Connection conn = openConnection()) {
                ensureSchema(conn);
                List<String> result = new ArrayList<>();
                try (PreparedStatement ps = conn.prepareStatement("""
                        SELECT DISTINCT field_value FROM task_fields
                        WHERE field_key = 'host' AND field_value != ''
                        ORDER BY field_value ASC
                        """);
                     ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        String v = rs.getString("field_value");
                        if (StringUtils.isNotEmpty(v)) {
                            result.add(v);
                        }
                    }
                }
                return result;
            } catch (Exception e) {
                Logger.error("listDistinctHosts failed: %s", e.getMessage());
                return new ArrayList<>();
            }
        }
    }

    // ──────────────── Base64 字节与字符串互转 ────────────────

    private static String bytesToBase64(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static byte[] base64ToBytes(String base64) {
        if (StringUtils.isEmpty(base64)) {
            return null;
        }
        try {
            return Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static List<String> labelsByKeys(List<String> keys) {
        ArrayList<String> labels = new ArrayList<>();
        Map<String, String> labelMap = new LinkedHashMap<>();
        for (FieldDef field : getSelectableFields()) {
            labelMap.put(field.key(), field.label());
        }
        for (String key : keys) {
            labels.add(labelMap.getOrDefault(key, key));
        }
        return labels;
    }

    private static void writeCsvLine(BufferedWriter writer, List<String> values) throws Exception {
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                writer.write(',');
            }
            writer.write(escapeCsv(values.get(i)));
        }
        writer.newLine();
    }

    private static String escapeCsv(String value) {
        String text = value == null ? "" : value;
        if (text.contains("\"") || text.contains(",") || text.contains("\r") || text.contains("\n")) {
            return "\"" + text.replace("\"", "\"\"") + "\"";
        }
        return text;
    }

    private static String normalizeLabel(String label) {
        if (label == null) {
            return DEFAULT_DATA_LABEL;
        }
        String result = label.trim();
        return result.isEmpty() ? DEFAULT_DATA_LABEL : result;
    }

    private static int parseInt(String value) {
        return StringUtils.parseInt(value, 0);
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    public record FieldDef(String key, String label) {
    }

    public record HistoryLabel(String label, int count) {

        @Override
        public String toString() {
            return "%s (%d)".formatted(label, count);
        }
    }

    public record SaveResult(String label, int count) {
    }
}
