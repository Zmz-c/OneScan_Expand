package burp.vaycore.ost.common;

import burp.vaycore.common.config.ConfigManager;
import burp.vaycore.common.filter.FilterRule;
import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.*;
import burp.vaycore.ost.bean.IdentityProfile;
import burp.vaycore.ost.bean.VariableDefinition;
import burp.vaycore.ost.manager.CollectManager;
import burp.vaycore.ost.manager.FpManager;
import burp.vaycore.ost.manager.VariableManager;
import burp.vaycore.ost.manager.WordlistManager;
import burp.vaycore.ost.ui.widget.payloadlist.PayloadItem;
import burp.vaycore.ost.ui.widget.payloadlist.PayloadRule;
import burp.vaycore.ost.ui.widget.payloadlist.ProcessingItem;
import burp.vaycore.ost.ui.widget.payloadlist.SimplePayloadList;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 配置类
 * <p>
 * Created by vaycore on 2022-08-19.
 */
public class Config {
    // 配置项
    public static final String KEY_VERSION = "version";
    public static final String KEY_PAYLOAD_PROCESS_LIST = "payload-process-list";
    public static final String KEY_QPS_LIMIT = "qps-limit";
    public static final String KEY_REQUEST_DELAY = "request-delay";
    public static final String KEY_SCAN_LEVEL_DIRECT = "scan-level-direct";
    public static final String KEY_SCAN_LEVEL = "scan-level";
    public static final String KEY_RETRY_COUNT = "retry-count";
    public static final String KEY_RETRY_INTERVAL = "retry-interval";
    public static final String KEY_MAX_DISPLAY_LENGTH = "max-display-length";
    public static final String KEY_COLLECT_PATH = "collect-path";
    public static final String KEY_EXCLUDE_SUFFIX = "exclude-suffix";
    public static final String KEY_INCLUDE_METHOD = "include-method";
    public static final String KEY_WORDLIST_PATH = "dict-path";
    public static final String KEY_DATABOARD_FILTER_RULES = "databoard-filter-rules";
    public static final String KEY_DATA_PERSISTENCE_ENABLED = "data-persistence-enabled";
    public static final String KEY_DATA_PERSISTENCE_DB_PATH = "data-persistence-db-path";
    public static final String KEY_DATA_PERSISTENCE_AUTO_SAVE_INTERVAL = "data-persistence-auto-save-interval";
    public static final String KEY_DATA_PERSISTENCE_FIELDS = "data-persistence-fields";
    public static final String KEY_ENABLE_MCP = "enable-mcp";
    public static final String KEY_FOLLOW_REDIRECT = "follow-redirect";
    public static final String KEY_REDIRECT_COOKIES_FOLLOW = "redirect-cookies-follow";
    public static final String KEY_REDIRECT_TARGET_HOST_LIMIT = "redirect-target-host-limit";
    public static final String KEY_INTERCEPT_TIMEOUT_HOST = "intercept-timeout-host";
    public static final String KEY_VARIABLE_DEFINITIONS = "variable-definitions";
    public static final String KEY_IDENTITY_PROFILES = "identity-profiles";
    public static final String KEY_NAMED_VARIABLE_DEFAULTS_INITIALIZED =
            "named-variable-defaults-initialized";
    // 首页开关配置项
    public static final String KEY_ENABLE_LISTEN_PROXY = "enable-listen-proxy";
    public static final String KEY_ENABLE_BROWSER_REQUEST = "enable-browser-request";
    public static final String KEY_BROWSER_PYTHON_PATH = "browser-python-path";
    public static final String KEY_BROWSER_BINARY_PATH = "browser-binary-path";
    public static final String KEY_BROWSER_TYPE = "browser-type";
    public static final String KEY_BROWSER_TIMEOUT = "browser-timeout";
    public static final String KEY_BROWSER_LOAD_STATIC_RESOURCES = "browser-load-static-resources";
    public static final String KEY_BROWSER_TARGET_HOST_REGEX = "browser-target-host-regex";
    public static final String KEY_ENABLE_REMOVE_HEADER = "enable-remove-header";
    public static final String KEY_ENABLE_REPLACE_HEADER = "enable-replace-header";
    public static final String KEY_ENABLE_DIR_SCAN = "enable-dir-scan";
    public static final String KEY_ENABLE_PAYLOAD_PROCESSING = "payload-processing";
    // 配置常量值
    public static final String DIRECT_LEFT = "left";
    public static final String DIRECT_RIGHT = "right";
    public static final String BROWSER_TYPE_EDGE = "edge";
    public static final String BROWSER_TYPE_CHROME = "chrome";
    public static final String BROWSER_TYPE_FIREFOX = "firefox";

    private static String sWorkDir;
    private static String sConfigPath;
    private static ConfigManager sConfigManager;

    public static void init(String wordDir) {
        sWorkDir = wordDir;
        sConfigPath = getWorkDir() + "config.json";
        sConfigManager = new ConfigManager(sConfigPath);
        initDefaultConfig(Config.KEY_VERSION, Constants.PLUGIN_VERSION);
        initDefaultConfig(Config.KEY_QPS_LIMIT, "1024");
        initDefaultConfig(Config.KEY_REQUEST_DELAY, "0");
        initDefaultConfig(Config.KEY_SCAN_LEVEL_DIRECT, "left");
        initDefaultConfig(Config.KEY_SCAN_LEVEL, "99");
        initDefaultConfig(Config.KEY_RETRY_COUNT, "3");
        initDefaultConfig(Config.KEY_RETRY_INTERVAL, "3000");
        initDefaultConfig(Config.KEY_MAX_DISPLAY_LENGTH, "0");
        initDefaultConfig(Config.KEY_COLLECT_PATH, getWorkDir() + "collect");
        initDefaultConfig(KEY_EXCLUDE_SUFFIX, "3g2|3gp|7z|aac|abw|aif|aifc|aiff|arc|au|avi|azw|bin|bmp|bz|" +
                "bz2|cmx|cod|csh|css|csv|doc|docx|eot|epub|gif|gz|ico|ics|ief|jar|jfif|jpe|jpeg|jpg|m3u|mid|midi|" +
                "mjs|mp2|mp3|mpa|mpe|mpeg|mpg|mpkg|mpp|mpv2|odp|ods|odt|oga|ogv|ogx|otf|pbm|pdf|pgm|png|pnm|ppm|" +
                "ppt|pptx|ra|ram|rar|ras|rgb|rmi|rtf|snd|svg|swf|tar|tif|tiff|ttf|vsd|wav|weba|webm|webp|woff|" +
                "woff2|xbm|xls|xlsx|xpm|xul|xwd|zip");
        initDefaultConfig(Config.KEY_INCLUDE_METHOD, "GET|POST");
        initDefaultConfig(Config.KEY_WORDLIST_PATH, getWorkDir() + "wordlist");
        initDefaultConfig(Config.KEY_DATA_PERSISTENCE_ENABLED, "false");
        initDefaultConfig(Config.KEY_DATA_PERSISTENCE_DB_PATH, getWorkDir() + "ost-data.sqlite");
        initDefaultConfig(Config.KEY_DATA_PERSISTENCE_AUTO_SAVE_INTERVAL, "60");
        initDefaultConfig(Config.KEY_DATA_PERSISTENCE_FIELDS, "from,method,host,url,title,ip,status,length,color,profile,variant");
        initDefaultConfig(Config.KEY_ENABLE_MCP, "false");
        initDefaultConfig(Config.KEY_FOLLOW_REDIRECT, "true");
        initDefaultConfig(Config.KEY_REDIRECT_COOKIES_FOLLOW, "true");
        initDefaultConfig(Config.KEY_REDIRECT_TARGET_HOST_LIMIT, "true");
        initDefaultConfig(Config.KEY_INTERCEPT_TIMEOUT_HOST, "false");
        initDefaultConfig(Config.KEY_VARIABLE_DEFINITIONS, "[]");
        initDefaultConfig(Config.KEY_IDENTITY_PROFILES, "[]");
        // 默认开关配置
        initDefaultConfig(Config.KEY_ENABLE_LISTEN_PROXY, "false");
        initDefaultConfig(Config.KEY_ENABLE_BROWSER_REQUEST, "false");
        initDefaultConfig(Config.KEY_BROWSER_PYTHON_PATH, "");
        initDefaultConfig(Config.KEY_BROWSER_BINARY_PATH, "");
        initDefaultConfig(Config.KEY_BROWSER_TYPE, Config.BROWSER_TYPE_EDGE);
        initDefaultConfig(Config.KEY_BROWSER_TIMEOUT, "15000");
        initDefaultConfig(Config.KEY_BROWSER_LOAD_STATIC_RESOURCES, "false");
        initDefaultConfig(Config.KEY_BROWSER_TARGET_HOST_REGEX, "");
        initDefaultConfig(Config.KEY_ENABLE_REMOVE_HEADER, "false");
        initDefaultConfig(Config.KEY_ENABLE_REPLACE_HEADER, "true");
        initDefaultConfig(Config.KEY_ENABLE_DIR_SCAN, "true");
        initDefaultConfig(Config.KEY_ENABLE_PAYLOAD_PROCESSING, "true");
        String browserType = sanitizeBrowserType(get(Config.KEY_BROWSER_TYPE));
        if (!browserType.equals(get(Config.KEY_BROWSER_TYPE))) {
            put(Config.KEY_BROWSER_TYPE, browserType);
        }
        // 初始化数据收集管理
        CollectManager.init(get(Config.KEY_COLLECT_PATH));
        // 初始化字典管理
        WordlistManager.init(get(Config.KEY_WORDLIST_PATH));
        // 初始化指纹管理
        initFpManager();
        // 版本更新处理
        onVersionUpgrade();
        // 预加载一些需要实例化成对象的配置
        onPreloadConfig();
    }

    private static void initFpManager() {
        String path = getWorkDir() + "fp_config.json";
        if (!FileUtils.isFile(path)) {
            InputStream is = Config.class.getClassLoader().getResourceAsStream("fp_config.json");
            String content = FileUtils.readStreamToString(is);
            FileUtils.writeFile(path, content);
        }
        FpManager.init(path);
    }

    private static void onVersionUpgrade() {
        String version = getVersion();
        if (!version.equals(Constants.PLUGIN_VERSION)) {
            putVersion(Constants.PLUGIN_VERSION);
            backupConfig(version);
            upgradeConfigKey();
            upgradeDomain();
            upgradeHeaders();
            upgradeRemoveHeaderList();
            upgradeWordlist();
            upgradePayloadProcessing(version);
        }
    }

    /**
     * 备份配置（从0.x版本升级到1.x时备份）
     */
    private static void backupConfig(String oldVersion) {
        if (!oldVersion.startsWith("0.")) {
            return;
        }
        String bakPath = sConfigPath + ".bak";
        String content = FileUtils.readFileToString(sConfigPath);
        FileUtils.writeFile(bakPath, content);
        Logger.info("Welcome to update version %s, the configuration file has been backed up to the %s",
                Constants.PLUGIN_VERSION, bakPath);
    }

    private static void upgradeConfigKey() {
        // 将 enable-exclude-header 配置项迁移到新字段
        if (hasKey("enable-exclude-header")) {
            String enable = get("enable-exclude-header");
            sConfigManager.put(Config.KEY_ENABLE_REMOVE_HEADER, enable);
            sConfigManager.remove("enable-exclude-header");
        }
        // 将 white-host 配置项迁移到新字段
        if (hasKey("white-host")) {
            String enable = get("white-host");
            sConfigManager.put(WordlistManager.KEY_HOST_ALLOWLIST, enable);
            sConfigManager.remove("white-host");
        }
        // 将 black-host 配置项迁移到新字段
        if (hasKey("black-host")) {
            String enable = get("black-host");
            sConfigManager.put(WordlistManager.KEY_HOST_BLOCKLIST, enable);
            sConfigManager.remove("black-host");
        }
        // 将 exclude-headers 配置项迁移到新字段
        if (hasKey("exclude-headers")) {
            String enable = get("exclude-headers");
            sConfigManager.put(WordlistManager.KEY_REMOVE_HEADERS, enable);
            sConfigManager.remove("exclude-headers");
        }
        // 将 hae-plugin-path 配置项删除
        if (hasKey("hae-plugin-path")) {
            sConfigManager.remove("hae-plugin-path");
        }
        if (hasKey("browser-driver")) {
            sConfigManager.remove("browser-driver");
        }
        if (hasKey("browser-driver-path")) {
            sConfigManager.remove("browser-driver-path");
        }
        if (hasKey("enable-browser-js")) {
            sConfigManager.remove("enable-browser-js");
        }
        if (hasKey("enable-browser-proxy")) {
            sConfigManager.remove("enable-browser-proxy");
        }
    }

    private static void upgradeDomain() {
        String configJson = FileUtils.readFileToString(sConfigPath);
        if (configJson.contains("{{mdomain}}")) {
            configJson = configJson.replace("{{mdomain}}", "{{domain.name}}");
            boolean state = FileUtils.writeFile(sConfigPath, configJson);
            if (state) {
                Logger.info("Replace all {{mdomain}} to {{domain.name}} ok!");
                init(sWorkDir);
            }
        }
    }

    private static void upgradeHeaders() {
        List<String> defaultHeaders = WordlistManager.getList(WordlistManager.KEY_HEADERS, "default");
        // 默认配置已删除的情况
        if (defaultHeaders.isEmpty()) {
            return;
        }
        String joinResult = StringUtils.join(defaultHeaders, ",");
        // 新 headers 配置的 MD5 值
        String headersMd5 = Utils.md5(joinResult.getBytes(StandardCharsets.UTF_8));
        // 旧 headers 配置的 MD5 值
        String matchMd5 = "6eb466e03eda48b29275da941bfed84c";
        // 默认配置的 headers 如果无变更，将旧配置替换为新的配置
        if (headersMd5.equals(matchMd5)) {
            InputStream is = Config.class.getClassLoader().getResourceAsStream("header.txt");
            ArrayList<String> list = FileUtils.readStreamToList(is);
            WordlistManager.putList(WordlistManager.KEY_HEADERS, "default", list);
        }
    }

    private static void upgradeRemoveHeaderList() {
        // 将remove-header-list配置项迁移到新字段
        if (hasKey("remove-header-list")) {
            ArrayList<String> list = getList("remove-header-list");
            WordlistManager.putList(WordlistManager.KEY_REMOVE_HEADERS, list);
            sConfigManager.remove("remove-header-list");
        }
    }

    private static void upgradeWordlist() {
        ArrayList<String> list;
        if (hasKey("payload-list")) {
            list = getList("payload-list");
            WordlistManager.putList(WordlistManager.KEY_PAYLOAD, list);
            sConfigManager.remove("payload-list");
        }

        if (hasKey("header-list")) {
            list = getList("header-list");
            WordlistManager.putList(WordlistManager.KEY_HEADERS, list);
            sConfigManager.remove("header-list");
        }

        if (hasKey("user-agent-list")) {
            list = getList("user-agent-list");
            WordlistManager.putList(WordlistManager.KEY_USER_AGENT, list);
            WordlistManager.replaceMigratedUserAgentValues(list);
            sConfigManager.remove("user-agent-list");
        }

        if (hasKey("whitelist")) {
            list = getList("whitelist");
            WordlistManager.putList(WordlistManager.KEY_HOST_ALLOWLIST, list);
            sConfigManager.remove("whitelist");
        }

        if (hasKey("blacklist")) {
            list = getList("blacklist");
            WordlistManager.putList(WordlistManager.KEY_HOST_BLOCKLIST, list);
            sConfigManager.remove("blacklist");
        }

        if (hasKey("exclude-header")) {
            list = getList("exclude-header");
            WordlistManager.putList(WordlistManager.KEY_REMOVE_HEADERS, list);
            sConfigManager.remove("exclude-header");
        }

        if (hasKey("web-name-collect-path")) {
            sConfigManager.remove("web-name-collect-path");
        }

        if (hasKey("json-field-collect-path")) {
            sConfigManager.remove("json-field-collect-path");
        }
    }

    private static void upgradePayloadProcessing(String oldVersion) {
        // 版本检测（从 OST <= 1.3.7 版本升级时需要变更配置）
        String version = oldVersion.replace(".", "");
        int versionInt = StringUtils.parseInt(version);
        if (versionInt == 0 || versionInt > 137) {
            return;
        }
        // Merge Payload Processing 开关配置更新
        if (hasKey("merge-payload-processing")) {
            boolean configValue = getBoolean("merge-payload-processing");
            put(Config.KEY_ENABLE_PAYLOAD_PROCESSING, String.valueOf(configValue));
            sConfigManager.remove("merge-payload-processing");
        }
        // Payload Processing 的结构迁移统一由 preparePayloadProcessList() 完成，
        // 避免同一次初始化中重复转换已实例化的 ProcessingItem。
    }

    private static void onPreloadConfig() {
        preparePayloadProcessList();
        prepareDataboardFilterRules();
        prepareVariableDefinitions();
        ensureBundledNamedVariableDefinitions();
        prepareIdentityProfiles();
    }

    private static void initDefaultConfig(String key, String defValue) {
        if (!hasKey(key)) {
            sConfigManager.put(key, defValue);
        }
    }

    private static void checkInit() {
        if (sConfigManager == null) {
            throw new IllegalStateException("Config class is not initialize");
        }
    }

    public static String getWorkDir() {
        if (StringUtils.isNotEmpty(sWorkDir) && FileUtils.isDir(sWorkDir)) {
            return sWorkDir;
        }
        return PathUtils.getUserHome() + ".config" + File.separator + "OST" + File.separator;
    }

    public static String getVersion() {
        return get(KEY_VERSION);
    }

    public static String sanitizeBrowserType(String value) {
        if (BROWSER_TYPE_CHROME.equalsIgnoreCase(value)) {
            return BROWSER_TYPE_CHROME;
        }
        return BROWSER_TYPE_EDGE;
    }

    public static void putVersion(String version) {
        put(KEY_VERSION, version);
    }

    public static String getFilePath(String key) {
        return getFilePath(key, false);
    }

    public static String getFilePath(String key, boolean isDir) {
        checkInit();
        String path = sConfigManager.get(key);
        if (StringUtils.isEmpty(path)) {
            return path;
        }
        File dir = isDir ? new File(path) : new File(path).getParentFile();
        if (!dir.exists()) {
            boolean state = dir.mkdirs();
            Logger.debug("Config item path state: %s", state);
        }
        return path;
    }

    public static void put(String key, String text) {
        checkInit();
        sConfigManager.put(key, text);
    }

    public static void put(String key, Object obj) {
        checkInit();
        if (Config.KEY_VARIABLE_DEFINITIONS.equals(key)) {
            obj = copyVariableDefinitions(obj);
        } else if (Config.KEY_IDENTITY_PROFILES.equals(key)) {
            obj = copyIdentityProfiles(obj);
        }
        sConfigManager.put(key, obj);
    }

    public static String get(String key) {
        checkInit();
        return sConfigManager.get(key);
    }

    public static int getInt(String key) {
        checkInit();
        String value = sConfigManager.get(key);
        return StringUtils.parseInt(value);
    }

    public static boolean getBoolean(String key) {
        checkInit();
        String value = sConfigManager.get(key);
        return "true".equals(value);
    }

    public static ArrayList<String> getList(String key) {
        checkInit();
        return sConfigManager.getList(key);
    }

    public static boolean hasKey(String key) {
        checkInit();
        return sConfigManager.hasKey(key);
    }

    public static void removeKey(String key) {
        checkInit();
        sConfigManager.remove(key);
    }

    private static void preparePayloadProcessList() {
        try {
            Object rawValue = sConfigManager.get(Config.KEY_PAYLOAD_PROCESS_LIST);
            List<?> items = asList(rawValue);
            if (items == null) {
                return;
            }
            ArrayList<ProcessingItem> result = new ArrayList<>();
            ArrayList<Map<String, Object>> legacyRules = new ArrayList<>();
            for (Object rawItem : items) {
                if (rawItem instanceof ProcessingItem) {
                    result.add((ProcessingItem) rawItem);
                    continue;
                }
                Map<String, Object> mapItem = asMap(rawItem);
                if (mapItem == null) {
                    continue;
                }
                if (mapItem.containsKey("ruleType")) {
                    legacyRules.add(mapItem);
                    continue;
                }
                ProcessingItem item = new ProcessingItem();
                item.setEnabled(Boolean.TRUE.equals(mapItem.get("enabled")));
                item.setMerge(Boolean.parseBoolean(stringValue(mapItem.get("merge"))));
                String name = stringValue(mapItem.get("name"));
                item.setName(name == null ? "" : name);
                item.setItems(mapItemsConvert(asPayloadMaps(asList(mapItem.get("items")))));
                result.add(item);
            }
            if (!legacyRules.isEmpty()) {
                ProcessingItem migrated = new ProcessingItem();
                migrated.setEnabled(true);
                migrated.setMerge(false);
                migrated.setName("Low version rules");
                migrated.setItems(mapItemsConvert(legacyRules));
                result.add(0, migrated);
            }
            put(Config.KEY_PAYLOAD_PROCESS_LIST, result);
        } catch (Exception e) {
            Logger.debug("Skip invalid payload processing configuration: %s", e.getMessage());
        }
    }

    private static ArrayList<Map<String, Object>> asPayloadMaps(List<?> items) {
        ArrayList<Map<String, Object>> result = new ArrayList<>();
        if (items == null) {
            return result;
        }
        for (Object item : items) {
            Map<String, Object> map = asMap(item);
            if (map != null) {
                result.add(map);
            }
        }
        return result;
    }

    static ArrayList<PayloadItem> mapItemsConvert(List<? extends Map<String, Object>> items) {
        ArrayList<PayloadItem> result = new ArrayList<>();
        if (items == null || items.isEmpty()) {
            return result;
        }
        // Older configurations can omit fields; keep valid rules and use safe defaults.
        for (Map<String, Object> mapItem : items) {
            if (mapItem == null) {
                continue;
            }
            PayloadRule rule = SimplePayloadList.getPayloadRuleByType(stringValue(mapItem.get("ruleType")));
            if (rule == null) {
                Logger.debug("Skip invalid payload processing rule during config migration");
                continue;
            }
            PayloadItem item = new PayloadItem();
            item.setScope(payloadScope(mapItem.get("scope")));
            Map<String, Object> ruleMap = asMap(mapItem.get("rule"));
            List<?> ruleParamValues = ruleMap == null ? null : asList(ruleMap.get("paramValues"));
            for (int j = 0; j < rule.paramCount(); j++) {
                String paramValue = ruleParamValues != null && j < ruleParamValues.size()
                        ? stringValue(ruleParamValues.get(j)) : "";
                rule.setParamValue(j, paramValue == null ? "" : paramValue);
            }
            item.setRule(rule);
            result.add(item);
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        return value instanceof Map<?, ?> ? (Map<String, Object>) value : null;
    }

    private static List<?> asList(Object value) {
        return value instanceof List ? (List<?>) value : null;
    }

    private static String stringValue(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private static int payloadScope(Object value) {
        if (!(value instanceof Number)) {
            return PayloadRule.SCOPE_URL;
        }
        int scope = ((Number) value).intValue();
        return scope >= PayloadRule.SCOPE_URL && scope <= PayloadRule.SCOPE_REQUEST
                ? scope : PayloadRule.SCOPE_URL;
    }

    private static void prepareDataboardFilterRules() {
        Object obj = sConfigManager.get(Config.KEY_DATABOARD_FILTER_RULES);
        if (obj == null) {
            obj = new ArrayList<>();
        }
        String json = GsonUtils.toJson(obj);
        ArrayList<FilterRule> rules = GsonUtils.toList(json, FilterRule.class);
        put(Config.KEY_DATABOARD_FILTER_RULES, rules);
    }

    public static ArrayList<ProcessingItem> getPayloadProcessList() {
        checkInit();
        return sConfigManager.get(Config.KEY_PAYLOAD_PROCESS_LIST);
    }

    public static ArrayList<FilterRule> getDataboardFilterRules() {
        checkInit();
        return sConfigManager.get(Config.KEY_DATABOARD_FILTER_RULES);
    }

    private static void prepareVariableDefinitions() {
        Object obj = sConfigManager.get(Config.KEY_VARIABLE_DEFINITIONS);
        String json = obj instanceof String ? (String) obj : GsonUtils.toJson(obj);
        ArrayList<VariableDefinition> definitions = GsonUtils.toList(json, VariableDefinition.class);
        put(Config.KEY_VARIABLE_DEFINITIONS, definitions == null ? new ArrayList<>() : definitions);
    }

    /**
     * Adds the packaged variables once after persisted JSON has been converted to typed objects.
     * A later user deletion remains intentional and is not recreated on every startup.
     */
    private static void ensureBundledNamedVariableDefinitions() {
        if (getBoolean(KEY_NAMED_VARIABLE_DEFAULTS_INITIALIZED)) {
            return;
        }
        ArrayList<VariableDefinition> definitions = getVariableDefinitions();
        boolean changed = false;
        for (VariableDefinition defaultDefinition : VariableManager.getBundledVariableDefinitions()) {
            boolean exists = definitions.stream().anyMatch(item -> item != null
                    && defaultDefinition.getName().equalsIgnoreCase(item.getName()));
            if (!exists) {
                definitions.add(new VariableDefinition(defaultDefinition));
                changed = true;
            }
        }
        if (changed) {
            put(KEY_VARIABLE_DEFINITIONS, definitions);
        }
        put(KEY_NAMED_VARIABLE_DEFAULTS_INITIALIZED, "true");
    }

    private static void prepareIdentityProfiles() {
        Object obj = sConfigManager.get(Config.KEY_IDENTITY_PROFILES);
        String json = obj instanceof String ? (String) obj : GsonUtils.toJson(obj);
        ArrayList<IdentityProfile> profiles = GsonUtils.toList(json, IdentityProfile.class);
        put(Config.KEY_IDENTITY_PROFILES, profiles == null ? new ArrayList<>() : profiles);
    }

    public static ArrayList<VariableDefinition> getVariableDefinitions() {
        checkInit();
        return copyVariableDefinitions(sConfigManager.get(Config.KEY_VARIABLE_DEFINITIONS));
    }

    public static ArrayList<IdentityProfile> getIdentityProfiles() {
        checkInit();
        return copyIdentityProfiles(sConfigManager.get(Config.KEY_IDENTITY_PROFILES));
    }

    private static ArrayList<VariableDefinition> copyVariableDefinitions(Object source) {
        ArrayList<VariableDefinition> result = new ArrayList<>();
        if (!(source instanceof Iterable<?> values)) {
            return result;
        }
        for (Object value : values) {
            if (value instanceof VariableDefinition definition) {
                result.add(new VariableDefinition(definition));
            }
        }
        return result;
    }

    private static ArrayList<IdentityProfile> copyIdentityProfiles(Object source) {
        ArrayList<IdentityProfile> result = new ArrayList<>();
        if (!(source instanceof Iterable<?> values)) {
            return result;
        }
        for (Object value : values) {
            if (value instanceof IdentityProfile profile) {
                result.add(new IdentityProfile(profile));
            }
        }
        return result;
    }
}
