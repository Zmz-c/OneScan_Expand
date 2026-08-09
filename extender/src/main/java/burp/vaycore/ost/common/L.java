package burp.vaycore.ost.common;

import java.util.Locale;
import java.util.ResourceBundle;

/**
 * 语言包辅助类
 * <p>
 * Created by vaycore on 2024-12-02.
 */
public class L {

    public static final String LANGUAGE_AUTO = "auto";
    public static final String LANGUAGE_CHINESE = "zh_CN";
    public static final String LANGUAGE_ENGLISH = "en_US";

    private static final Locale CHINESE_LOCALE = Locale.SIMPLIFIED_CHINESE;
    private static final Locale DEFAULT_LOCALE = Locale.US;
    private static final String sBaseName = "i18n/messages";
    private static volatile ResourceBundle sLanguage = loadLanguage(resolveLocale(LANGUAGE_AUTO));

    private L() {
        throw new IllegalAccessError("L class not support create instance.");
    }

    /**
     * 获取语言包中 key 对应的内容
     *
     * @param key key
     * @return key 对应的内容
     * @throws IllegalArgumentException key 不存在时抛出该异常
     */
    public static String get(String key) {
        return L.get(key, "");
    }

    /**
     * 获取语言包中 key 对应的内容
     *
     * @param key  key
     * @param args 格式化参数
     * @return key 对应的内容
     * @throws IllegalArgumentException key 不存在时抛出该异常
     */
    public static String get(String key, Object... args) {
        // 如果当前语言资源包找不到对应的值，到默认语言资源包里找
        ResourceBundle language = sLanguage;
        String value;
        if (language.containsKey(key)) {
            value = language.getString(key);
        } else {
            ResourceBundle defaultLanguage = loadLanguage(DEFAULT_LOCALE);
            if (!defaultLanguage.containsKey(key)) {
                return "Null";
            }
            value = defaultLanguage.getString(key);
        }
        return String.format(value, args);
    }

    /**
     * Selects the resource bundle used by the extension. Burp does not expose its display
     * language through the legacy extension API, so follow mode uses the JVM default locale,
     * which Burp sets from its display-language preference when it starts.
     */
    public static synchronized void configure(String languageSetting) {
        sLanguage = loadLanguage(resolveLocale(normalizeLanguageSetting(languageSetting)));
    }

    public static String normalizeLanguageSetting(String languageSetting) {
        if (LANGUAGE_CHINESE.equalsIgnoreCase(languageSetting)) {
            return LANGUAGE_CHINESE;
        }
        if (LANGUAGE_ENGLISH.equalsIgnoreCase(languageSetting)) {
            return LANGUAGE_ENGLISH;
        }
        return LANGUAGE_AUTO;
    }

    static Locale resolveLocale(String languageSetting) {
        if (LANGUAGE_CHINESE.equals(languageSetting)) {
            return CHINESE_LOCALE;
        }
        if (LANGUAGE_ENGLISH.equals(languageSetting)) {
            return DEFAULT_LOCALE;
        }
        Locale burpLocale = Locale.getDefault();
        return Locale.CHINESE.getLanguage().equalsIgnoreCase(burpLocale.getLanguage())
                ? CHINESE_LOCALE : DEFAULT_LOCALE;
    }

    private static ResourceBundle loadLanguage(Locale locale) {
        try {
            ResourceBundle language = ResourceBundle.getBundle(sBaseName, locale);
            if (!language.containsKey("plugin_name")) {
                throw new IllegalStateException("Unable to identify language resource package");
            }
            return language;
        } catch (Exception e) {
            return ResourceBundle.getBundle(sBaseName, DEFAULT_LOCALE);
        }
    }
}
