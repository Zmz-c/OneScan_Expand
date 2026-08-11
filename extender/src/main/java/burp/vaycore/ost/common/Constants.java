package burp.vaycore.ost.common;

import java.util.regex.Pattern;

/**
 * 常量
 * <p>
 * Created by vaycore on 2022-08-07.
 */
public interface Constants {

    // 插件信息
    String PLUGIN_NAME = "OST";
    String PLUGIN_VERSION = "1.2.4";
    boolean DEBUG = false;

    // 插件启动显示的信息
    String BANNER = "#" +
            "#############################################\n" +
            "  " + PLUGIN_NAME + " v" + PLUGIN_VERSION + "\n" +
            "  Author:    0ne_1\n" +
            "  Developer: vaycore\n" +
            "  Developer: Rural.Dog\n" +
            "  Developer:人间小福星\n"+
            "  Project:    OST\n" +
            "  Note:UI小调整，归类调整，增加语言选择功能，可以更好的玩耍了！\n" +
            "#############################################\n";

    // 插件卸载显示的信息
    String UNLOAD_BANNER = "\n" +
            "###########################################################################\n" +
            "  " + PLUGIN_NAME + " uninstallation completed, thank you for your attention and use." + "\n" +
            "###########################################################################\n";

    // 匹配请求行的 URL 位置
    Pattern REGEX_REQ_LINE_URL = Pattern.compile("[A-Z]+\\s+(.*?)\\s+HTTP/", Pattern.CASE_INSENSITIVE);
}
