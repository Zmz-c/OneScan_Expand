package burp.vaycore.ost.ui.tab.config;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.ost.common.Config;
import burp.vaycore.ost.common.L;
import burp.vaycore.ost.common.NumberFilter;
import burp.vaycore.ost.ui.base.BaseConfigTab;

import javax.swing.*;
import java.awt.event.ItemEvent;
import java.util.Vector;

/**
 * Browser replay settings.
 */
public class BrowserTab extends BaseConfigTab {

    @Override
    protected void initView() {
        addEnabledConfigPanel(L.get("browser_request"), L.get("browser_request_sub_title"),
                Config.KEY_ENABLE_BROWSER_REQUEST);
        addFileConfigPanel(L.get("browser_python_path"), L.get("browser_python_path_sub_title"),
                Config.KEY_BROWSER_PYTHON_PATH, true);
        addFileConfigPanel(L.get("browser_binary_path"), L.get("browser_binary_path_sub_title"),
                Config.KEY_BROWSER_BINARY_PATH);
        addBrowserTypeConfigPanel();
        addTextConfigPanel(L.get("browser_timeout"), L.get("browser_timeout_sub_title"),
                20, Config.KEY_BROWSER_TIMEOUT).addKeyListener(new NumberFilter(6));
        addEnabledConfigPanel(L.get("browser_load_static_resources"),
                L.get("browser_load_static_resources_sub_title"),
                Config.KEY_BROWSER_LOAD_STATIC_RESOURCES);
        addTextConfigPanel(L.get("browser_target_host_regex"),
                L.get("browser_target_host_regex_sub_title"), 35, Config.KEY_BROWSER_TARGET_HOST_REGEX);
    }

    private void addBrowserTypeConfigPanel() {
        JPanel panel = new JPanel(new HLayout(3));
        Vector<String> items = new Vector<>();
        items.add(L.get("browser_type.edge"));
        items.add(L.get("browser_type.chrome"));
        JComboBox<String> comboBox = new JComboBox<>(items);
        comboBox.setSelectedItem(getBrowserTypeLabel(Config.get(Config.KEY_BROWSER_TYPE)));
        comboBox.addItemListener(e -> {
            if (e.getStateChange() != ItemEvent.SELECTED) {
                return;
            }
            Config.put(Config.KEY_BROWSER_TYPE, getBrowserTypeValue(String.valueOf(e.getItem())));
        });
        panel.add(comboBox);
        addConfigItem(L.get("browser_type"), L.get("browser_type_sub_title"), panel);
    }

    private String getBrowserTypeLabel(String value) {
        if (Config.BROWSER_TYPE_CHROME.equalsIgnoreCase(value)) {
            return L.get("browser_type.chrome");
        }
        return L.get("browser_type.edge");
    }

    private String getBrowserTypeValue(String label) {
        if (L.get("browser_type.chrome").equals(label)) {
            return Config.BROWSER_TYPE_CHROME;
        }
        return Config.BROWSER_TYPE_EDGE;
    }

    @Override
    public String getTitleName() {
        return L.get("tab_name.browser");
    }

    @Override
    protected boolean onTextConfigSave(String configKey, String text) {
        if (Config.KEY_BROWSER_TARGET_HOST_REGEX.equals(configKey)) {
            text = text == null ? "" : text.trim();
            if (StringUtils.isNotEmpty(text)) {
                try {
                    java.util.regex.Pattern.compile(text);
                } catch (java.util.regex.PatternSyntaxException e) {
                    UIHelper.showTipsDialog(L.get("browser_target_host_regex_invalid"));
                    return false;
                }
            }
            return super.onTextConfigSave(configKey, text);
        }
        if (!Config.KEY_BROWSER_TIMEOUT.equals(configKey)) {
            return super.onTextConfigSave(configKey, text);
        }
        int value = StringUtils.parseInt(text, -1);
        if (value < 1000 || value > 300000) {
            UIHelper.showTipsDialog(L.get("browser_timeout_value_invalid"));
            return false;
        }
        Config.put(configKey, String.valueOf(value));
        return true;
    }
}
