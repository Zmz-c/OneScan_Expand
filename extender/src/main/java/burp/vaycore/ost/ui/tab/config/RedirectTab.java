package burp.vaycore.ost.ui.tab.config;

import burp.vaycore.ost.common.Config;
import burp.vaycore.ost.common.L;
import burp.vaycore.ost.ui.base.BaseConfigTab;

/**
 * Redirect设置
 * <p>
 * Created by vaycore on 2025-06-13.
 */
public class RedirectTab extends BaseConfigTab {

    protected void initView() {
        addEnabledConfigPanel(L.get("follow_redirect"), L.get("follow_redirect_sub_title"),
                Config.KEY_FOLLOW_REDIRECT);
        addEnabledConfigPanel(L.get("cookies_follow"), L.get("cookies_follow_sub_title"),
                Config.KEY_REDIRECT_COOKIES_FOLLOW);
        addEnabledConfigPanel(L.get("target_host_limit"), L.get("target_host_limit_sub_title"),
                Config.KEY_REDIRECT_TARGET_HOST_LIMIT);
    }

    @Override
    public String getTitleName() {
        return L.get("tab_name.redirect");
    }
}