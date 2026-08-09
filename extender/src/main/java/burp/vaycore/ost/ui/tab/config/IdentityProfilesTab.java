package burp.vaycore.ost.ui.tab.config;

import burp.vaycore.common.layout.VFlowLayout;
import burp.vaycore.ost.common.Config;
import burp.vaycore.ost.common.L;

import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * Identity profile editor embedded in the Request configuration page.
 */
public class IdentityProfilesTab extends VariablesTab {

    @Override
    protected void initData() {
        setBorder(new EmptyBorder(0, 0, 0, 0));
        setLayout(new VFlowLayout());
        setAlignmentX(Component.LEFT_ALIGNMENT);
    }

    @Override
    protected void initView() {
        profiles = Config.getIdentityProfiles();
        addProfilePanel();
    }

    @Override
    public String getTitleName() {
        return L.get("identity_profiles");
    }
}
