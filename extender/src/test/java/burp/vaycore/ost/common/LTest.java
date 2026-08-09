package burp.vaycore.ost.common;

import org.junit.After;
import org.junit.Test;

import java.util.Locale;

import static org.junit.Assert.assertEquals;

public class LTest {

    private final Locale originalLocale = Locale.getDefault();

    @After
    public void restoreLanguage() {
        Locale.setDefault(originalLocale);
        L.configure(L.LANGUAGE_AUTO);
    }

    @Test
    public void followsChineseBurpLocale() {
        Locale.setDefault(Locale.SIMPLIFIED_CHINESE);

        L.configure(L.LANGUAGE_AUTO);

        assertEquals("\u6570\u636E\u770B\u677F", L.get("tab_name.databoard"));
    }

    @Test
    public void followsEnglishBurpLocale() {
        Locale.setDefault(Locale.US);

        L.configure(L.LANGUAGE_AUTO);

        assertEquals("Databoard", L.get("tab_name.databoard"));
    }

    @Test
    public void manualLanguageOverridesBurpLocale() {
        Locale.setDefault(Locale.US);
        L.configure(L.LANGUAGE_CHINESE);
        assertEquals("\u6570\u636E\u770B\u677F", L.get("tab_name.databoard"));

        Locale.setDefault(Locale.SIMPLIFIED_CHINESE);
        L.configure(L.LANGUAGE_ENGLISH);
        assertEquals("Databoard", L.get("tab_name.databoard"));
    }

    @Test
    public void invalidSettingFallsBackToFollowBurp() {
        assertEquals(L.LANGUAGE_AUTO, L.normalizeLanguageSetting("unsupported"));
        assertEquals(L.LANGUAGE_AUTO, L.normalizeLanguageSetting(null));
    }
}
