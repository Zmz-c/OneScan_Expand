package burp.vaycore.ost.manager;

import burp.vaycore.ost.common.Config;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class WordlistManagerTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void matchesPathFragmentsCaseInsensitivelyAndIgnoresBlankRules() {
        List<String> rules = Arrays.asList("", null, " /Admin/ ", "internal");

        assertTrue(WordlistManager.matchesPathBlocklist("/api/ADMIN/users", rules));
        assertTrue(WordlistManager.matchesPathBlocklist("/v1/internal/health", rules));
        assertTrue(WordlistManager.matchesPathBlocklist("/api/%41dmin/users", rules));
        assertTrue(WordlistManager.matchesPathBlocklist("/v1/%2569nternal/health", rules));
        assertFalse(WordlistManager.matchesPathBlocklist("/api/public/users", rules));
        assertFalse(WordlistManager.matchesPathBlocklist("/api/a+b", List.of("a b")));
        assertFalse(WordlistManager.matchesPathBlocklist("/api/%zz", rules));
        assertFalse(WordlistManager.matchesPathBlocklist("", rules));
    }

    @Test
    public void installsEditableDictionariesForBundledNamedVariables() throws Exception {
        File workDir = temporaryFolder.newFolder("variable-dictionaries-work");
        Config.init(workDir.getAbsolutePath() + File.separator);
        String wordlistPath = Config.get(Config.KEY_WORDLIST_PATH);

        assertTrue(WordlistManager.getItemList(WordlistManager.KEY_VARIABLES)
                .containsAll(List.of(
                        WordlistManager.VARIABLE_DICTIONARY_RANDOM_IP,
                        WordlistManager.VARIABLE_DICTIONARY_RANDOM_LOCAL_IP,
                        WordlistManager.VARIABLE_DICTIONARY_USER_AGENT)));
        assertFalse(WordlistManager.getList(WordlistManager.KEY_VARIABLES,
                WordlistManager.VARIABLE_DICTIONARY_RANDOM_IP).isEmpty());
        assertFalse(WordlistManager.getList(WordlistManager.KEY_VARIABLES,
                WordlistManager.VARIABLE_DICTIONARY_RANDOM_LOCAL_IP).isEmpty());

        List<String> edited = List.of("Custom-UA/1.0", "Custom-UA/2.0");
        WordlistManager.putList(WordlistManager.KEY_VARIABLES,
                WordlistManager.VARIABLE_DICTIONARY_USER_AGENT, edited);
        WordlistManager.init(wordlistPath);

        assertEquals(edited, WordlistManager.getList(WordlistManager.KEY_VARIABLES,
                WordlistManager.VARIABLE_DICTIONARY_USER_AGENT));
    }
}