package burp.vaycore.ost.common;

import burp.vaycore.ost.manager.WordlistManager;
import burp.vaycore.ost.ui.widget.payloadlist.PayloadItem;
import burp.vaycore.ost.ui.widget.payloadlist.PayloadRule;
import burp.vaycore.ost.ui.widget.payloadlist.ProcessingItem;
import burp.vaycore.ost.ui.widget.payloadlist.rule.AddSuffix;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class ConfigDefaultsTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void installsDisabledAuthFuzzVariableAndProcessingBypasses() throws Exception {
        File workDir = temporaryFolder.newFolder("defaults");
        Config.init(workDir.getAbsolutePath() + File.separator);

        assertTrue(Config.getVariableDefinitions().stream()
                .anyMatch(item -> "AuthFuzz".equals(item.getName()) && !item.isEnabled()
                        && "AuthFuzz".equals(item.getDictionary())));
        assertEquals(46, WordlistManager.getList(WordlistManager.KEY_VARIABLES,
                WordlistManager.VARIABLE_DICTIONARY_AUTHFUZZ).size());
        assertTrue(WordlistManager.getHeader().stream()
                .noneMatch("{{random.AuthFuzz}}"::equals));

        List<ProcessingItem> rules = Config.getPayloadProcessList();
        assertEquals(10, rules.size());
        assertTrue(rules.stream().noneMatch(ProcessingItem::isEnabled));
        assertTrue(rules.stream().noneMatch(ProcessingItem::isMerge));

        ProcessingItem methodRule = rules.get(0);
        PayloadItem methodItem = methodRule.getItems().get(0);
        assertEquals(PayloadRule.SCOPE_REQUEST, methodItem.getScope());
        assertEquals("MatchReplace", methodItem.getRule().getClass().getSimpleName());
        assertEquals("^GET ", methodItem.getRule().getParamValues()[0]);
        assertEquals("POST ", methodItem.getRule().getParamValues()[1]);

        ProcessingItem suffixRule = rules.get(1);
        PayloadItem suffixItem = suffixRule.getItems().get(0);
        assertEquals(PayloadRule.SCOPE_URL, suffixItem.getScope());
        assertNotNull(suffixItem.getRule());
        assertEquals(";index.jgp", suffixItem.getRule().getParamValues()[0]);

        // The persisted JSON is converted back to typed ProcessingItem/PayloadRule
        // instances on the next plugin initialization.
        Config.init(workDir.getAbsolutePath() + File.separator);
        assertEquals(10, Config.getPayloadProcessList().size());
        assertEquals("MatchReplace", Config.getPayloadProcessList().get(0).getItems().get(0)
                .getRule().getClass().getSimpleName());
    }

    @Test
    public void upgradesExistingNamedVariableDefaultsWithAuthFuzzOnce() throws Exception {
        File workDir = temporaryFolder.newFolder("authfuzz-upgrade");
        Config.init(workDir.getAbsolutePath() + File.separator);
        Config.put(Config.KEY_NAMED_VARIABLE_DEFAULTS_INITIALIZED, "true");
        Config.removeKey(Config.KEY_AUTHFUZZ_VARIABLE_DEFAULT_INITIALIZED);
        Config.put(Config.KEY_VARIABLE_DEFINITIONS, Config.getVariableDefinitions().stream()
                .filter(item -> !"AuthFuzz".equals(item.getName())).toList());

        Config.init(workDir.getAbsolutePath() + File.separator);
        assertTrue(Config.getVariableDefinitions().stream()
                .anyMatch(item -> "AuthFuzz".equals(item.getName()) && !item.isEnabled()));
        assertTrue(Config.getBoolean(Config.KEY_AUTHFUZZ_VARIABLE_DEFAULT_INITIALIZED));
    }

    @Test
    public void appendsMissingPayloadDefaultsWhenExistingRulesArePresent() throws Exception {
        File workDir = temporaryFolder.newFolder("payload-default-migration");
        Config.init(workDir.getAbsolutePath() + File.separator);

        ProcessingItem custom = new ProcessingItem();
        custom.setName("Custom rule");
        custom.setEnabled(true);
        custom.setMerge(false);
        AddSuffix customRule = new AddSuffix();
        customRule.setParamValue(0, "/custom");
        PayloadItem customPayload = new PayloadItem();
        customPayload.setScope(PayloadRule.SCOPE_URL);
        customPayload.setRule(customRule);
        custom.setItems(new ArrayList<>(List.of(customPayload)));
        Config.put(Config.KEY_PAYLOAD_PROCESS_LIST, new ArrayList<>(List.of(custom)));
        // Simulate a 1.2.5 installation: it has the old boolean marker but no
        // revision marker, which means missing defaults must be filled once.
        Config.put(Config.KEY_PAYLOAD_PROCESS_DEFAULTS_INITIALIZED, "true");
        Config.removeKey(Config.KEY_PAYLOAD_PROCESS_DEFAULTS_VERSION);

        Config.init(workDir.getAbsolutePath() + File.separator);
        List<ProcessingItem> rules = Config.getPayloadProcessList();
        assertEquals(11, rules.size());
        assertEquals("Custom rule", rules.get(0).getName());
        assertFalse(rules.stream().skip(1).anyMatch(ProcessingItem::isEnabled));

        Config.init(workDir.getAbsolutePath() + File.separator);
        assertEquals(11, Config.getPayloadProcessList().size());
    }
}
