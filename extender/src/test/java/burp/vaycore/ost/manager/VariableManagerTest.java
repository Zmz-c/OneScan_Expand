package burp.vaycore.ost.manager;

import burp.vaycore.ost.bean.IdentityProfile;
import burp.vaycore.ost.bean.VariableDefinition;
import burp.vaycore.ost.common.Config;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class VariableManagerTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void installsBundledRandomVariablesAsEditableNamedDefinitions() throws Exception {
        File workDir = temporaryFolder.newFolder("bundled-variables");
        Config.init(workDir.getAbsolutePath() + File.separator);

        List<VariableDefinition> definitions = Config.getVariableDefinitions();
        assertEquals(List.of("ip", "local-ip", "ua"), definitions.stream()
                .map(VariableDefinition::getName).toList());
        assertTrue(definitions.stream().allMatch(item -> item.isEnabled()
                && VariableDefinition.STRATEGY_RANDOM.equals(item.getStrategy())));
        assertEquals(List.of(
                        WordlistManager.VARIABLE_DICTIONARY_RANDOM_IP,
                        WordlistManager.VARIABLE_DICTIONARY_RANDOM_LOCAL_IP,
                        WordlistManager.VARIABLE_DICTIONARY_USER_AGENT),
                definitions.stream().map(VariableDefinition::getDictionary).toList());

        String ip = VariableManager.resolveVariables("{{random.ip}}");
        String localIp = VariableManager.resolveVariables("{{random.local-ip}}");
        String userAgent = VariableManager.resolveVariables("{{random.ua}}");
        assertTrue(WordlistManager.getList(WordlistManager.KEY_VARIABLES,
                WordlistManager.VARIABLE_DICTIONARY_RANDOM_IP).contains(ip));
        assertTrue(WordlistManager.getList(WordlistManager.KEY_VARIABLES,
                WordlistManager.VARIABLE_DICTIONARY_RANDOM_LOCAL_IP).contains(localIp));
        assertTrue(WordlistManager.getList(WordlistManager.KEY_VARIABLES,
                WordlistManager.VARIABLE_DICTIONARY_USER_AGENT).contains(userAgent));
    }

    @Test
    public void preservesAUserDefinedBundledVariableNameDuringMigration() throws Exception {
        File workDir = temporaryFolder.newFolder("custom-bundled-variable");
        Config.init(workDir.getAbsolutePath() + File.separator);

        VariableDefinition customIp = new VariableDefinition();
        customIp.setName("ip");
        customIp.setStrategy(VariableDefinition.STRATEGY_FIXED);
        customIp.setFixedValue("custom-ip");
        Config.put(Config.KEY_VARIABLE_DEFINITIONS, new ArrayList<>(List.of(customIp)));
        Config.removeKey(Config.KEY_NAMED_VARIABLE_DEFAULTS_INITIALIZED);
        Config.init(workDir.getAbsolutePath() + File.separator);

        List<VariableDefinition> definitions = Config.getVariableDefinitions();
        assertEquals("custom-ip", definitions.stream()
                .filter(item -> "ip".equals(item.getName())).findFirst().orElseThrow().getFixedValue());
        assertEquals(3, definitions.size());
    }

    @Test
    public void resolvesNestedVariablesIndependentlyOfDefinitionOrderAndRejectsCycles() throws Exception {
        File workDir = temporaryFolder.newFolder("nested-variable-work");
        Config.init(workDir.getAbsolutePath() + File.separator);

        VariableDefinition leaf = new VariableDefinition();
        leaf.setName("leaf");
        leaf.setFixedValue("alpha");
        VariableDefinition root = new VariableDefinition();
        root.setName("root");
        root.setFixedValue("{{value.leaf}}");
        Config.put(Config.KEY_VARIABLE_DEFINITIONS, new ArrayList<>(List.of(leaf, root)));

        assertEquals("tenant-alpha", VariableManager.resolveVariables("tenant-{{value.root}}"));
        assertNull(VariableManager.resolveVariables("{{value.missing}}"));

        VariableDefinition first = new VariableDefinition();
        first.setName("first");
        first.setFixedValue("{{value.second}}");
        VariableDefinition second = new VariableDefinition();
        second.setName("second");
        second.setFixedValue("{{value.first}}");
        Config.put(Config.KEY_VARIABLE_DEFINITIONS, new ArrayList<>(List.of(first, second)));
        assertNull(VariableManager.resolveVariables("{{value.first}}"));
    }

    @Test
    public void structuredConfigUsesDetachedSnapshots() throws Exception {
        File workDir = temporaryFolder.newFolder("snapshot-work");
        Config.init(workDir.getAbsolutePath() + File.separator);

        VariableDefinition variable = new VariableDefinition();
        variable.setName("tenant");
        variable.setFixedValue("alpha");
        Config.put(Config.KEY_VARIABLE_DEFINITIONS, new ArrayList<>(List.of(variable)));
        variable.setFixedValue("mutated-after-save");

        ArrayList<VariableDefinition> variables = Config.getVariableDefinitions();
        assertEquals("alpha", variables.get(0).getFixedValue());
        variables.get(0).setFixedValue("mutated-snapshot");
        assertEquals("alpha", Config.getVariableDefinitions().get(0).getFixedValue());

        IdentityProfile profile = new IdentityProfile();
        profile.setName("reader");
        profile.setHeaders(Map.of("X-Role", "reader"));
        Config.put(Config.KEY_IDENTITY_PROFILES, new ArrayList<>(List.of(profile)));
        profile.getHeaders().put("X-Role", "mutated-after-save");

        ArrayList<IdentityProfile> profiles = Config.getIdentityProfiles();
        assertEquals("reader", profiles.get(0).getHeaders().get("X-Role"));
        profiles.get(0).getHeaders().put("X-Role", "mutated-snapshot");
        assertEquals("reader", Config.getIdentityProfiles().get(0).getHeaders().get("X-Role"));
    }
}