package burp.vaycore.ost.manager;

import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.common.utils.Utils;
import burp.vaycore.ost.bean.VariableDefinition;
import burp.vaycore.ost.common.Config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class VariableManager {

    public static final String DEFAULT_VARIABLE_IP = "ip";
    public static final String DEFAULT_VARIABLE_LOCAL_IP = "local-ip";
    public static final String DEFAULT_VARIABLE_UA = "ua";

    private static final ConcurrentHashMap<String, AtomicInteger> ROUND_ROBIN_INDEX = new ConcurrentHashMap<>();
    private static final Pattern NAMED_VARIABLE_PATTERN = Pattern.compile("\\{\\{(?:random|value)\\.[^}]+}}");

    private VariableManager() {
    }

    /**
     * Returns fresh definitions for the dictionaries packaged with the plugin.
     * They are ordinary named variables and can be edited or removed after migration.
     */
    public static List<VariableDefinition> getBundledVariableDefinitions() {
        return List.of(
                randomDefinition(DEFAULT_VARIABLE_IP, WordlistManager.VARIABLE_DICTIONARY_RANDOM_IP),
                randomDefinition(DEFAULT_VARIABLE_LOCAL_IP, WordlistManager.VARIABLE_DICTIONARY_RANDOM_LOCAL_IP),
                randomDefinition(DEFAULT_VARIABLE_UA, WordlistManager.VARIABLE_DICTIONARY_USER_AGENT)
        );
    }

    public static List<String> getBundledVariablePlaceholders() {
        return getBundledVariableDefinitions().stream().map(VariableDefinition::placeholder).toList();
    }

    private static VariableDefinition randomDefinition(String name, String dictionary) {
        VariableDefinition definition = new VariableDefinition();
        definition.setEnabled(true);
        definition.setName(name);
        definition.setStrategy(VariableDefinition.STRATEGY_RANDOM);
        definition.setDictionary(dictionary);
        return definition;
    }

    public static String resolveVariables(String source) {
        if (source == null) {
            return null;
        }
        LinkedHashMap<String, VariableDefinition> definitions = new LinkedHashMap<>();
        for (VariableDefinition definition : Config.getVariableDefinitions()) {
            if (definition == null || !definition.isEnabled() || StringUtils.isEmpty(definition.getName())) {
                continue;
            }
            definitions.putIfAbsent(definition.placeholder(), definition);
        }

        String result = source;
        Map<String, String> resolvedValues = new HashMap<>();
        Set<String> resolving = new HashSet<>();
        for (Map.Entry<String, VariableDefinition> entry : definitions.entrySet()) {
            String placeholder = entry.getKey();
            if (!result.contains(placeholder)) {
                continue;
            }
            String value = resolveDefinition(placeholder, definitions, resolvedValues, resolving);
            if (StringUtils.isEmpty(value)) {
                return null;
            }
            result = result.replace(placeholder, value);
        }
        return hasUnknownNamedVariables(result, definitions) ? null : result;
    }

    private static String resolveDefinition(String placeholder,
                                            Map<String, VariableDefinition> definitions,
                                            Map<String, String> resolvedValues,
                                            Set<String> resolving) {
        if (resolvedValues.containsKey(placeholder)) {
            return resolvedValues.get(placeholder);
        }
        VariableDefinition definition = definitions.get(placeholder);
        if (definition == null || !resolving.add(placeholder)) {
            return null;
        }
        try {
            String value = resolve(definition);
            if (StringUtils.isEmpty(value)) {
                return null;
            }
            for (Map.Entry<String, VariableDefinition> entry : definitions.entrySet()) {
                String nestedPlaceholder = entry.getKey();
                if (!value.contains(nestedPlaceholder)) {
                    continue;
                }
                String nestedValue = resolveDefinition(
                        nestedPlaceholder, definitions, resolvedValues, resolving);
                if (StringUtils.isEmpty(nestedValue)) {
                    return null;
                }
                value = value.replace(nestedPlaceholder, nestedValue);
            }
            resolvedValues.put(placeholder, value);
            return value;
        } finally {
            resolving.remove(placeholder);
        }
    }

    private static boolean hasUnknownNamedVariables(String source,
                                                    Map<String, VariableDefinition> definitions) {
        Matcher matcher = NAMED_VARIABLE_PATTERN.matcher(source);
        while (matcher.find()) {
            if (!definitions.containsKey(matcher.group())) {
                return true;
            }
        }
        return false;
    }

    public static boolean hasUnresolvedVariables(String source) {
        return StringUtils.isNotEmpty(source) && NAMED_VARIABLE_PATTERN.matcher(source).find();
    }

    private static String resolve(VariableDefinition definition) {
        if (VariableDefinition.STRATEGY_FIXED.equals(definition.getStrategy())) {
            return definition.getFixedValue();
        }
        List<String> values = new ArrayList<>(WordlistManager.getList(
                WordlistManager.KEY_VARIABLES, definition.getDictionary()));
        values.removeIf(StringUtils::isEmpty);
        if (values.isEmpty()) {
            return null;
        }
        if (VariableDefinition.STRATEGY_RANDOM.equals(definition.getStrategy())) {
            return Utils.getRandomItem(values);
        }
        AtomicInteger counter = ROUND_ROBIN_INDEX.computeIfAbsent(definition.getName(), key -> new AtomicInteger());
        return values.get(Math.floorMod(counter.getAndIncrement(), values.size()));
    }
}