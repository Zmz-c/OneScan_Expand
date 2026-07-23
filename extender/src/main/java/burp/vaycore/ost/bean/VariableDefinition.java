package burp.vaycore.ost.bean;

import java.util.Locale;

public class VariableDefinition {

    public static final String STRATEGY_FIXED = "fixed";
    public static final String STRATEGY_RANDOM = "random";
    public static final String STRATEGY_ROUND_ROBIN = "round-robin";

    private boolean enabled = true;
    private String name = "";
    private String strategy = STRATEGY_FIXED;
    private String dictionary = "default";
    private String fixedValue = "";

    public VariableDefinition() {
    }

    public VariableDefinition(VariableDefinition source) {
        if (source == null) {
            return;
        }
        enabled = source.isEnabled();
        name = source.getName();
        strategy = source.getStrategy();
        dictionary = source.getDictionary();
        fixedValue = source.getFixedValue();
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getName() {
        return name == null ? "" : name;
    }

    public void setName(String name) {
        this.name = name == null ? "" : name.trim();
    }

    public String getStrategy() {
        String value = strategy == null ? "" : strategy.toLowerCase(Locale.ROOT);
        return switch (value) {
            case STRATEGY_RANDOM, STRATEGY_ROUND_ROBIN -> value;
            default -> STRATEGY_FIXED;
        };
    }

    public void setStrategy(String strategy) {
        this.strategy = strategy;
    }

    public String getDictionary() {
        return dictionary == null ? "default" : dictionary;
    }

    public void setDictionary(String dictionary) {
        this.dictionary = dictionary == null ? "default" : dictionary.trim();
    }

    public String getFixedValue() {
        return fixedValue == null ? "" : fixedValue;
    }

    public void setFixedValue(String fixedValue) {
        this.fixedValue = fixedValue == null ? "" : fixedValue;
    }

    public String placeholder() {
        String prefix = STRATEGY_RANDOM.equals(getStrategy()) ? "random." : "value.";
        return "{{" + prefix + getName() + "}}";
    }
}
