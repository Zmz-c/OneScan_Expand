package burp.vaycore.ost.common;

import burp.vaycore.ost.manager.VariableManager;

final class ReflectionTestSupport {
    private ReflectionTestSupport() { }

    static String apply(String request) {
        if (request == null) return null;
        for (var item : ReflectionProbe.defaultItems()) request = item.getRule().handleProcess(request);
        return VariableManager.resolveVariables(request);
    }
}
