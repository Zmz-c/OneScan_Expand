package burp.vaycore.ost.common;

import burp.IExtensionHelpers;
import burp.IParameter;
import burp.IRequestInfo;
import org.junit.Test;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

public class ParameterFuzzRequestBuilderTest {

    @Test
    public void onlyReplacesExplicitQueryPositionAndKeepsDuplicateKeys() {
        String template = "GET /items?id=keep&id=$1$&fixed=yes HTTP/1.1\r\nHost: example.test\r\n\r\n";
        String result = new String(ParameterFuzzRequestBuilder.applyPayloadPositions(
                template.getBytes(StandardCharsets.UTF_8), Map.of("1", "abc")), StandardCharsets.UTF_8);
        assertEquals(template.replace("$1$", "abc"), result);
    }

    @Test
    public void replacesNestedJsonArrayPositionWithoutQuotingOrWrappingPayload() {
        String template = "POST /items HTTP/1.1\r\nHost: example.test\r\n\r\n{\n  \"items\": [1, $1$, 3],\n  \"keep\": \"old\"\n}";
        assertEquals(template.replace("$1$", "{\"id\":2}"), new String(
                ParameterFuzzRequestBuilder.applyPayloadPositions(template.getBytes(StandardCharsets.UTF_8),
                        Map.of("1", "{\"id\":2}")), StandardCharsets.UTF_8));
    }

    @Test
    public void replacesAllMarkedPositionsWithTheSameLiteralPayloadOnce() {
        String template = "GET /$1$?id=$1$ HTTP/1.1\r\nHost: example.test\r\nX-Test: $1$\r\n\r\n";
        byte[] bytes = template.getBytes(StandardCharsets.UTF_8);
        assertEquals(3, ParameterFuzzRequestBuilder.countPayloadPositions(bytes));
        assertEquals(template.replace("$1$", "$1\\x$1$中文"), new String(
                ParameterFuzzRequestBuilder.applyPayloadPositions(bytes, Map.of("1", "$1\\x$1$中文")), StandardCharsets.UTF_8));
        assertEquals(template, new String(bytes, StandardCharsets.UTF_8));
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsRequestWithoutMarkedPositions() {
        ParameterFuzzRequestBuilder.applyPayloadPositions("GET / HTTP/1.1\r\n\r\n".getBytes(), Map.of("1", "1"));
    }

    @Test
    public void normalizesOnlyHeadersAndPreservesMultilineBody() {
        String body = "{\n\"value\": \"$1$\"\n}\n";
        assertEquals("POST /items HTTP/1.1\r\nHost: example.test\r\n\r\n" + body,
                ParameterFuzzRequestBuilder.normalizeRequestTemplate("POST /items HTTP/1.1\nHost: example.test\n\n" + body));
    }

    @Test(expected = IllegalArgumentException.class)
    public void doesNotAcceptOldDictionaryWrapperAsARequest() {
        ParameterFuzzRequestBuilder.normalizeRequestTemplate("[$1$]");
    }

    @Test
    public void addsDictionaryProbeWhenParameterIsMissing() {
        byte[] request = "GET /items HTTP/1.1\r\nHost: example.test\r\n\r\n".getBytes();
        byte[] added = "added".getBytes();
        AtomicInteger addCalls = new AtomicInteger();
        AtomicInteger updateCalls = new AtomicInteger();
        IParameter probe = parameter("debug", IParameter.PARAM_URL);
        IExtensionHelpers helpers = helpers(List.of(), probe, added, addCalls, updateCalls);

        byte[] result = ParameterFuzzRequestBuilder.applyProbe(
                helpers, request, "debug", "true", IParameter.PARAM_URL);

        assertArrayEquals(added, result);
        assertEquals(1, addCalls.get());
        assertEquals(0, updateCalls.get());
    }

    @Test
    public void updatesExistingParameterUsingBurpParameterMutator() {
        byte[] request = "POST /items HTTP/1.1\r\nHost: example.test\r\n\r\nid=old".getBytes();
        byte[] updated = "updated".getBytes();
        AtomicInteger addCalls = new AtomicInteger();
        AtomicInteger updateCalls = new AtomicInteger();
        IParameter probe = parameter("id", IParameter.PARAM_BODY);
        IParameter existing = parameter("id", IParameter.PARAM_BODY);
        IExtensionHelpers helpers = helpers(List.of(existing), probe, updated, addCalls, updateCalls);

        byte[] result = ParameterFuzzRequestBuilder.applyProbe(
                helpers, request, "id", "dictionary-value", IParameter.PARAM_BODY);

        assertArrayEquals(updated, result);
        assertEquals(0, addCalls.get());
        assertEquals(1, updateCalls.get());
    }

    @Test public void independentNamesValuesRepeatedAndMultiDigitMarkersAreLiteral() {
        String raw = "GET /?$1$=$2$&$3$=$4$&again=$1$&ten=$10$ HTTP/1.1\r\n\r\n";
        Map<String, String> values = Map.of("1", "name", "2", "$10$\\literal", "3", "other",
                "4", "中文", "10", "ten");
        assertEquals("GET /?name=$10$\\literal&other=中文&again=name&ten=ten HTTP/1.1\r\n\r\n",
                new String(ParameterFuzzRequestBuilder.applyPayloadPositions(raw.getBytes(StandardCharsets.UTF_8), values),
                        StandardCharsets.UTF_8));
        assertEquals(List.of("1", "2", "3", "4", "10"), ParameterFuzzRequestBuilder.payloadPositionIds(raw));
        assertEquals("GET /?original=$2$&$3$=$4$&again=original&ten=$10$ HTTP/1.1\r\n\r\n",
                ParameterFuzzRequestBuilder.replacePositionText(raw, Map.of("1", "original")));
    }

    @Test public void cartesianPlanDeduplicatesValuesAndDoesNotMultiplyRepeatedIds() {
        byte[] template = "$1$=$2$&again=$1$".getBytes(StandardCharsets.UTF_8);
        var plan = ParameterFuzzRequestBuilder.positionPlan(template,
                Map.of("1", List.of("a", "a", "b", ""), "2", List.of("1", "2")));
        assertEquals(4L, plan.count());
        var iterator = plan.iterator();
        assertEquals(Map.of("1", "a", "2", "1"), iterator.next());
        assertEquals(Map.of("1", "a", "2", "2"), iterator.next());
        assertEquals(Map.of("1", "b", "2", "1"), iterator.next());
        assertEquals(Map.of("1", "b", "2", "2"), iterator.next());
        org.junit.Assert.assertFalse(iterator.hasNext());
        org.junit.Assert.assertThrows(java.util.NoSuchElementException.class, iterator::next);
        assertEquals(0, ParameterFuzzRequestBuilder.positionPlan("unmarked".getBytes(), Map.of()).count());
    }

    @Test public void largePositionCountsSaturateWithoutExpansionOrStackOverflow() {
        StringBuilder text = new StringBuilder();
        Map<String, List<String>> values = new java.util.LinkedHashMap<>();
        for (int i = 1; i <= 100; i++) {
            text.append("$").append(i).append("$");
            values.put(String.valueOf(i), List.of("a", "b"));
        }
        var plan = ParameterFuzzRequestBuilder.positionPlan(text.toString().getBytes(), values);
        assertEquals(Long.MAX_VALUE, plan.count());
        assertEquals(100, plan.iterator().next().size());
    }

    @Test public void rejectsMissingDictionariesAndPreservesNonUtf8TemplateBytes() {
        org.junit.Assert.assertThrows(IllegalArgumentException.class, () -> ParameterFuzzRequestBuilder.positionPlan(
                "$1$=$2$".getBytes(), Map.of("1", List.of("one"))));
        org.junit.Assert.assertThrows(IllegalArgumentException.class, () -> ParameterFuzzRequestBuilder.positionPlan(
                "$1$".getBytes(), Map.of("1", List.of(""))));
        byte[] raw = new byte[]{(byte) 0xff, '$', '1', '$', (byte) 0x80};
        assertArrayEquals(new byte[]{(byte) 0xff, 'x', (byte) 0x80},
                ParameterFuzzRequestBuilder.applyPayloadPositions(raw, Map.of("1", "x")));
        assertEquals(List.of("9999999999999999999999"), ParameterFuzzRequestBuilder.payloadPositionIds("$9999999999999999999999$"));
    }

    private static IExtensionHelpers helpers(List<IParameter> existing, IParameter probe, byte[] result,
                                             AtomicInteger addCalls, AtomicInteger updateCalls) {
        IRequestInfo info = proxy(IRequestInfo.class, (instance, method, args) -> {
            if ("getParameters".equals(method.getName())) {
                return existing;
            }
            return objectMethod(instance, method, args);
        });
        return proxy(IExtensionHelpers.class, (instance, method, args) -> {
            switch (method.getName()) {
                case "analyzeRequest":
                    return info;
                case "buildParameter":
                    return probe;
                case "addParameter":
                    addCalls.incrementAndGet();
                    assertSame(probe, args[1]);
                    return result;
                case "updateParameter":
                    updateCalls.incrementAndGet();
                    assertSame(probe, args[1]);
                    return result;
                default:
                    return objectMethod(instance, method, args);
            }
        });
    }

    private static IParameter parameter(String name, byte type) {
        return proxy(IParameter.class, (instance, method, args) -> switch (method.getName()) {
            case "getName" -> name;
            case "getType" -> type;
            default -> objectMethod(instance, method, args);
        });
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, handler);
    }

    private static Object objectMethod(Object instance, Method method, Object[] args) {
        if (method.getDeclaringClass() == Object.class) {
            return switch (method.getName()) {
                case "toString" -> instance.getClass().getInterfaces()[0].getSimpleName() + " test proxy";
                case "hashCode" -> System.identityHashCode(instance);
                case "equals" -> instance == args[0];
                default -> null;
            };
        }
        return null;
    }
}
