package burp.vaycore.ost.common;

import burp.*;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.junit.Assert.*;

/** Matches the legacy Burp API contract: its add/updateParameter do NOT support PARAM_JSON. */
public class ParameterFuzzJsonTest {
    @Test public void addsJsonNameWithEscapedDictionaryValueWithoutUnsupportedMutator() {
        String value = "中文\"\\\n{{host}}";
        byte[] request = request("{\"keep\":true}");
        byte[] result = ParameterFuzzRequestBuilder.applyProbe(helpers(), request, "new", value, IParameter.PARAM_JSON);
        var body = json(result).getAsJsonObject();
        assertTrue(body.get("keep").getAsBoolean());
        assertEquals(value, body.get("new").getAsString());
        assertArrayEquals(request("{\"keep\":true}"), request);
        assertLength(result);
    }

    @Test public void updatesNestedScalarWithoutAddingAnUnrelatedRootField() {
        byte[] result = ParameterFuzzRequestBuilder.applyProbe(helpers(),
                request("{\"nested\":{\"id\":12},\"items\":[1,true,null]}"), "id", "value", IParameter.PARAM_JSON);
        var root = json(result).getAsJsonObject();
        assertFalse(root.has("id"));
        assertEquals("value", root.getAsJsonObject("nested").get("id").getAsString());
        assertEquals(JsonParser.parseString("[1,true,null]"), root.get("items"));
    }

    @Test public void updatesNestedArrayObjectButNeverInventsPropertiesOnRootArray() {
        byte[] request = request("[{\"id\":\"one\"},{\"id\":\"two\"}]");
        byte[] result = ParameterFuzzRequestBuilder.applyProbe(helpers(), request, "id", "probe", IParameter.PARAM_JSON);
        assertEquals("probe", json(result).getAsJsonArray().get(0).getAsJsonObject().get("id").getAsString());
        assertEquals("two", json(result).getAsJsonArray().get(1).getAsJsonObject().get("id").getAsString());
        assertThrows(IllegalArgumentException.class,
                () -> ParameterFuzzRequestBuilder.applyProbe(helpers(), request, "missing", "probe", IParameter.PARAM_JSON));
    }

    @Test public void malformedJsonDoesNotTurnIntoAReplacementDocument() {
        assertThrows(IllegalArgumentException.class, () -> ParameterFuzzRequestBuilder.applyProbe(
                helpers(), request("{\"id\":"), "id", "probe", IParameter.PARAM_JSON));
    }

    private static byte[] request(String body) {
        return ("POST /probe HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n"
                + "Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\n\r\n" + body)
                .getBytes(StandardCharsets.UTF_8);
    }
    private static JsonElement json(byte[] request) {
        String raw = new String(request, StandardCharsets.UTF_8);
        return JsonParser.parseString(raw.substring(raw.indexOf("\r\n\r\n") + 4));
    }
    private static void assertLength(byte[] request) {
        String raw = new String(request, StandardCharsets.ISO_8859_1);
        int offset = raw.indexOf("\r\n\r\n") + 4;
        assertTrue(raw.contains("\r\nContent-Length: " + (request.length - offset) + "\r\n"));
    }

    @SuppressWarnings("unchecked") private static IExtensionHelpers helpers() {
        return (IExtensionHelpers) Proxy.newProxyInstance(IExtensionHelpers.class.getClassLoader(),
                new Class<?>[]{IExtensionHelpers.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "analyzeRequest" -> {
                        String raw = new String((byte[]) args[0], StandardCharsets.ISO_8859_1);
                        int end = raw.indexOf("\r\n\r\n");
                        yield Proxy.newProxyInstance(IRequestInfo.class.getClassLoader(), new Class<?>[]{IRequestInfo.class},
                                (p, getter, ignored) -> switch (getter.getName()) {
                                    case "getParameters" -> List.of();
                                    case "getBodyOffset" -> end + 4;
                                    case "getHeaders" -> Arrays.asList(raw.substring(0, end).split("\r\n"));
                                    default -> throw new AssertionError(getter.getName());
                                });
                    }
                    case "buildHttpMessage" -> {
                        List<String> headers = new ArrayList<>((List<String>) args[0]);
                        byte[] body = (byte[]) args[1];
                        headers.removeIf(header -> header.toLowerCase(Locale.ROOT).startsWith("content-length:"));
                        headers.add("Content-Length: " + body.length);
                        ByteArrayOutputStream out = new ByteArrayOutputStream();
                        out.write((String.join("\r\n", headers) + "\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
                        out.write(body);
                        yield out.toByteArray();
                    }
                    case "buildParameter" -> Proxy.newProxyInstance(IParameter.class.getClassLoader(),
                            new Class<?>[]{IParameter.class}, (p, getter, ignored) -> switch (getter.getName()) {
                                case "getName" -> args[0];
                                case "getValue" -> args[1];
                                case "getType" -> args[2];
                                default -> throw new AssertionError(getter.getName());
                            });
                    default -> throw new AssertionError("JSON must not use unsupported Burp mutator: " + method.getName());
                });
    }
}
