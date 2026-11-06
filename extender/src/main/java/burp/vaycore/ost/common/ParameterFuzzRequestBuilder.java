package burp.vaycore.ost.common;

import burp.IExtensionHelpers;
import burp.IParameter;
import burp.IRequestInfo;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Uses Burp's request helpers; JSON bodies use the existing Gson dependency. */
public final class ParameterFuzzRequestBuilder {

    private static final Pattern HEADER_END = Pattern.compile("\\r?\\n\\r?\\n");

    private static final Pattern POSITION = Pattern.compile("\\$([1-9][0-9]*)\\$");
    public static final int MAX_REQUESTS = 5000;

    private ParameterFuzzRequestBuilder() {
        throw new IllegalAccessError("utility class");
    }

    public static byte[] applyProbe(IExtensionHelpers helpers, byte[] request,
                                    String name, String value, byte type) {
        if (helpers == null || request == null || request.length == 0
                || name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("parameter probe requires helpers, request, and name");
        }
        IRequestInfo info = helpers.analyzeRequest(request);
        if (type == IParameter.PARAM_JSON) {
            return applyJsonProbe(helpers, request, info, name, value == null ? "" : value);
        }
        IParameter existing = info.getParameters().stream()
                .filter(parameter -> parameter.getType() == type && name.equals(parameter.getName()))
                .findFirst().orElse(null);
        IParameter probe = helpers.buildParameter(name, value == null ? "" : value, type);
        return existing == null
                ? helpers.addParameter(request, probe)
                : helpers.updateParameter(request, probe);
    }

    /** Legacy IExtensionHelpers.addParameter/updateParameter only support URL, BODY and COOKIE.
     * Automatic JSON probes encode dictionary entries as strings. Use explicit positions for
     * raw JSON types/fragments or to distinguish duplicate field names. */
    private static byte[] applyJsonProbe(IExtensionHelpers helpers, byte[] request, IRequestInfo info,
                                         String name, String value) {
        int bodyOffset = info.getBodyOffset();
        if (bodyOffset < 0 || bodyOffset >= request.length) {
            throw new IllegalArgumentException("JSON probe requires a body");
        }
        JsonElement document;
        try {
            document = JsonParser.parseString(new String(request, bodyOffset,
                    request.length - bodyOffset, StandardCharsets.UTF_8));
        } catch (JsonParseException e) {
            throw new IllegalArgumentException("Invalid JSON probe body", e);
        }
        if (!replaceJsonScalar(document, name, value, 0)) {
            if (!document.isJsonObject() || document.getAsJsonObject().has(name)) {
                throw new IllegalArgumentException("JSON parameter cannot be added to this body");
            }
            document.getAsJsonObject().addProperty(name, value);
        }
        byte[] body = document.toString().getBytes(StandardCharsets.UTF_8);
        List<String> headers = new ArrayList<>(info.getHeaders());
        headers.removeIf(header -> header.regionMatches(true, 0, "Content-Length:", 0, 15));
        return helpers.buildHttpMessage(headers, body);
    }

    private static boolean replaceJsonScalar(JsonElement node, String name, String value, int depth) {
        if (depth > 128) throw new IllegalArgumentException("JSON probe nesting is too deep");
        if (node.isJsonObject()) {
            JsonObject object = node.getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : object.entrySet()) {
                JsonElement child = entry.getValue();
                if (entry.getKey().equals(name) && (child.isJsonPrimitive() || child.isJsonNull())) {
                    object.add(name, new JsonPrimitive(value));
                    return true;
                }
                if (replaceJsonScalar(child, name, value, depth + 1)) return true;
            }
        } else if (node.isJsonArray()) {
            for (JsonElement child : node.getAsJsonArray()) {
                if (replaceJsonScalar(child, name, value, depth + 1)) return true;
            }
        }
        return false;
    }

    /** IDs are strings so manually entered large IDs cannot overflow integer parsing. */
    public static List<String> payloadPositionIds(String template) {
        return POSITION.matcher(template).results().map(match -> match.group(1)).distinct().toList();
    }

    /** Single pass: marker-looking text inside payloads is never expanded again. */
    public static byte[] applyPayloadPositions(byte[] requestTemplate, Map<String, String> payloads) {
        Objects.requireNonNull(requestTemplate, "requestTemplate");
        Matcher matcher = POSITION.matcher(new String(requestTemplate, StandardCharsets.ISO_8859_1));
        ByteArrayOutputStream output = new ByteArrayOutputStream(requestTemplate.length);
        int cursor = 0;
        boolean found = false;
        while (matcher.find()) {
            found = true;
            String id = matcher.group(1);
            if (!payloads.containsKey(id)) throw new IllegalArgumentException("Missing dictionary for $" + id + "$");
            byte[] replacement = Objects.requireNonNull(payloads.get(id)).getBytes(StandardCharsets.UTF_8);
            output.write(requestTemplate, cursor, matcher.start() - cursor);
            output.write(replacement, 0, replacement.length);
            cursor = matcher.end();
        }
        if (!found) throw new IllegalArgumentException("Request template needs numbered positions");
        output.write(requestTemplate, cursor, requestTemplate.length - cursor);
        return output.toByteArray();
    }

    /** Used by marker removal; unselected markers remain unchanged. */
    public static String replacePositionText(String template, Map<String, String> replacements) {
        return POSITION.matcher(template).replaceAll(match -> Matcher.quoteReplacement(
                replacements.getOrDefault(match.group(1), match.group())));
    }

    public static int countPayloadPositions(byte[] requestTemplate) {
        return requestTemplate == null ? 0 : (int) POSITION.matcher(
                new String(requestTemplate, StandardCharsets.ISO_8859_1)).results().count();
    }

    /** Shared by the preview and scanner, with lazy Cartesian expansion and saturated counting. */
    public static PayloadPlan positionPlan(byte[] template, Map<String, List<String>> dictionaries) {
        List<String> ids = payloadPositionIds(new String(template, StandardCharsets.ISO_8859_1));
        List<List<String>> values = new ArrayList<>();
        long count = ids.isEmpty() ? 0 : 1;
        for (String id : ids) {
            List<String> dictionary = dictionaries.get(id);
            List<String> entries = dictionary == null ? List.of() : dictionary.stream()
                    .filter(value -> value != null && !value.isEmpty()).distinct().toList();
            if (entries.isEmpty()) throw new IllegalArgumentException("Missing or empty dictionary for $" + id + "$");
            values.add(entries);
            count = count > Long.MAX_VALUE / entries.size() ? Long.MAX_VALUE : count * entries.size();
        }
        return new PayloadPlan(List.copyOf(ids), List.copyOf(values), count);
    }

    public record PayloadPlan(List<String> ids, List<List<String>> values, long count)
            implements Iterable<Map<String, String>> {
        @Override public Iterator<Map<String, String>> iterator() {
            return new Iterator<>() {
                private final int[] indexes = new int[ids.size()];
                private boolean available = count > 0;
                @Override public boolean hasNext() { return available; }
                @Override public Map<String, String> next() {
                    if (!available) throw new NoSuchElementException();
                    Map<String, String> result = new LinkedHashMap<>();
                    for (int i = 0; i < ids.size(); i++) result.put(ids.get(i), values.get(i).get(indexes[i]));
                    for (int i = indexes.length - 1; i >= 0; i--) {
                        if (++indexes[i] < values.get(i).size()) break;
                        indexes[i] = 0;
                        if (i == 0) available = false;
                    }
                    return result;
                }
            };
        }
    }

    /** Text editors may use LF; normalize only HTTP headers, never the request body. */
    public static String normalizeRequestTemplate(String template) {
        Matcher separator = HEADER_END.matcher(template);
        if (!separator.find()) {
            throw new IllegalArgumentException("request needs a header/body separator");
        }
        String headers = template.substring(0, separator.start()).replace("\r\n", "\n");
        String firstLine = headers.split("\n", 2)[0];
        if (!firstLine.matches("(?:GET|POST) [^ \\r\\n]+ HTTP/[0-9]+(?:\\.[0-9]+)?") || headers.contains("\r")) {
            throw new IllegalArgumentException("request needs a GET or POST request line");
        }
        return headers.replace("\n", "\r\n") + "\r\n\r\n" + template.substring(separator.end());
    }

    public static String requestMethod(byte[] request) {
        for (int i = 0; i < Math.min(request.length, 16); i++) {
            if (request[i] == ' ') {
                return new String(request, 0, i, StandardCharsets.US_ASCII);
            }
        }
        return "";
    }

    public static boolean isSelectedMethod(String method, boolean scanGet, boolean scanPost) {
        return method != null && ("GET".equalsIgnoreCase(method.trim()) && scanGet
                || "POST".equalsIgnoreCase(method.trim()) && scanPost);
    }

    public static boolean isExistingRoute(int status) {
        return status >= 200 && status < 600 && status != 404 && status != 410;
    }

}
