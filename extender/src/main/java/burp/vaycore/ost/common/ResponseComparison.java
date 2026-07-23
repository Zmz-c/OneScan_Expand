package burp.vaycore.ost.common;

import burp.vaycore.common.utils.HtmlUtils;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.common.utils.Utils;
import burp.vaycore.ost.bean.TaskData;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public final class ResponseComparison {

    private static final Set<String> KEY_HEADERS = Set.of(
            "content-type", "location", "www-authenticate", "cache-control", "set-cookie");

    private ResponseComparison() {
    }

    public static String compare(List<TaskData> tasks) {
        return compare(tasks, "");
    }

    public static String compare(List<TaskData> tasks, String bodyRegex) {
        validateTasks(tasks);
        Pattern regex = compileRegex(bodyRegex);
        ArrayList<ResponseData> responses = new ArrayList<>();
        for (TaskData task : tasks) {
            responses.add(read(task));
        }

        StringBuilder result = new StringBuilder();
        result.append(L.get("response_compare_disclaimer")).append("\n\n");
        result.append(L.get("response_compare_variant", tasks.get(0).getHost() + tasks.get(0).getUrl()))
                .append("\n\n");
        appendSummary(result, responses);
        appendHeaders(result, responses);
        appendJsonDifferences(result, responses);
        appendRegexMatches(result, responses, regex);
        appendRawDiffs(result, responses);
        appendAssessment(result, responses);
        return result.toString();
    }

    private static void validateTasks(List<TaskData> tasks) {
        if (tasks == null || tasks.size() < 2) {
            throw new IllegalArgumentException(L.get("response_compare_minimum"));
        }
        String variantId = tasks.get(0).getVariantId();
        if (StringUtils.isEmpty(variantId) || tasks.stream()
                .anyMatch(task -> task == null || !variantId.equals(task.getVariantId()))) {
            throw new IllegalArgumentException(L.get("response_compare_same_variant"));
        }
    }

    private static Pattern compileRegex(String bodyRegex) {
        if (StringUtils.isEmpty(bodyRegex) || bodyRegex.isBlank()) {
            return null;
        }
        try {
            return Pattern.compile(bodyRegex, Pattern.MULTILINE);
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException(L.get("response_compare_regex_invalid", e.getDescription()));
        }
    }

    private static void appendSummary(StringBuilder result, List<ResponseData> responses) {
        result.append(String.format("%-20s %-8s %-10s %-12s %-8s %s%n",
                L.get("profile_name"), L.get("task_table_columns.status"),
                L.get("task_table_columns.length"), "Body MD5", L.get("response_compare_similarity"),
                L.get("task_table_columns.title")));
        ResponseData baseline = responses.get(0);
        for (ResponseData response : responses) {
            result.append(String.format("%-20s %-8d %-10d %-12s %-8s %s%n",
                    response.profile(), response.status(), response.body().length,
                    shortHash(response.body()), percent(similarity(baseline.body(), response.body())),
                    response.title()));
        }
    }

    private static void appendHeaders(StringBuilder result, List<ResponseData> responses) {
        result.append("\n").append(L.get("response_compare_headers")).append("\n");
        for (ResponseData response : responses) {
            result.append(response.profile()).append(": ");
            result.append(response.headers().isEmpty() ? '-' : response.headers());
            result.append('\n');
        }
    }

    private static void appendJsonDifferences(StringBuilder result, List<ResponseData> responses) {
        ArrayList<Map<String, String>> values = new ArrayList<>();
        boolean hasJson = false;
        for (ResponseData response : responses) {
            Map<String, String> fields = flattenJson(response.body());
            values.add(fields);
            hasJson |= !fields.isEmpty();
        }
        result.append("\n").append(L.get("response_compare_json")).append("\n");
        if (!hasJson) {
            result.append(L.get("response_compare_json_not_available")).append('\n');
            return;
        }

        TreeSet<String> keys = new TreeSet<>();
        for (Map<String, String> item : values) {
            keys.addAll(item.keySet());
        }
        boolean hasDifference = false;
        for (String key : keys) {
            LinkedHashMap<String, String> fieldValues = new LinkedHashMap<>();
            for (int i = 0; i < responses.size(); i++) {
                fieldValues.put(responses.get(i).profile(), values.get(i).getOrDefault(key, "<missing>"));
            }
            if (new HashSet<>(fieldValues.values()).size() <= 1) {
                continue;
            }
            hasDifference = true;
            result.append(key).append(':').append('\n');
            for (Map.Entry<String, String> entry : fieldValues.entrySet()) {
                result.append("  ").append(entry.getKey()).append(" = ").append(entry.getValue()).append('\n');
            }
        }
        if (!hasDifference) {
            result.append(L.get("response_compare_same")).append('\n');
        }
    }

    private static Map<String, String> flattenJson(byte[] body) {
        try {
            JsonElement root = JsonParser.parseString(bodyText(body));
            LinkedHashMap<String, String> result = new LinkedHashMap<>();
            flattenJson(root, "$", result);
            return result;
        } catch (JsonSyntaxException | IllegalStateException e) {
            return Map.of();
        }
    }

    private static void flattenJson(JsonElement element, String path, Map<String, String> values) {
        if (element == null || element.isJsonNull()) {
            values.put(path, "null");
            return;
        }
        if (element.isJsonPrimitive()) {
            values.put(path, element.getAsString());
            return;
        }
        if (element.isJsonArray()) {
            for (int i = 0; i < element.getAsJsonArray().size(); i++) {
                flattenJson(element.getAsJsonArray().get(i), path + "[" + i + "]", values);
            }
            return;
        }
        for (Map.Entry<String, JsonElement> entry : element.getAsJsonObject().entrySet()) {
            flattenJson(entry.getValue(), path + "." + entry.getKey(), values);
        }
    }

    private static void appendRegexMatches(StringBuilder result, List<ResponseData> responses, Pattern regex) {
        if (regex == null) {
            return;
        }
        result.append("\n").append(L.get("response_compare_regex_matches")).append("\n");
        for (ResponseData response : responses) {
            ArrayList<String> matches = new ArrayList<>();
            Matcher matcher = regex.matcher(bodyText(response.body()));
            while (matcher.find()) {
                matches.add(matcher.group());
            }
            result.append(response.profile()).append(": ");
            result.append(matches.isEmpty() ? L.get("response_compare_no_match") : String.join(" | ", matches));
            result.append('\n');
        }
    }

    private static void appendRawDiffs(StringBuilder result, List<ResponseData> responses) {
        ResponseData baseline = responses.get(0);
        result.append("\n").append(L.get("response_compare_raw_diff")).append("\n");
        for (int i = 1; i < responses.size(); i++) {
            ResponseData response = responses.get(i);
            result.append("--- ").append(baseline.profile()).append('\n');
            result.append("+++ ").append(response.profile()).append('\n');
            appendRawDiff(result, baseline.body(), response.body());
        }
    }

    private static void appendRawDiff(StringBuilder result, byte[] baseline, byte[] candidate) {
        if (Arrays.equals(baseline, candidate)) {
            result.append(L.get("response_compare_unchanged")).append('\n');
            return;
        }
        String[] left = bodyText(baseline).split("\\R", -1);
        String[] right = bodyText(candidate).split("\\R", -1);
        int prefix = 0;
        while (prefix < left.length && prefix < right.length && left[prefix].equals(right[prefix])) {
            prefix++;
        }
        int suffix = 0;
        while (suffix < left.length - prefix && suffix < right.length - prefix
                && left[left.length - suffix - 1].equals(right[right.length - suffix - 1])) {
            suffix++;
        }
        result.append("@@ ").append(L.get("response_compare_baseline")).append(" @@\n");
        appendDiffLines(result, '-', left, prefix, left.length - suffix);
        appendDiffLines(result, '+', right, prefix, right.length - suffix);
    }

    private static void appendDiffLines(StringBuilder result, char prefix, String[] values, int from, int to) {
        for (int i = from; i < to; i++) {
            result.append(prefix).append(' ').append(values[i]).append('\n');
        }
    }

    private static void appendAssessment(StringBuilder result, List<ResponseData> responses) {
        ResponseData baseline = responses.get(0);
        double minimum = 1D;
        for (ResponseData response : responses) {
            minimum = Math.min(minimum, similarity(baseline.body(), response.body()));
        }
        boolean statusSame = responses.stream().map(ResponseData::status).distinct().count() == 1;
        boolean bodySame = responses.stream().map(item -> Utils.md5(item.body())).distinct().count() == 1;
        String assessment = statusSame && bodySame
                ? L.get("response_compare_same")
                : minimum < 0.5D ? L.get("response_compare_significant") : L.get("response_compare_different");
        result.append("\n").append(L.get("response_compare_result", assessment));
    }

    private static ResponseData read(TaskData task) {
        byte[] response = task.getRespBytes();
        if (response == null) {
            response = new byte[0];
        }
        int separator = indexOf(response, new byte[]{'\r', '\n', '\r', '\n'});
        int bodyOffset = separator < 0 ? 0 : separator + 4;
        byte[] body = Arrays.copyOfRange(response, Math.min(bodyOffset, response.length), response.length);
        LinkedHashMap<String, String> headers = new LinkedHashMap<>();
        if (separator > 0) {
            String headerText = new String(response, 0, separator, StandardCharsets.ISO_8859_1);
            for (String line : headerText.split("\\r?\\n")) {
                int colon = line.indexOf(':');
                if (colon <= 0) {
                    continue;
                }
                String name = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
                if (KEY_HEADERS.contains(name)) {
                    headers.put(name, line.substring(colon + 1).trim());
                }
            }
        }
        String profile = StringUtils.isEmpty(task.getProfile()) ? L.get("profile_none") : task.getProfile();
        String title = StringUtils.isEmpty(task.getTitle()) ? HtmlUtils.findTitleByHtmlBody(response) : task.getTitle();
        return new ResponseData(profile, task.getStatus(), body, title, headers);
    }

    private static double similarity(byte[] left, byte[] right) {
        if (Arrays.equals(left, right)) {
            return 1D;
        }
        if (left.length == 0 || right.length == 0) {
            return 0D;
        }
        Set<String> leftTokens = tokens(left);
        Set<String> rightTokens = tokens(right);
        if (leftTokens.isEmpty() || rightTokens.isEmpty()) {
            return 1D - Math.min(1D, Math.abs(left.length - right.length) / (double) Math.max(left.length, right.length));
        }
        Set<String> intersection = new HashSet<>(leftTokens);
        intersection.retainAll(rightTokens);
        Set<String> union = new HashSet<>(leftTokens);
        union.addAll(rightTokens);
        return intersection.size() / (double) union.size();
    }

    private static Set<String> tokens(byte[] bytes) {
        String text = bodyText(bytes).toLowerCase(Locale.ROOT);
        Set<String> result = new HashSet<>();
        for (String token : text.split("[^\\p{L}\\p{N}_-]+")) {
            if (token.length() >= 3) {
                result.add(token);
            }
        }
        return result;
    }

    private static int indexOf(byte[] value, byte[] target) {
        outer:
        for (int i = 0; i <= value.length - target.length; i++) {
            for (int j = 0; j < target.length; j++) {
                if (value[i + j] != target[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static String bodyText(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static String percent(double value) {
        return String.format(Locale.ROOT, "%.0f%%", value * 100D);
    }

    private static String shortHash(byte[] value) {
        String hash = Utils.md5(value);
        return hash.length() <= 10 ? hash : hash.substring(0, 10);
    }

    private record ResponseData(String profile, int status, byte[] body, String title,
                                Map<String, String> headers) {
    }
}