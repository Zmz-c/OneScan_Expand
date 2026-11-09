package burp.vaycore.ost.common;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Inert, per-request reflection canary. Never shares a last-marker global across scans. */
public final class ReflectionProbe {
    public static final String PRESET_NAME = "Reflection probe";
    public static final String FINDING = "Reflection candidate";
    private static final Pattern MARKER = Pattern.compile("ostref[0-9a-f]{24}end\\z");
    private static final Pattern REQUEST_LINE = Pattern.compile("^(GET|POST) ([^ \\r\\n]+) HTTP/\\d+(?:\\.\\d+)?$");
    private static final Pattern FORM_TYPE = Pattern.compile(
            "(?im)^Content-Type:[ \\t]*application/x-www-form-urlencoded(?:[; \\t]|$)");
    private static final Pattern UNSUPPORTED_ENCODING = Pattern.compile(
            "(?im)^(?:Transfer-Encoding:[^\\r\\n]+|Content-Encoding:(?![ \\t]*identity[ \\t]*$)[^\\r\\n]+)$");

    private ReflectionProbe() { }


    /** Plain MatchReplace items: expressions, replacements and scopes are persisted and editable. */
    public static java.util.ArrayList<burp.vaycore.ost.ui.widget.payloadlist.PayloadItem> defaultItems() {
        String query = "\\A(?=[^\\r\\n]+ HTTP/\\d+(?:\\.\\d+)?\\r\\n(?:[^\\r\\n]+\\r\\n)*\\r\\n)"
                + "((?:GET|POST) [^ ?#\\r\\n]*\\?(?:&|=[^&# \\r\\n]*&)*[^=&# \\r\\n]+)"
                + "(?:=([^&# \\r\\n]*?))?(?:ostref[0-9a-f]{24}end)?(?=[&# ]|\\z)";
        String form = "\\A(?=POST [^ ?#\\r\\n]*(?:\\?(?:&|=[^&# \\r\\n]*)*)?(?:#[^ \\r\\n]*)? HTTP/\\d+(?:\\.\\d+)?\\r\\n)"
                + "(?=(?:[^\\r\\n]+\\r\\n)*(?i:Content-Type:[ \\t]*application/x-www-form-urlencoded(?:[; \\t][^\\r\\n]*)?)\\r\\n)"
                + "(?!(?:[^\\r\\n]+\\r\\n)*(?i:Transfer-Encoding:[^\\r\\n]+|Content-Encoding:(?![ \\t]*identity[ \\t]*\\r\\n)[^\\r\\n]+)\\r\\n)"
                + "((?:[^\\r\\n]+\\r\\n)*\\r\\n(?:&|=[^&]*&)*[^=& \\t\\r\\n]+)"
                + "(?:=([^&]*?))?(?:ostref[0-9a-f]{24}end)?(?=&|\\z)";
        return new java.util.ArrayList<>(java.util.List.of(replaceRule(query), replaceRule(form)));
    }

    public static final String REQUEST_MARKER_PATTERN =
            "(?:\\A(?:GET|POST) [^\\r\\n]*?|\\r\\n\\r\\n[\\s\\S]*?)(ostref[0-9a-f]{24}end)(?=[&# \\r\\n]|\\z)";

    private static burp.vaycore.ost.ui.widget.payloadlist.PayloadItem replaceRule(String regex) {
        var rule = new burp.vaycore.ost.ui.widget.payloadlist.rule.MatchReplace();
        rule.setParamValue(0, regex);
        rule.setParamValue(1, "$1=$2ostref{{nonce}}end");
        var item = new burp.vaycore.ost.ui.widget.payloadlist.PayloadItem();
        item.setScope(burp.vaycore.ost.ui.widget.payloadlist.PayloadRule.SCOPE_REQUEST);
        item.setRule(rule);
        return item;
    }

    // Compatibility data source for previously saved custom fingerprints.
    public static String markerFromRequest(String request) {
        Span value = firstValue(request);
        if (value == null || value.bare()) return "";
        Matcher marker = MARKER.matcher(request.substring(value.start(), value.end()));
        return marker.find() ? marker.group() : "";
    }

    private static Span firstValue(String request) {
        if (request == null) return null;
        int lineEnd = request.indexOf("\r\n");
        int headerEnd = request.indexOf("\r\n\r\n");
        if (lineEnd < 0 || headerEnd < lineEnd) return null;
        Matcher line = REQUEST_LINE.matcher(request.substring(0, lineEnd));
        if (!line.matches()) return null;
        String target = line.group(2);
        int fragment = target.indexOf('#');
        int targetEnd = fragment < 0 ? target.length() : fragment;
        int query = target.indexOf('?');
        if (query >= 0 && query < targetEnd) {
            Span value = firstNamedValue(request, line.start(2) + query + 1, line.start(2) + targetEnd);
            if (value != null) return value;
        }
        String headers = headerEnd == lineEnd ? "" : request.substring(lineEnd + 2, headerEnd);
        if ("POST".equals(line.group(1)) && FORM_TYPE.matcher(headers).find()
                && !UNSUPPORTED_ENCODING.matcher(headers).find()) {
            return firstNamedValue(request, headerEnd + 4, request.length());
        }
        return null;
    }

    private static Span firstNamedValue(String request, int start, int end) {
        while (start < end) {
            int separator = request.indexOf('&', start);
            int partEnd = separator < 0 || separator > end ? end : separator;
            int equals = request.indexOf('=', start);
            if (equals >= partEnd) equals = -1;
            int nameEnd = equals < 0 ? partEnd : equals;
            if (nameEnd > start && !request.substring(start, nameEnd).isBlank()) {
                return new Span(equals < 0 ? partEnd : equals + 1, partEnd, equals < 0);
            }
            start = partEnd + 1;
        }
        return null;
    }

    private record Span(int start, int end, boolean bare) { }
}
