package burp.vaycore.ost.common;

import burp.vaycore.ost.bean.FpDSProvider;
import burp.vaycore.ost.bean.FpRule;
import burp.vaycore.ost.ui.widget.payloadlist.rule.MatchReplace;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.Assert.*;

public class ReflectionProbeTest {
    @org.junit.Rule public org.junit.rules.TemporaryFolder temp = new org.junit.rules.TemporaryFolder();
    @org.junit.Before public void init() throws Exception {
        Config.init(temp.newFolder().getAbsolutePath() + java.io.File.separator);
    }
    private static String get(String target) {
        return "GET " + target + " HTTP/1.1\r\nHost: example.test\r\n\r\n";
    }

    private static String form(String target, String extra, String body) {
        return "POST " + target + " HTTP/1.1\r\nHost: example.test\r\n"
                + "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n" + extra + "\r\n" + body;
    }

    private static String append(String input) {
        String result = ReflectionTestSupport.apply(input);
        assertTrue(ReflectionProbe.markerFromRequest(result).matches("ostref[0-9a-f]{24}end"));
        return result;
    }

    @Test public void appendsOnlyToFirstValueWithoutReencodingAnything() {
        String input = get("/find?q=%E4%B8%AD+%26%3D&next=a=b&next=2#local");
        String result = append(input);
        String marker = ReflectionProbe.markerFromRequest(result);
        assertEquals(input.replace("%26%3D&", "%26%3D" + marker + "&"), result);
    }

    @Test public void handlesBareEmptyDuplicateAndUnnamedFields() {
        for (String query : new String[]{"flag", "q=", "&&=skip&q=", "q=one&q=two"}) {
            String result = append(get("/?" + query));
            String marker = ReflectionProbe.markerFromRequest(result);
            String expected = query.equals("flag") ? "flag=" + marker
                    : query.equals("q=one&q=two") ? "q=one" + marker + "&q=two" : query + marker;
            assertEquals(get("/?" + expected), result);
        }
    }

    @Test public void handlesAbsoluteTargetsAndHeaderlessHttp10() {
        append(get("https://example.test/?q=v"));
        append("GET /?q=v HTTP/1.0\r\n\r\n");
    }

    @Test public void formFallbackAndQueryPriorityPreserveOtherFields() {
        String input = form("/", "Content-Length: 16\r\n", "q=a%2Bb&second=2");
        String result = append(input);
        assertEquals(input.replace("q=a%2Bb&", "q=a%2Bb" + ReflectionProbe.markerFromRequest(result) + "&"), result);
        String both = form("/?url=first", "", "body=untouched");
        result = append(both);
        assertTrue(result.endsWith("\r\n\r\nbody=untouched"));
        assertTrue(result.startsWith("POST /?url=firstostref"));
        append(form("/?", "", "flag"));
        append(form("/", "Content-Encoding: identity\r\n", "q=first"));
    }

    @Test public void unsupportedAndMissingParametersAreUntouched() {
        String json = form("/", "", "q=v").replace("application/x-www-form-urlencoded", "application/json");
        for (String input : new String[]{get("/"), get("/?"), get("/?&&=unnamed"),
                get("/#fragment?q=not-a-query"), json, json.replace("application/json", "multipart/form-data"),
                form("/", "Transfer-Encoding: chunked\r\n", "q=v"),
                form("/", "Content-Encoding: gzip\r\n", "q=v"),
                form("/", "content-encoding: br\r\nX-Last: true\r\n", "q=v"),
                get("/?q=v").replace("GET ", "PUT "), "GET /?q=v HTTP/1.1\n\n", "bad"}) {
            assertEquals(input, ReflectionTestSupport.apply(input));
            assertEquals("", ReflectionProbe.markerFromRequest(input));
        }
        assertNull(ReflectionTestSupport.apply(null));
        assertEquals("", ReflectionProbe.markerFromRequest(null));
    }

    @Test public void replacesAnExistingProbeRatherThanStacking() {
        String first = append(get("/?q=old"));
        String second = append(first);
        assertNotEquals(first, second);
        assertEquals(first.length(), second.length());
        assertEquals(get("/?q=old"), second.replace(ReflectionProbe.markerFromRequest(second), ""));
    }

    @Test public void concurrentMarkersAreIndependentAndUnique() {
        Set<String> markers = IntStream.range(0, 200).parallel().mapToObj(i -> {
            String req = append(get("/?q=" + i));
            String marker = ReflectionProbe.markerFromRequest(req);
            assertEquals("true", provider(req, "<p>" + marker + "</p>").getMatchData("reflection", "reflected"));
            return marker;
        }).collect(Collectors.toSet());
        assertEquals(200, markers.size());
    }

    private static FpDSProvider provider(String request, String body) {
        return new FpDSProvider(request == null ? null : request.getBytes(StandardCharsets.UTF_8),
                ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body).getBytes(StandardCharsets.UTF_8));
    }

    @Test public void matchesOnlyTheFullCurrentRequestMarkerInResponseBody() {
        String req = append(get("/?q=old"));
        String marker = ReflectionProbe.markerFromRequest(req);
        assertEquals(marker, provider(req, marker).getMatchData("reflection", "marker"));
        assertEquals("true", provider(req, marker).getMatchData("reflection", "reflected"));
        for (String body : new String[]{"", marker.substring(0, marker.length() - 1), marker.toUpperCase(),
                ReflectionProbe.markerFromRequest(append(get("/?q=other")))}) {
            assertEquals("false", provider(req, body).getMatchData("reflection", "reflected"));
        }
        assertEquals("false", provider(null, marker).getMatchData("reflection", "reflected"));
        assertEquals("false", provider(get("/?q=plain&second=" + marker), marker).getMatchData("reflection", "reflected"));
        assertEquals("false", new FpDSProvider(req.getBytes(StandardCharsets.UTF_8),
                ("HTTP/1.1 200 OK\r\nX-Marker: " + marker + "\r\n\r\nno reflection").getBytes(StandardCharsets.UTF_8))
                .getMatchData("reflection", "reflected"));
        assertEquals("false", new FpDSProvider(req.getBytes(StandardCharsets.UTF_8), null)
                .getMatchData("reflection", "reflected"));
    }

    @Test public void fieldSelectorsExposeCorrelationAndDocsRegexActuallyWorks() {
        assertTrue(FpRule.getDataSources().contains("reflection"));
        assertEquals(Set.of("marker", "reflected"), Set.copyOf(FpRule.getFieldsByDataSource("reflection")));
        MatchReplace rule = new MatchReplace();
        rule.setParamValue(0, "^([^?]*\\?[^=&?#]+=[^&#]*)(.*)$");
        rule.setParamValue(1, "$1PROBE$2");
        assertEquals("/search?q=applePROBE&page=2", rule.handleProcess("/search?q=apple&page=2"));
    }
}
