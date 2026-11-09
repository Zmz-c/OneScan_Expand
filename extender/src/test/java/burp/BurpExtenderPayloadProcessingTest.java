package burp;

import burp.vaycore.ost.common.Config;
import burp.vaycore.ost.common.ReflectionProbe;
import burp.vaycore.ost.ui.widget.payloadlist.PayloadItem;
import burp.vaycore.ost.ui.widget.payloadlist.PayloadRule;
import burp.vaycore.ost.ui.widget.payloadlist.rule.AddSuffix;
import burp.vaycore.ost.ui.widget.payloadlist.rule.MatchReplace;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class BurpExtenderPayloadProcessingTest {
    @Rule public TemporaryFolder temp = new TemporaryFolder();
    private BurpExtender extender;
    private static final IHttpService SERVICE = new IHttpService() {
        public String getHost() { return "example.test"; }
        public int getPort() { return 443; }
        public String getProtocol() { return "https"; }
    };

    @Before public void init() throws Exception {
        Config.init(temp.newFolder().getAbsolutePath() + File.separator);
        burp.vaycore.common.helper.DomainHelper.init("public_suffix_list.json");
        extender = new BurpExtender();
        var field = BurpExtender.class.getDeclaredField("mHelpers");
        field.setAccessible(true);
        field.set(extender, helpers());
    }

    private String process(String raw, PayloadItem... rules) throws Exception {
        var method = BurpExtender.class.getDeclaredMethod("handlePayloadProcess", IHttpService.class, byte[].class, List.class);
        method.setAccessible(true);
        byte[] result = (byte[]) method.invoke(extender, SERVICE, raw.getBytes(StandardCharsets.UTF_8), List.of(rules));
        assertNotNull(result);
        return new String(result, StandardCharsets.UTF_8);
    }

    private static PayloadItem rule(int scope, PayloadRule rule, String... args) {
        for (int i = 0; i < args.length; i++) rule.setParamValue(i, args[i]);
        PayloadItem item = new PayloadItem();
        item.setScope(scope); item.setRule(rule);
        return item;
    }

    @Test public void fullRequestProbeSurvivesFollowingHeaderAndUrlRules() throws Exception {
        String result = process("GET /search?q=apple HTTP/1.1\r\nHost: example.test\r\n\r\n",
                ReflectionProbe.defaultItems().get(0), ReflectionProbe.defaultItems().get(1),
                rule(PayloadRule.SCOPE_HEADER, new AddSuffix(), "\r\nX-Test: true"),
                rule(PayloadRule.SCOPE_URL, new AddSuffix(), "&page=2"));
        assertTrue(result.startsWith("GET /search?q=appleostref"));
        assertTrue(result.contains("end&page=2 HTTP/1.1\r\n"));
        assertTrue(result.contains("\r\nX-Test: true\r\n"));
        assertFalse(ReflectionProbe.markerFromRequest(result).isEmpty());
    }

    @Test public void formProbeAndMixedScopesKeepBodyBytesAndRecalculateContentLength() throws Exception {
        String result = process("POST /submit HTTP/1.1\r\nHost: example.test\r\n"
                        + "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 999\r\n\r\nq=中文&other=keep",
                ReflectionProbe.defaultItems().get(0), ReflectionProbe.defaultItems().get(1),
                rule(PayloadRule.SCOPE_BODY, new AddSuffix(), "&last=yes"),
                rule(PayloadRule.SCOPE_HEADER, new AddSuffix(), "\r\nX-Test: true"));
        String body = result.substring(result.indexOf("\r\n\r\n") + 4);
        assertTrue(body.startsWith("q=中文ostref"));
        assertTrue(body.endsWith("end&other=keep&last=yes"));
        assertTrue(result.contains("\r\nContent-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\n"));
        assertFalse(result.contains("Content-Length: 999"));
    }

    @Test public void wholeRequestAndHeaderChangesAreVisibleToLaterRules() throws Exception {
        String result = process("GET /old?q=1 HTTP/1.1\r\nHost: example.test\r\n\r\n",
                rule(PayloadRule.SCOPE_REQUEST, new MatchReplace(), "^GET ", "POST "),
                rule(PayloadRule.SCOPE_HEADER, new MatchReplace(), "/old", "/new"),
                rule(PayloadRule.SCOPE_URL, new AddSuffix(), "&b=2"),
                rule(PayloadRule.SCOPE_BODY, new AddSuffix(), "body=ok"));
        assertTrue(result.startsWith("POST /new?q=1&b=2 HTTP/1.1"));
        assertTrue(result.endsWith("\r\n\r\nbody=ok"));
    }

    @Test public void headerlessHttp10SupportsUrlRulesAfterWholeRequestRule() throws Exception {
        String result = process("GET /?q=1 HTTP/1.0\r\n\r\n",
                ReflectionProbe.defaultItems().get(0), ReflectionProbe.defaultItems().get(1),
                rule(PayloadRule.SCOPE_URL, new AddSuffix(), "&next=2"));
        assertFalse(ReflectionProbe.markerFromRequest(result).isEmpty());
        assertTrue(result.endsWith("&next=2 HTTP/1.0\r\n\r\n"));
    }

    /** Faithful byte-preserving Burp string conversions. This fixture never sends requests. */
    @SuppressWarnings("unchecked") private static IExtensionHelpers helpers() {
        return (IExtensionHelpers) Proxy.newProxyInstance(IExtensionHelpers.class.getClassLoader(),
                new Class<?>[]{IExtensionHelpers.class}, (object, method, args) -> {
                    switch (method.getName()) {
                        case "bytesToString": return new String((byte[]) args[0], StandardCharsets.ISO_8859_1);
                        case "stringToBytes": return ((String) args[0]).getBytes(StandardCharsets.ISO_8859_1);
                        case "analyzeRequest": {
                            String raw = new String((byte[]) args[args.length - 1], StandardCharsets.ISO_8859_1);
                            int boundary = raw.indexOf("\r\n\r\n");
                            assertTrue(boundary > 0);
                            List<String> headers = Arrays.asList(raw.substring(0, boundary).split("\r\n"));
                            String[] line = headers.get(0).split(" ");
                            return Proxy.newProxyInstance(IRequestInfo.class.getClassLoader(), new Class<?>[]{IRequestInfo.class},
                                    (info, getter, ignored) -> switch (getter.getName()) {
                                        case "getHeaders" -> headers;
                                        case "getBodyOffset" -> boundary + 4;
                                        case "getMethod" -> line[0];
                                        case "getUrl" -> new URL("https://example.test" + line[1]);
                                        default -> throw new AssertionError(getter.getName());
                                    });
                        }
                        case "buildHttpMessage": {
                            List<String> headers = new ArrayList<>((List<String>) args[0]);
                            byte[] body = (byte[]) args[1];
                            if (body.length > 0) headers.add("Content-Length: " + body.length);
                            ByteArrayOutputStream result = new ByteArrayOutputStream();
                            result.write((String.join("\r\n", headers) + "\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
                            result.write(body);
                            return result.toByteArray();
                        }
                        default: throw new AssertionError(method.getName());
                    }
                });
    }
}
