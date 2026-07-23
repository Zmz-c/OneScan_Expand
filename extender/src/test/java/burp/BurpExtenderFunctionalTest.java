package burp;

import burp.vaycore.common.utils.UrlUtils;
import burp.vaycore.ost.bean.IdentityProfile;
import org.junit.Test;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class BurpExtenderFunctionalTest {

    private static final IHttpService SERVICE = new IHttpService() {
        public String getHost() {
            return "example.test";
        }

        public int getPort() {
            return 443;
        }

        public String getProtocol() {
            return "https";
        }
    };

    @Test
    public void variantIdIncludesHeaderAndBodyContent() {
        byte[] first = ("POST /api HTTP/1.1\r\nHost: example.test\r\n"
                + "X-Variant: one\r\nContent-Length: 1\r\n\r\nA")
                .getBytes(StandardCharsets.ISO_8859_1);
        byte[] second = ("POST /api HTTP/1.1\r\nHost: example.test\r\n"
                + "X-Variant: two\r\nContent-Length: 1\r\n\r\nB")
                .getBytes(StandardCharsets.ISO_8859_1);

        assertNotEquals(BurpExtender.buildVariantId(SERVICE, first),
                BurpExtender.buildVariantId(SERVICE, second));
        assertEquals(BurpExtender.buildVariantId(SERVICE, first),
                BurpExtender.buildVariantId(SERVICE, first.clone()));
    }

    @Test
    public void redirectRequestIdsAreScopedPerProfile() {
        IdentityProfile reader = profile("reader");
        IdentityProfile admin = profile("admin");

        String readerId = BurpExtender.scopeRedirectRequestId(
                "https://example.test/home", "Redirect（1）", List.of(reader));
        String adminId = BurpExtender.scopeRedirectRequestId(
                "https://example.test/home", "Redirect（2）", List.of(admin));

        assertNotEquals(readerId, adminId);
        assertEquals(readerId, BurpExtender.scopeRedirectRequestId(
                "https://example.test/home", "Redirect（3）", List.of(reader)));
        assertEquals("https://example.test/home", BurpExtender.scopeRedirectRequestId(
                "https://example.test/home", "Send", List.of(reader)));
    }

    @Test
    public void redirectContextDoesNotReprocessOrReapplyProfiles() {
        BurpExtender.RedirectScanContext context = BurpExtender.redirectScanContext("auditor");

        assertFalse(context.expandDirectories());
        assertFalse(context.applyPayloadProcessing());
        assertEquals(1, context.profiles().size());
        assertEquals("auditor", context.profiles().get(0).getName());
        assertTrue(context.profiles().get(0).getHeaders().isEmpty());
        assertTrue(context.profiles().get(0).getQuery().isEmpty());
        assertTrue(context.profiles().get(0).getBody().isEmpty());
        assertTrue(BurpExtender.redirectScanContext("").profiles().isEmpty());

        assertTrue(BurpExtender.isRedirectStatus(301));
        assertTrue(BurpExtender.isRedirectStatus(302));
        assertTrue(BurpExtender.isRedirectStatus(303));
        assertTrue(BurpExtender.isRedirectStatus(307));
        assertTrue(BurpExtender.isRedirectStatus(308));
        assertFalse(BurpExtender.isRedirectStatus(304));
        assertEquals("/next", BurpExtender.findHeaderValue(
                List.of("HTTP/1.1 302 Found", "location:/next"), "Location"));
        assertNull(BurpExtender.findHeaderValue(
                List.of("HTTP/1.1 302 Found", "Location:   "), "Location"));
    }

    @Test
    public void hostRulesAreCaseInsensitiveAndSupportMultipleWildcards() {
        assertTrue(BurpExtender.matchHost("API.Dev.Example.COM", "api.*.example.*"));
        assertTrue(BurpExtender.matchHost("sub.example.com", "*.EXAMPLE.com"));
        assertTrue(BurpExtender.matchHost("anything", "*"));
        assertFalse(BurpExtender.matchHost("api.example.net", "api.*.example.*"));
        assertFalse(BurpExtender.matchHost("example.com", ""));
    }

    @Test
    public void redirectedProfilesKeepOneVariantButDifferentParentVariantsDoNotDeduplicate() {
        byte[] readerRequest = ("GET /next?view=full HTTP/1.1\r\nHost: example.test\r\n"
                + "Cookie: role=reader\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1);
        byte[] adminRequest = ("GET /next?view=full HTTP/1.1\r\nHost: example.test\r\n"
                + "Cookie: role=admin\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1);
        byte[] otherTarget = ("GET /other HTTP/1.1\r\nHost: example.test\r\n\r\n")
                .getBytes(StandardCharsets.ISO_8859_1);

        String readerVariant = BurpExtender.buildRedirectVariantId("parent-variant", SERVICE, readerRequest);
        String adminVariant = BurpExtender.buildRedirectVariantId("parent-variant", SERVICE, adminRequest);
        assertEquals(readerVariant, adminVariant);
        String otherVariant = BurpExtender.buildRedirectVariantId(
                "parent-variant", SERVICE, otherTarget);
        assertNotEquals(readerVariant, otherVariant);
        assertEquals(readerVariant,
                BurpExtender.buildRedirectVariantId(otherVariant, SERVICE, readerRequest));

        String firstId = BurpExtender.scopeRedirectRequestId(
                "https://example.test/next", "Redirect（1）", List.of(), readerVariant);
        String secondId = BurpExtender.scopeRedirectRequestId(
                "https://example.test/next", "Redirect（2）", List.of(), "another-parent-variant");
        assertNotEquals(firstId, secondId);
    }

    @Test
    public void profileCookieAcceptsRawValuesAndCompleteHeaders() {
        List<String> original = List.of(
                "GET / HTTP/1.1", "Host: example.test", "Cookie: session=secret");
        List<String> retained = BurpExtender.mergeProfileHeaders(
                original, Map.of("X-Role", "guest"), true, "");
        assertTrue(retained.contains("Cookie: session=secret"));

        List<String> replaced = BurpExtender.mergeProfileHeaders(
                original, Map.of("X-Role", "reader"), true,
                "Cookie: Cookie: session=new; role=reader");
        assertTrue(replaced.contains("Cookie: session=new; role=reader"));
        assertEquals(1, replaced.stream()
                .filter(header -> header.toLowerCase().startsWith("cookie:")).count());
        assertFalse(replaced.stream().anyMatch(header -> header.contains("Cookie: Cookie:")));
        assertEquals("session=raw", BurpExtender.normalizeCookieHeaderValue("session=raw"));
        assertEquals("session=full", BurpExtender.normalizeCookieHeaderValue("cookie : session=full"));
    }

    @Test
    public void fragmentsAreClientSideAndExplicitNonDefaultPortsArePreserved() throws Exception {
        assertTrue(BurpExtender.isFragmentOnlyRedirect("#section"));
        assertFalse(BurpExtender.isFragmentOnlyRedirect("/next#section"));

        URL httpOn443 = new URL("http://example.test:443/path?q=1#section");
        URL httpsOn80 = new URL("https://example.test:80/path");
        assertEquals("example.test:443", UrlUtils.getHostByURL(httpOn443));
        assertEquals("http://example.test:443", UrlUtils.getReqHostByURL(httpOn443));
        assertEquals("http://example.test:443/path?q=1", UrlUtils.toRequestURL(httpOn443));
        assertEquals("https://example.test:80", UrlUtils.getReqHostByURL(httpsOn80));
        assertEquals("example.test:443", BurpExtender.getHostByHttpService(service("http", 443)));
        assertEquals("example.test", BurpExtender.getHostByHttpService(service("https", 443)));
    }

    private static IHttpService service(String protocol, int port) {
        return new IHttpService() {
            public String getHost() {
                return "example.test";
            }

            public int getPort() {
                return port;
            }

            public String getProtocol() {
                return protocol;
            }
        };
    }

    private static IdentityProfile profile(String name) {
        IdentityProfile profile = new IdentityProfile();
        profile.setName(name);
        return profile;
    }
}