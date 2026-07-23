package burp.vaycore.ost.bean;

import java.util.LinkedHashMap;
import java.util.Map;

public class IdentityProfile {

    private boolean enabled = true;
    private String name = "";
    private boolean replaceCookie;
    private String cookie = "";
    private Map<String, String> headers = new LinkedHashMap<>();
    private Map<String, String> query = new LinkedHashMap<>();
    private Map<String, String> body = new LinkedHashMap<>();
    private Map<String, String> variables = new LinkedHashMap<>();

    public IdentityProfile() {
    }

    public IdentityProfile(IdentityProfile source) {
        if (source == null) {
            return;
        }
        enabled = source.isEnabled();
        name = source.getName();
        replaceCookie = source.isReplaceCookie();
        cookie = source.getCookie();
        headers = copyMap(source.getHeaders());
        query = copyMap(source.getQuery());
        body = copyMap(source.getBody());
        variables = copyMap(source.getVariables());
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

    public boolean isReplaceCookie() {
        return replaceCookie;
    }

    public void setReplaceCookie(boolean replaceCookie) {
        this.replaceCookie = replaceCookie;
    }

    public String getCookie() {
        return cookie == null ? "" : cookie;
    }

    public void setCookie(String cookie) {
        this.cookie = cookie == null ? "" : cookie;
    }

    public Map<String, String> getHeaders() {
        return safeMap(headers);
    }

    public void setHeaders(Map<String, String> headers) {
        this.headers = copyMap(headers);
    }

    public Map<String, String> getQuery() {
        return safeMap(query);
    }

    public void setQuery(Map<String, String> query) {
        this.query = copyMap(query);
    }

    public Map<String, String> getBody() {
        return safeMap(body);
    }

    public void setBody(Map<String, String> body) {
        this.body = copyMap(body);
    }

    public Map<String, String> getVariables() {
        return safeMap(variables);
    }

    public void setVariables(Map<String, String> variables) {
        this.variables = copyMap(variables);
    }

    private Map<String, String> safeMap(Map<String, String> values) {
        if (values == null) {
            values = new LinkedHashMap<>();
        }
        return values;
    }

    private static Map<String, String> copyMap(Map<String, String> values) {
        return values == null ? new LinkedHashMap<>() : new LinkedHashMap<>(values);
    }

    @Override
    public String toString() {
        return getName();
    }
}
