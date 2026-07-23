package burp.vaycore.ost.common;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.common.utils.UrlUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * IHttpRequestResponse 接口适配器
 * <p>
 * Created by vaycore on 2023-07-09.
 */
public class HttpReqRespAdapter implements IHttpRequestResponse {

    private IHttpService service;
    private byte[] requestBytes;
    private byte[] responseBytes;
    private String comment;
    private String highlight;

    public static HttpReqRespAdapter from(String url) throws IllegalArgumentException {
        if (StringUtils.isEmpty(url)) {
            throw new IllegalArgumentException("url is null");
        }
        if (!UrlUtils.isHTTP(url)) {
            throw new IllegalArgumentException(url + " does not include the protocol.");
        }
        try {
            URL u = new URL(url);
            IHttpService service = BurpExtender.buildHttpServiceByURL(u);
            String host = UrlUtils.getHostByURL(u);
            byte[] requestBytes = buildRequestBytes(host, UrlUtils.toPQ(u));
            return new HttpReqRespAdapter(service, requestBytes);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Url: " + url + " format error.");
        }
    }

    public static HttpReqRespAdapter from(IHttpService service, String reqPQF,
                                          List<String> headers, List<String> cookies) {
        StringBuilder builder = new StringBuilder();
        String host = BurpExtender.getHostByHttpService(service);
        builder.append("GET ").append(stripFragment(reqPQF)).append(" HTTP/1.1").append("\r\n");
        builder.append("Host: ").append(host).append("\r\n");
        ArrayList<String> oldCookies = new ArrayList<>();
        List<String> safeHeaders = headers == null ? List.of() : headers;
        for (int i = 1; i < safeHeaders.size(); i++) {
            String item = safeHeaders.get(i);
            String name = headerName(item);
            // 排除 Host 请求头（需要特殊定制）
            if ("Host".equalsIgnoreCase(name)) {
                continue;
            }
            if ("Cookie".equalsIgnoreCase(name)) {
                String cookieValue = headerValue(item);
                if (StringUtils.isNotEmpty(cookieValue)) {
                    oldCookies.addAll(Arrays.asList(cookieValue.split(";\\s*")));
                }
                continue;
            }
            builder.append(item).append("\r\n");
        }
        String cookie = mergeCookie(oldCookies.isEmpty() ? null : oldCookies.toArray(new String[0]), cookies);
        if (StringUtils.isNotEmpty(cookie)) {
            builder.append("Cookie: ").append(cookie).append("\r\n");
        }
        builder.append("\r\n");
        byte[] requestBytes = builder.toString().getBytes(StandardCharsets.UTF_8);
        return new HttpReqRespAdapter(service, requestBytes);
    }

    /**
     * Builds a redirect request while preserving the HTTP method and body rules from RFC 9110.
     * 303 always becomes a body-less retrieval (HEAD remains HEAD), 301/302 may rewrite POST
     * to GET, and 307/308 preserve both the original method and raw body bytes.
     */
    public static HttpReqRespAdapter followRedirect(IHttpService service, String reqPQF,
                                                    byte[] originalRequest, List<String> cookies,
                                                    int statusCode) {
        if (service == null || originalRequest == null) {
            throw new IllegalArgumentException("service or original request is null");
        }
        int headerEnd = findHeaderEnd(originalRequest);
        int separatorLength = headerEnd < 0 ? 0 : headerSeparatorLength(originalRequest, headerEnd);
        int bodyOffset = headerEnd < 0 ? originalRequest.length : headerEnd + separatorLength;
        byte[] headerBytes = Arrays.copyOfRange(originalRequest, 0,
                headerEnd < 0 ? originalRequest.length : headerEnd);
        byte[] originalBody = Arrays.copyOfRange(originalRequest,
                Math.min(bodyOffset, originalRequest.length), originalRequest.length);

        String headerText = new String(headerBytes, StandardCharsets.ISO_8859_1);
        String[] lines = headerText.split("\\r?\\n", -1);
        String originalMethod = requestMethod(lines);
        String method = redirectMethod(originalMethod, statusCode);
        boolean dropBody = statusCode == 303
                || ((statusCode == 301 || statusCode == 302) && "POST".equalsIgnoreCase(originalMethod));
        byte[] body = dropBody ? new byte[0] : originalBody;

        StringBuilder builder = new StringBuilder();
        builder.append(method).append(' ').append(stripFragment(reqPQF)).append(" HTTP/1.1\r\n");
        builder.append("Host: ").append(BurpExtender.getHostByHttpService(service)).append("\r\n");

        ArrayList<String> oldCookies = new ArrayList<>();
        for (int i = 1; i < lines.length; i++) {
            String header = lines[i];
            String name = headerName(header);
            if (StringUtils.isEmpty(name) || "Host".equalsIgnoreCase(name)) {
                continue;
            }
            if ("Cookie".equalsIgnoreCase(name)) {
                String value = headerValue(header);
                if (StringUtils.isNotEmpty(value)) {
                    oldCookies.addAll(Arrays.asList(value.split(";\\s*")));
                }
                continue;
            }
            if (dropBody && ("Content-Length".equalsIgnoreCase(name)
                    || "Transfer-Encoding".equalsIgnoreCase(name))) {
                continue;
            }
            builder.append(header).append("\r\n");
        }
        String cookie = mergeCookie(oldCookies.isEmpty() ? null : oldCookies.toArray(new String[0]), cookies);
        if (StringUtils.isNotEmpty(cookie)) {
            builder.append("Cookie: ").append(cookie).append("\r\n");
        }
        builder.append("\r\n");

        byte[] rebuiltHeaders = builder.toString().getBytes(StandardCharsets.ISO_8859_1);
        byte[] requestBytes = new byte[rebuiltHeaders.length + body.length];
        System.arraycopy(rebuiltHeaders, 0, requestBytes, 0, rebuiltHeaders.length);
        System.arraycopy(body, 0, requestBytes, rebuiltHeaders.length, body.length);
        return new HttpReqRespAdapter(service, requestBytes);
    }

    private static String stripFragment(String requestTarget) {
        if (requestTarget == null) {
            return "/";
        }
        int fragment = requestTarget.indexOf('#');
        String result = fragment < 0 ? requestTarget : requestTarget.substring(0, fragment);
        return StringUtils.isEmpty(result) ? "/" : result;
    }

    private static String requestMethod(String[] lines) {
        if (lines == null || lines.length == 0 || StringUtils.isEmpty(lines[0])) {
            return "GET";
        }
        String[] parts = lines[0].trim().split("\\s+", 2);
        return parts.length == 0 || StringUtils.isEmpty(parts[0]) ? "GET" : parts[0];
    }

    private static String redirectMethod(String originalMethod, int statusCode) {
        if (statusCode == 303) {
            return "HEAD".equalsIgnoreCase(originalMethod) ? "HEAD" : "GET";
        }
        if ((statusCode == 301 || statusCode == 302) && "POST".equalsIgnoreCase(originalMethod)) {
            return "GET";
        }
        return StringUtils.isEmpty(originalMethod) ? "GET" : originalMethod;
    }

    private static int findHeaderEnd(byte[] request) {
        for (int i = 0; i <= request.length - 4; i++) {
            if (request[i] == '\r' && request[i + 1] == '\n'
                    && request[i + 2] == '\r' && request[i + 3] == '\n') {
                return i;
            }
        }
        for (int i = 0; i <= request.length - 2; i++) {
            if (request[i] == '\n' && request[i + 1] == '\n') {
                return i;
            }
        }
        return -1;
    }

    private static int headerSeparatorLength(byte[] request, int headerEnd) {
        return headerEnd + 3 < request.length
                && request[headerEnd] == '\r' && request[headerEnd + 1] == '\n'
                && request[headerEnd + 2] == '\r' && request[headerEnd + 3] == '\n' ? 4 : 2;
    }

    private static String headerName(String header) {
        if (StringUtils.isEmpty(header)) {
            return "";
        }
        int separator = header.indexOf(':');
        return separator < 0 ? header.trim() : header.substring(0, separator).trim();
    }

    private static String headerValue(String header) {
        if (StringUtils.isEmpty(header)) {
            return "";
        }
        int separator = header.indexOf(':');
        return separator < 0 ? "" : header.substring(separator + 1).trim();
    }

    public static HttpReqRespAdapter from(IHttpService service, byte[] requestBytes) {
        return new HttpReqRespAdapter(service, requestBytes);
    }


    /**
     * 合并 Cookie 列表
     *
     * @param oldCookies 原请求的 Cookie 列表
     * @param cookies    响应包中的 Cookie 列表
     * @return 返回请求包中的 Cookie 格式
     */
    private static String mergeCookie(String[] oldCookies, List<String> cookies) {
        List<String> result = new ArrayList<>();
        // 处理响应包中 Cookie 列表为空的情况
        if (cookies == null || cookies.isEmpty()) {
            return StringUtils.join(oldCookies, "; ");
        }
        // 合并 Cookie 值
        for (String cookie : cookies) {
            int separator = cookie == null ? -1 : cookie.indexOf('=');
            if (separator <= 0) {
                continue;
            }
            String key = cookie.substring(0, separator);
            String value = cookie.substring(separator + 1);
            int index = cookieKeyIndexOf(oldCookies, key);
            if (index >= 0) {
                oldCookies[index] = null;
            }
            // 兼容 Shiro 移除 Cookie 的操作
            if (value.equalsIgnoreCase("deleteMe")) {
                continue;
            }
            result.add(cookie);
        }
        // 剩下未移除的，全部添加到列表
        if (oldCookies != null) {
            for (String cookie : oldCookies) {
                if (cookie != null) {
                    result.add(cookie);
                }
            }
        }
        return StringUtils.join(result, "; ");
    }

    /**
     * 查询 CookieKey 在列表中的下标
     *
     * @param cookies   列表实例
     * @param cookieKey Cookie 的 key
     * @return 失败返回 -1
     */
    private static int cookieKeyIndexOf(String[] cookies, String cookieKey) {
        if (cookies == null || cookies.length == 0) {
            return -1;
        }
        for (int i = 0; i < cookies.length; i++) {
            String item = cookies[i];
            if (item != null && item.contains("=")) {
                String key = item.substring(0, item.indexOf('='));
                if (key.equals(cookieKey)) {
                    return i;
                }
            }
        }
        return -1;
    }

    private HttpReqRespAdapter() {
        throw new IllegalAccessError("class not support create instance.");
    }

    private HttpReqRespAdapter(IHttpService service, byte[] requestBytes) {
        if (service == null || requestBytes == null) {
            throw new IllegalArgumentException("service or request bytes is null");
        }
        this.service = service;
        this.requestBytes = requestBytes;
        this.responseBytes = new byte[0];
        this.comment = "";
        this.highlight = "";
    }

    private static byte[] buildRequestBytes(String host, String reqPQF) {
        StringBuilder result = buildRequest(host, reqPQF);
        if (StringUtils.isNotEmpty(result)) {
            return result.toString().getBytes(StandardCharsets.UTF_8);
        }
        return new byte[0];
    }

    private static StringBuilder buildRequest(String host, String reqPQF) {
        return new StringBuilder()
                .append("GET ").append(stripFragment(reqPQF)).append(" HTTP/1.1").append("\r\n")
                .append("Host: ").append(host).append("\r\n")
                .append("Accept: ").append("text/html,application/xhtml+xml,")
                .append("application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;")
                .append("q=0.8,application/signed-exchange;v=b3;q=0.9").append("\r\n")
                .append("Accept-Language: ").append("zh-CN,zh;q=0.9,en;q=0.8").append("\r\n")
                .append("Accept-Encoding: ").append("gzip, deflate").append("\r\n")
                .append("Cache-Control: ").append("max-age=0").append("\r\n")
                .append("\r\n");
    }

    @Override
    public byte[] getRequest() {
        return this.requestBytes;
    }

    @Override
    public void setRequest(byte[] bytes) {
        this.requestBytes = bytes;
    }

    @Override
    public byte[] getResponse() {
        return this.responseBytes;
    }

    @Override
    public void setResponse(byte[] bytes) {
        this.responseBytes = bytes;
    }

    @Override
    public String getComment() {
        return this.comment;
    }

    @Override
    public void setComment(String s) {
        this.comment = s;
    }

    @Override
    public String getHighlight() {
        return this.highlight;
    }

    @Override
    public void setHighlight(String s) {
        this.highlight = s;
    }

    @Override
    public IHttpService getHttpService() {
        return this.service;
    }

    @Override
    public void setHttpService(IHttpService iHttpService) {
        this.service = iHttpService;
    }
}
