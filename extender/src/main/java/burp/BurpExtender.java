package burp;

import burp.vaycore.common.helper.DomainHelper;
import burp.vaycore.common.helper.QpsLimiter;
import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.*;
import burp.vaycore.onescan.OneScan;
import burp.vaycore.onescan.bean.TaskData;
import burp.vaycore.onescan.browser.BrowserRequest;
import burp.vaycore.onescan.browser.BrowserRequestManager;
import burp.vaycore.onescan.common.*;
import burp.vaycore.onescan.info.OneScanInfoTab;
import burp.vaycore.onescan.manager.CollectManager;
import burp.vaycore.onescan.manager.FpManager;
import burp.vaycore.onescan.manager.WordlistManager;
import burp.vaycore.onescan.ui.tab.DataBoardTab;
import burp.vaycore.onescan.ui.tab.FingerprintTab;
import burp.vaycore.onescan.ui.tab.config.OtherTab;
import burp.vaycore.onescan.ui.tab.config.RequestTab;
import burp.vaycore.onescan.ui.widget.TaskTable;
import burp.vaycore.onescan.ui.widget.payloadlist.PayloadItem;
import burp.vaycore.onescan.ui.widget.payloadlist.PayloadRule;
import burp.vaycore.onescan.ui.widget.payloadlist.ProcessingItem;

import javax.swing.*;
import javax.swing.Timer;
import java.awt.*;
import java.awt.event.ActionListener;
import java.io.File;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

// 閫夋嫨 Payload 鎵弿
        List<String> payloadList = WordlistManager.getItemList(WordlistManager.KEY_PAYLOAD);
ActionListener listener = (event) -> new Thread(() -> {
                String action = event.getActionCommand();
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                for (IHttpRequestResponse httpReqResp : messages) {
                    doScan(httpReqResp, FROM_SEND, action);
                    // 绾跨▼姹犲叧闂悗锛屽仠姝㈠彂閫佹壂鎻忎换鍔?                    if (isTaskThreadPoolShutdown() || isTaskStopVersionExpired(taskStopVersion)) {
                        Logger.debug("usePayloadScan: thread pool is shutdown, stop sending scan task");
                        return;
                    }
                }
            ).start());
// 鑾峰彇涓€涓嬭姹傛暟鎹寘涓殑璇锋眰璺緞
        String reqPath = getReqPathByRequestInfo(info);
        if (!payloadList.isEmpty() && payloadList.size() > 1) {
            JMenu menu = new JMenu(L.get("use_payload_scan"));
            items.add(menu);
            // 浠庤姹傝矾寰勪腑锛屽皾璇曡幏鍙栬姹備富鏈哄湴鍧€
        String reqHost = getReqHostByReqPath(reqPath);}).start();
            for (String itemName : payloadList) {
                JMenuItem item = new JMenuItem(itemName);
                item.setActionCommand(itemName);
                item.addActionListener(listener);
                menu.add(item);
            }
        }
        return items;
    }

    @Override
    public String getTabCaption() {
        return Constants.PLUGIN_NAME;
    }

    @Override
    public Component getUiComponent() {
        return mOneScan;
    }
// 鍑嗗鐢熸垚浠诲姟
        URL url = getUrlByRequestInfo(info);
// 妫€娴嬪紑鍏崇姸鎬?        if (!mDataBoardTab.hasListenProxyMessage()) {
            return;
        }
        IHttpRequestResponse httpReqResp = message.getMessageInfo();
        if (handleBrowserProxyResponse(httpReqResp)) {
            return;
        }
// 璇锋眰澶存瀯寤哄畬鎴愬悗锛屽閲岄潰鍖呭惈鐨勫姩鎬佸彉閲忚繘琛岃祴鍊?        IHttpService service = httpReqResp.getHttpService();
        URL url = getUrlByRequestInfo(info);
    }

    private void doScan(IHttpRequestResponse httpReqResp, String from) {
        String item = WordlistManager.getItem(WordlistManager.KEY_PAYLOAD);
        doScan(httpReqResp, from, item);
    }
// 鏍规嵁*鍙蜂綅缃紝杩涜鍖归厤
        String ruleValue = rule.replace("*", "");
// 鏀堕泦鏁版嵁锛堝彧鏀堕泦浠ｇ悊娴侀噺鐨勬暟鎹級
            CollectManager.collect(true, host, request);
            CollectManager.collect(false, host, response);
        }
                // 濡傛灉鍚敤锛屽鏉ヨ嚜閲嶅畾鍚戠殑鍖呰繘琛屾娴?        if (from.startsWith(FROM_REDIRECT) && Config.getBoolean(Config.KEY_REDIRECT_TARGET_HOST_LIMIT)) {
                // 妫€娴?Host 鏄惁鍦ㄧ櫧鍚嶅崟銆侀粦鍚嶅崟涓?            if (hostAllowlistFilter(host) || hostBlocklistFilter(host)) {
                Logger.debug("doScan allowlist and blocklist filter host: %s", host);
                return;
            }
        }
                        // 寮€鍚嚎绋嬭瘑鍒寚绾癸紝灏嗚瘑鍒粨鏋滅紦瀛樿捣鏉?        if (!mFpThreadPool.isShutdown()) {
            mFpThreadPool.execute(() -> FpManager.check(request, response));
        }
// 妫€娴嬫槸鍚︽湭杩涜浠讳綍澶勭悊
            boolean equals = Arrays.equals(reqRawBytes, resultBytes);
// 鍘熷璇锋眰涔熼渶瑕佺粡杩?Payload Process 澶勭悊锛堜笉杩囬渶瑕佽繃婊や竴浜涘悗缂€鐨勬祦閲忥級
        if (!proxyExcludeSuffixFilter(url.getPath())) {
// 妫€娴嬫寚绾规暟鎹?        List<FpData> checkResult = FpManager.check(httpReqResp.getRequest(), httpReqResp.getResponse());
// 鏋勫缓琛ㄦ牸瀵硅薄
        TaskData data = new TaskData();
        } else {
            Logger.debug("proxyExcludeSuffixFilter filter request path: %s", url.getPath());
        }
        // 妫€娴嬫槸鍚︾鐢ㄩ€掑綊鎵弿
        if (!mDataBoardTab.hasDirScan()) {
            return;
        }
// 鎵弿浠诲姟
        doScan(httpReqResp, FROM_PROXY);
runScanTask(httpReqResp, info, null,from, taskStopVersion);
        Logger.debug("doScan receive: %s", url.toString());
        ArrayList<String> pathDict = getUrlPathDict(url.getPath());
        List<String> payloads = WordlistManager.getPayload(payloadItem);
// 涓€绾х洰褰曚竴绾х洰褰曢€掑噺璁块棶
        for (int i = pathDict.size() - 1; i >= 0; i--) {
            String path = pathDict.get(i);
// 鍘婚櫎缁撳熬鐨?'/' 绗﹀彿
            if (path.endsWith("/")) {
                path = path.substring(0, path.length() - 1);
            }
        // 鎷兼帴瀛楀吀锛屽彂璧疯姹?            for (String item : payloads) {
        // 绾跨▼姹犲叧闂悗锛屽仠姝㈢户缁敓鎴愪换鍔?                if (isTaskThreadPoolShutdown() || isTaskStopVersionExpired(taskStopVersion)) {
                    return;
                }
        // 瀵瑰畬鏁?Host 鍦板潃鐨勫瓧鍏稿彇娑堥€掑綊鎵弿锛堢洿鎺ユ浛鎹㈣姹傝矾寰勬壂鎻忥級
                if (StringUtils.isNotEmpty(path) && UrlUtils.isHTTP(item)) {
                    continue;
                }
                String urlPath = path + item;
// 濡傛灉閰嶇疆鐨勫瓧鍏镐笉鍚?'/' 鍓嶇紑锛屽湪鏍圭洰褰曚笅鎵弿鏃讹紝鑷姩娣诲姞 '/' 绗﹀彿
                if (StringUtils.isEmpty(path) && !item.startsWith("/") && !UrlUtils.isHTTP(item)) {
                    urlPath = "/" + item;
                }
// 妫€娴嬩竴涓嬫槸鍚︽惡甯﹀畬鏁寸殑 Host 鍦板潃锛堝吋瀹逛竴涓嬫惡甯︿簡瀹屾暣鐨?Host 鍦板潃鐨勬儏鍐碉級
// 浣嗘湁涓墠鎻愶細濡傛灉瀛楀吀瀛樺湪瀹屾暣鐨?Host 鍦板潃锛岀洿鎺ヤ笉鍋氬鐞?                if (UrlUtils.isHTTP(reqPath) && !UrlUtils.isHTTP(item)) {
                    urlPath = reqHost + urlPath;
                }

runScanTask(httpReqResp, info, urlPath, FROM_SCAN, taskStopVersion);
            }
        }
    }

doBurpRequest(service, reqId, request, from, taskStopVersion);

// 杩愯宸茬粡鍚敤骞朵笖闇€瑕佸悎骞剁殑浠诲姟
runEnableAndMergeTask(service, reqId, request, from, taskStopVersion);

// 杩愯宸茬粡鍚敤骞朵笖涓嶉渶瑕佸悎骞剁殑浠诲姟
runEnabledWithoutMergeProcessingTask(service, reqId, request, taskStopVersion);

// 鏈繘琛屼换浣曞鐞嗘椂锛屼笉鍙樻洿 from 鍊?            String newFrom = equals ? from : from + "锛? + FROM_PROCESS + "锛?;
doBurpRequest(service, reqId, resultBytes, newFrom, taskStopVersion);

// 濡傛灉瑙勫垯澶勭悊寮傚父瀵艰嚧鏁版嵁杩斿洖涓虹┖锛屽垯鍙戦€佸師鏉ョ殑璇锋眰
doBurpRequest(service, reqId, reqRawBytes, from, taskStopVersion);

    /**
     * 妫€娴?Host 鏄惁鍖归厤瑙勫垯
     *
     * @param host Host锛堜笉鍖呭惈鍗忚銆佺鍙ｅ彿锛?     * @param rule 瑙勫垯
     * @return true=鍖归厤锛沠alse=涓嶅尮閰?     */
    private static boolean matchHost(String host, String rule) {
        if (StringUtils.isEmpty(host)) {
            return StringUtils.isEmpty(rule);
        }
        // 瑙勫垯灏辨槸*鍙凤紝鐩存帴杩斿洖true
        if (rule.equals("*")) {
            return true;
        }
        // 涓嶅寘鍚?鍙凤紝妫€娴?Host 涓庤鍒欐槸鍚︾浉绛?        if (!rule.contains("*")) {
            return host.equals(rule);
        }

    /**
     * 閫氳繃 IHttpService 瀹炰緥锛岃幏鍙栬姹傜殑 Host 鍊硷紙绀轰緥鏍煎紡锛歺.x.x.x銆亁.x.x.x:8080锛?     *
     * @return 澶辫触杩斿洖null
     */
    public static String getHostByHttpService(IHttpService service) {
        if (service == null) {
            return null;
        }
        String host = service.getHost();
        int port = service.getPort();
        if (Utils.isIgnorePort(port)) {
            return host;
        }
        return host + ":" + port;
    }
        if (rule.startsWith("*") && rule.endsWith("*")) {
            return host.contains(ruleValue);
        } else if (rule.startsWith("*")) {
            return host.endsWith(ruleValue);
        } else if (rule.endsWith("*")) {
            return host.startsWith(ruleValue);
        } else {
            String[] split = rule.split("\\*");
            return host.startsWith(split[0]) && host.endsWith(split[1]);
        }
    }

    /**
     * 閫氳繃 URL 瀹炰緥锛屾瀯寤?IHttpService 瀹炰緥
     *
     * @return 澶辫触杩斿洖null
     */
    public static IHttpService buildHttpServiceByURL(URL url) {
        if (url == null) {
            return null;
        }
        return new IHttpService() {
            @Override
            public String getHost() {
                return url.getHost();
            }

            @Override
            public int getPort() {
                String protocol = getProtocol();
                int port = url.getPort();
                if (port == -1) {
                    port = protocol.equals("https") ? 443 : 80;
                }
                return port;
            }

            @Override
            public String getProtocol() {
                return url.getProtocol();
            }
        };
    }
        String[] split = suffix.split("\\|");
        for (String item : split) {
            if (path.endsWith("." + item)) {
                return true;
            }
        }
        return false;
    }

@Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        ArrayList<JMenuItem> items = new ArrayList<>();
        // 鎵弿閫夊畾鐩爣
        JMenuItem sendToOneScanItem = new JMenuItem(L.get("send_to_plugin"));
        items.add(sendToOneScanItem);
        sendToOneScanItem.addActionListener((event) -> new Thread(() -> {
            IHttpRequestResponse[] messages = invocation.getSelectedMessages();
            for (IHttpRequestResponse httpReqResp : messages) {
                doScan(httpReqResp, FROM_SEND);
                // 绾跨▼姹犲叧闂悗锛屽仠姝㈠彂閫佹壂鎻忎换鍔?                if (isTaskThreadPoolShutdown() || isTaskStopVersionExpired(taskStopVersion)) {
                    Logger.debug("sendToPlugin: thread pool is shutdown, stop sending scan task");
                    return;
                }
            }
        }
        return result;
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        // 褰撹姹傚拰鍝嶅簲閮芥湁鐨勬椂鍊欙紝鎵嶈繘琛屼笅涓€姝ユ搷浣?        if (messageIsRequest) {
            return;
        }
// 濡傛灉鏈惎鐢ㄢ€滆姹傚寘澶勭悊鈥濆姛鑳斤紝鐩存帴瀵规壂鎻忕殑浠诲姟鍙戣捣璇锋眰
        if (!mDataBoardTab.hasPayloadProcessing()) {

    private void doScan(IHttpRequestResponse httpReqResp, String from, String payloadItem) {
        int taskStopVersion = captureTaskStopVersion();
        if (httpReqResp == null || httpReqResp.getHttpService() == null) {
            return;
        }
        IRequestInfo info = mHelpers.analyzeRequest(httpReqResp);
        String host = httpReqResp.getHttpService().getHost();
        byte[] request = httpReqResp.getRequest();
        byte[] response = httpReqResp.getResponse();
        // 瀵规潵鑷唬鐞嗙殑鍖呰繘琛屾娴嬶紝妫€娴嬭姹傛柟娉曟槸鍚﹂渶瑕佹嫤鎴?        if (from.equals(FROM_PROXY)) {
            String method = info.getMethod();
            if (includeMethodFilter(method)) {
                // 鎷︽埅涓嶅尮閰嶇殑璇锋眰鏂规硶
                Logger.debug("doScan filter request method: %s, host: %s", method, host);
                return;
            }
        // 妫€娴?Host 鏄惁鍦ㄧ櫧鍚嶅崟銆侀粦鍚嶅崟涓?            if (hostAllowlistFilter(host) || hostBlocklistFilter(host)) {
                Logger.debug("doScan allowlist and blocklist filter host: %s", host);
                return;
            }
            return;
        }

    /**
     * 浠?IRequestInfo 瀹炰緥涓鍙栬姹傝涓殑璇锋眰璺緞
     *
     * @param info IRequestInfo 瀹炰緥
     * @return 涓嶅瓨鍦ㄨ繑鍥炵┖瀛楃涓?     */
    private String getReqPathByRequestInfo(IRequestInfo info) {
        if (info == null) {
            return "";
        }
        // 鑾峰彇璇锋眰琛?        List<String> headers = info.getHeaders();
        if (!headers.isEmpty()) {
            String reqLine = headers.get(0);
            Matcher matcher = Constants.REGEX_REQ_LINE_URL.matcher(reqLine);
            if (matcher.find() && matcher.groupCount() >= 1) {
                return matcher.group(1);
            }
        }
        return "";
    }

    /**
     * 浠庤姹傝矾寰勪腑锛堟湁浜涚珯鐐硅姹傝矾寰勪腑鍖呭惈瀹屾暣鐨?Host 鍦板潃锛夎幏鍙栬姹傜殑 Host 鍦板潃
     *
     * @param reqPath 璇锋眰璺緞
     * @return 涓嶅寘鍚?Host 鍦板潃锛岃繑鍥炵┖瀛楃涓?     */
    private String getReqHostByReqPath(String reqPath) {
        if (StringUtils.isEmpty(reqPath) || !UrlUtils.isHTTP(reqPath)) {
            return "";
        }
        try {
            URL url = new URL(reqPath);
            return UrlUtils.getReqHostByURL(url);
        } catch (MalformedURLException e) {
            return "";
        }
    }
    }

    /**
     * 杩囨护璇锋眰鏂规硶
     *
     * @param method 璇锋眰鏂规硶
     * @return true=鎷︽埅锛沠alse=涓嶆嫤鎴?     */
    private boolean includeMethodFilter(String method) {
        String includeMethod = Config.get(Config.KEY_INCLUDE_METHOD);
        // 濡傛灉閰嶇疆涓虹┖锛屼笉鎷︽埅浠讳綍璇锋眰鏂规硶
        if (StringUtils.isNotEmpty(includeMethod)) {
            String[] split = includeMethod.split("\\|");
            boolean hasFilter = true;
            for (String item : split) {
                if (method.equals(item)) {
                    hasFilter = false;
                    break;
                }
            }
            return hasFilter;
        }
        return false;
    }
        URL url = getUrlByRequestInfo(info);
        String reqHost = UrlUtils.getReqHostByURL(url);
// 鐢熸垚閲嶅畾鍚戣姹傜殑璇锋眰 ID 鍊?        if (from.startsWith(FROM_REDIRECT)) {
            return reqHost + reqPath;
        }
                // 榛樿浣跨敤 http://x.x.x.x/path/to/index.html 鏍煎紡浣滀负璇锋眰 ID 鍊?        return reqHost + url.getPath();
    }

    /**
     * Host 鐧藉悕鍗曡繃婊?     *
     * @param host Host
     * @return true=鎷︽埅锛沠alse=涓嶆嫤鎴?     */
    private boolean hostAllowlistFilter(String host) {
        List<String> list = WordlistManager.getHostAllowlist();
        // 鐧藉悕鍗曚负绌猴紝涓嶅惎鐢ㄧ櫧鍚嶅崟
        if (list.isEmpty()) {
            return false;
        }
        for (String item : list) {
            if (matchHost(host, item)) {
                return false;
            }
        }
        Logger.debug("hostAllowlistFilter filter host: %s", host);
        return true;
    }

    /**
     * Host 榛戝悕鍗曡繃婊?     *
     * @param host Host
     * @return true=鎷︽埅锛沠alse=涓嶆嫤鎴?     */
    private boolean hostBlocklistFilter(String host) {
        List<String> list = WordlistManager.getHostBlocklist();
        // 榛戝悕鍗曚负绌猴紝涓嶅惎鐢ㄩ粦鍚嶅崟
        if (list.isEmpty()) {
            return false;
        }
        for (String item : list) {
            if (matchHost(host, item)) {
                Logger.debug("hostBlocklistFilter filter host: %s 锛坮ule: %s锛?, host, item);
                return true;
            }
        }
        return false;
    }
        byte[] resultBytes = reqRawBytes;
        for (ProcessingItem item : processList) {
            ArrayList<PayloadItem> items = item.getItems();
            resultBytes = handlePayloadProcess(service, resultBytes, items);
        }
        if (resultBytes != null) {

    /**
     * 浠ｇ悊璇锋眰鐨勫悗缂€杩囨护
     *
     * @param reqPath 璇锋眰璺緞锛堜笉鍖呭惈 Query 鍙傛暟锛?     * @return true=鎷︽埅锛沠alse=涓嶆嫤鎴?     */
    private boolean proxyExcludeSuffixFilter(String reqPath) {
        if (StringUtils.isEmpty(reqPath) || "/".equals(reqPath)) {
            return false;
        }
        // 缁熶竴杞崲涓哄皬鍐?        String suffix = Config.get(Config.KEY_EXCLUDE_SUFFIX).toLowerCase();
        String path = reqPath.toLowerCase();
        if (StringUtils.isEmpty(suffix)) {
            return false;
        }
        // 閰嶇疆涓笉瀛樺湪澶氫釜杩囨护鐨勫悗缂€鍚嶏紝鐩存帴妫€娴?        if (!suffix.contains("|") && path.endsWith("." + suffix)) {
            return true;
        }

    /**
     * 浣跨敤 '/' 鍒嗗壊 URL 瀹炰緥鐨?path 鏁版嵁锛岄€氳繃缁勫悎绗竴灞傜骇鐩綍锛岀敓鎴愬瓧鍏稿垪琛?     *
     * @param urlPath URL 瀹炰緥鐨?path 鏁版嵁
     * @return 澶辫触杩斿洖绌哄垪琛?     */
    private ArrayList<String> getUrlPathDict(String urlPath) {
        String direct = Config.get(Config.KEY_SCAN_LEVEL_DIRECT);
        int scanLevel = Config.getInt(Config.KEY_SCAN_LEVEL);
        ArrayList<String> result = new ArrayList<>();
        result.add("/");
        if (StringUtils.isEmpty(urlPath) || "/".equals(urlPath)) {
            return result;
        }
        // 闄愬埗鏂瑰悜浠庡乏寰€鍙筹紝骞朵笖鎵弿灞傜骇涓?
        if (Config.DIRECT_LEFT.equals(direct) && scanLevel <= 1) {
            return result;
        }
        // 缁撳熬濡傛灉涓嶆槸'/'绗﹀彿锛屽幓鎺夎闂殑鏂囦欢
        if (!urlPath.endsWith("/")) {
            urlPath = urlPath.substring(0, urlPath.lastIndexOf("/") + 1);
        }
        String[] splitDirname = urlPath.split("/");
        if (splitDirname.length == 0) {
            return result;
        }
        // 闄愬埗鏂瑰悜浠庡彸寰€宸︼紝榛樿涓嶆壂鎻忔牴鐩綍
        if (Config.DIRECT_RIGHT.equals(direct) && scanLevel < splitDirname.length) {
            result.remove("/");
        }
        StringBuilder sb = new StringBuilder("/");
        for (String dirname : splitDirname) {
            if (StringUtils.isNotEmpty(dirname)) {
                sb.append(dirname).append("/");
                int level = StringUtils.countMatches(sb.toString(), "/");
                // 鏍规嵁涓嶅悓鏂瑰悜锛岄檺鍒剁洰褰曞眰绾?                if (Config.DIRECT_LEFT.equals(direct) && level > scanLevel) {
                    continue;
                } else if (Config.DIRECT_RIGHT.equals(direct)) {
                    level = splitDirname.length - level;
                    if (level >= scanLevel) {
                        continue;
                    }
                }
                result.add(sb.toString());
            }
        }
        } else {

    /**
     * 杩愯鎵弿浠诲姟
     *
     * @param httpReqResp   璇锋眰鍝嶅簲瀹炰緥
     * @param info          IRequestInfo 瀹炰緥
     * @param pathWithQuery 璺緞+query鍙傛暟
     * @param from          璇锋眰鏉ユ簮
     */
    private void runScanTask(IHttpRequestResponse httpReqResp, IRequestInfo info, String pathWithQuery, String from, int taskStopVersion) {
        IHttpService service = httpReqResp.getHttpService();
        // 澶勭悊璇锋眰澶?        byte[] request = handleHeader(httpReqResp, info, pathWithQuery, from);
        // 澶勭悊璇锋眰澶村け璐ユ椂锛屼涪寮冭浠诲姟
        if (request == null) {
            return;
        }
        IRequestInfo newInfo = mHelpers.analyzeRequest(service, request);
        String reqId = generateReqId(newInfo, from);
        // 濡傛灉褰撳墠 URL 宸茬粡鎵弿锛屼腑姝换鍔?        if (checkRepeatFilterByReqId(reqId)) {
            return;
        }
        }
    }

    /**
     * 鐢熸垚璇锋眰 ID
     *
     * @param info IRequestInfo 瀹炰緥
     * @param from 璇锋眰鏉ユ簮
     * @return 澶辫触杩斿洖 "null" 瀛楃涓?     */
    private String generateReqId(IRequestInfo info, String from) {
        if (info == null || StringUtils.isEmpty(from)) {
            return "null";
        }
        String reqPath = getReqPathByRequestInfo(info);
        // 鐢熸垚鎼哄甫瀹屾暣鐨?Host 鍦板潃璇锋眰鐨勮姹?ID 鍊?        if (UrlUtils.isHTTP(reqPath)) {
            URL originUrl = info.getUrl();
            String originReqHost = UrlUtils.getReqHostByURL(originUrl);
            return originReqHost + "->" + reqPath;
        }

    /**
     * 鏍规嵁 Url 妫€娴嬫槸鍚﹂噸澶嶆壂鎻?     *
     * @param reqId 璇锋眰 ID
     * @return true=閲嶅锛沠alse=涓嶉噸澶?     */
    private synchronized boolean checkRepeatFilterByReqId(String reqId) {
        if (sRepeatFilter.contains(reqId)) {
            return true;
        }
        return !sRepeatFilter.add(reqId);
    }

    /**
     * 杩愯宸茬粡鍚敤骞朵笖闇€瑕佸悎骞剁殑浠诲姟
     *
     * @param service     璇锋眰鐩爣鏈嶅姟瀹炰緥
     * @param reqId       璇锋眰 ID
     * @param reqRawBytes 璇锋眰鏁版嵁鍖?     * @param from        璇锋眰鏉ユ簮
     */
    private void runEnableAndMergeTask(IHttpService service, String reqId, byte[] reqRawBytes, String from, int taskStopVersion) {
        // 鑾峰彇宸茬粡鍚敤骞朵笖闇€瑕佸悎骞剁殑鈥滆姹傚寘澶勭悊鈥濊鍒?        List<ProcessingItem> processList = getPayloadProcess()
                .stream().filter(ProcessingItem::isEnabledAndMerge)
                .collect(Collectors.toList());
        // 濡傛灉瑙勫垯涓虹┖锛岀洿鎺ュ彂璧疯姹?        if (processList.isEmpty()) {
        doBurpRequest(service, reqId, reqRawBytes, from, taskStopVersion);
            return;
        }

    /**
     * 杩愯宸茬粡鍚敤骞朵笖涓嶉渶瑕佸悎骞剁殑浠诲姟
     *
     * @param service     璇锋眰鐩爣鏈嶅姟瀹炰緥
     * @param reqId       璇锋眰 ID
     * @param reqRawBytes 璇锋眰鏁版嵁鍖?     */
    private void runEnabledWithoutMergeProcessingTask(IHttpService service, String reqId, byte[] reqRawBytes, int taskStopVersion) {
        getPayloadProcess().parallelStream().filter(ProcessingItem::isEnabledWithoutMerge)
                .forEach((item) -> {
                    if (isTaskStopVersionExpired(taskStopVersion)) {
                        return;
                    }
                    ArrayList<PayloadItem> items = item.getItems();
                    byte[] requestBytes = handlePayloadProcess(service, reqRawBytes, items);
                    if (requestBytes == null) {
                        return;
                    }
                    if (Arrays.equals(reqRawBytes, requestBytes)) {
                        return;
                    }
                    doBurpRequest(service, reqId, requestBytes, FROM_PROCESS + "（" + item.getName() + "）", taskStopVersion);
                });
    }

    /**
     * 浣跨敤 Burp 鑷甫鐨勬柟寮忚姹?     *
     * @param service     璇锋眰鐩爣鏈嶅姟瀹炰緥
     * @param reqId       璇锋眰 ID
     * @param reqRawBytes 璇锋眰鏁版嵁鍖?     * @param from        璇锋眰鏉ユ簮
     */
    private void doBurpRequest(IHttpService service, String reqId, byte[] reqRawBytes, String from, int taskStopVersion) {
        if (isTaskThreadPoolShutdown() || isTaskStopVersionExpired(taskStopVersion)) {
            Logger.debug("doBurpRequest: thread pool is shutdown, intercept req id: %s", reqId);
            sRepeatFilter.remove(reqId);
            return;
        }
        TaskRunnable task = new TaskRunnable(reqId, from) {
            @Override
            public void run() {
                String reqId = getReqId();
                if (Thread.currentThread().isInterrupted() || isTaskStopVersionExpired(taskStopVersion)) {
                    sRepeatFilter.remove(reqId);
                    incrementTaskOverCounter(from);
                    return;
                }
                if (!isLowFrequencyTask(from) && checkQPSLimit()) {
                    sRepeatFilter.remove(reqId);
                    incrementTaskOverCounter(from);
                    return;
                }
                Logger.debug("Do Send Request id: %s", reqId);
                int retryCount = Config.getInt(Config.KEY_RETRY_COUNT);
                IHttpRequestResponse newReqResp = doMakeHttpRequest(service, reqRawBytes, retryCount, taskStopVersion);
                if (Thread.currentThread().isInterrupted() || isTaskStopVersionExpired(taskStopVersion) || newReqResp == null) {
                    sRepeatFilter.remove(reqId);
                    incrementTaskOverCounter(from);
                    return;
                }
                String displayFrom = isBrowserRequestResponse(newReqResp) ? appendBrowserFrom(from) : from;
                TaskData data = buildTaskData(newReqResp, displayFrom);
                mDataBoardTab.getTaskTable().addTaskData(data);
                CollectManager.collect(false, service.getHost(), newReqResp.getResponse());
                handleFollowRedirect(data, taskStopVersion);
                incrementTaskOverCounter(from);
            }
        };
        try {
            if (isLowFrequencyTask(from)) {
                mLFTaskThreadPool.execute(task);
                mLFTaskCommitCounter.incrementAndGet();
            } else {
                mTaskThreadPool.execute(task);
                mTaskCommitCounter.incrementAndGet();
            }
        } catch (Exception e) {
            Logger.error("doBurpRequest thread execute error: %s", e.getMessage());
        }
    }

    /**
     * 浠诲姟绾跨▼姹犳槸鍚﹀叧闂?     *
     * @return true=鏄紱false=鍚?     */
    private boolean isTaskThreadPoolShutdown() {
        return mTaskThreadPool.isShutdown() || mLFTaskThreadPool.isShutdown();
    }

private int captureTaskStopVersion() {
    return mTaskStopVersion.get();
}

private boolean isTaskStopVersionExpired(int taskStopVersion) {
    return taskStopVersion != mTaskStopVersion.get();
}

    /**
     * 褰撳墠璇锋眰鏉ユ簮锛屾槸鍚︿负浣庨浠诲姟
     *
     * @param from 璇锋眰鏉ユ簮
     * @return true=鏄紱false=鍚?     */
    private boolean isLowFrequencyTask(String from) {
        if (StringUtils.isEmpty(from)) {
            return false;
        }
        return from.startsWith(FROM_PROXY) || from.startsWith(FROM_SEND) || from.startsWith(FROM_REDIRECT);
    }
        return null;
    }

    /**
     * 澧炲姞浠诲姟瀹屾垚璁℃暟
     *
     * @param from 璇锋眰鏉ユ簮
     */
    private void incrementTaskOverCounter(String from) {
        if (isLowFrequencyTask(from)) {
            // 浣庨浠诲姟瀹屾垚璁℃暟
            mLFTaskOverCounter.incrementAndGet();
        } else {
            // 浠诲姟瀹屾垚璁℃暟
            mTaskOverCounter.incrementAndGet();
        }
    }

    /**
     * 澶勭悊璺熼殢閲嶅畾鍚?     */
    private void handleFollowRedirect(TaskData data, int taskStopVersion) {
        if (!Config.getBoolean(Config.KEY_FOLLOW_REDIRECT)) {
            return;
        }
        int status = data.getStatus();
        if (status < 300 || status >= 400) {
            return;
        }
        if (Thread.currentThread().isInterrupted() || isTaskStopVersionExpired(taskStopVersion)) {
            Logger.debug("handleFollowRedirect: thread pool is shutdown, intercept data id: %s", data.getId());
            return;
        }
        IHttpRequestResponse reqResp = (IHttpRequestResponse) data.getReqResp();
        IResponseInfo respInfo = mHelpers.analyzeResponse(reqResp.getResponse());
        String location = getLocationByResponseInfo(respInfo);
        if (location == null) {
            return;
        }
        List<String> cookies = null;
        if (Config.getBoolean(Config.KEY_REDIRECT_COOKIES_FOLLOW)) {
            cookies = getCookieByResponseInfo(respInfo);
        }
        String reqHost = data.getHost();
        String reqPath = data.getUrl();
        try {
            HttpReqRespAdapter httpReqResp;
            IRequestInfo reqInfo = mHelpers.analyzeRequest(reqResp);
            List<String> headers = reqInfo.getHeaders();
            if (UrlUtils.isHTTP(reqPath)) {
                URL originUrl = UrlUtils.parseURL(reqPath);
                URL redirectUrl = UrlUtils.parseRedirectTargetURL(originUrl, location);
                IHttpService service = reqResp.getHttpService();
                httpReqResp = HttpReqRespAdapter.from(service, redirectUrl.toString(), headers, cookies);
            } else {
                URL originUrl = UrlUtils.parseURL(reqHost + reqPath);
                URL redirectUrl = UrlUtils.parseRedirectTargetURL(originUrl, location);
                IHttpService service = buildHttpServiceByURL(redirectUrl);
                httpReqResp = HttpReqRespAdapter.from(service, UrlUtils.toPQF(redirectUrl), headers, cookies);
            }
            if (isTaskStopVersionExpired(taskStopVersion)) {
                return;
            }
            doScan(httpReqResp, FROM_REDIRECT + "（" + data.getId() + "）");
        } catch (Exception e) {
            Logger.debug("handleFollowRedirect error: %s", e.getMessage());
        }
    }

    /**
     * 浠?IResponseInfo 瀹炰緥鑾峰彇鍝嶅簲澶?Location 鍊?     *
     * @param info IResponseInfo 瀹炰緥
     * @return 澶辫触杩斿洖null
     */
    private String getLocationByResponseInfo(IResponseInfo info) {
        String headerPrefix = "location: ";
        List<String> headers = info.getHeaders();
        for (int i = 1; i < headers.size(); i++) {
            String header = headers.get(i);
            // 妫€娴嬫椂蹇界暐澶у皬鍐?            if (header.toLowerCase().startsWith(headerPrefix)) {
                return header.substring(headerPrefix.length());
            }
        }

    /**
     * 浠?IResponseInfo 瀹炰緥鑾峰彇鍝嶅簲澶?Set-Cookie 鍊硷紝骞惰浆鎹负璇锋眰澶寸殑 Cookie 鍊煎垪琛?     *
     * @param info IResponseInfo 瀹炰緥
     * @return 澶辫触杩斿洖绌哄垪琛?     */
    private List<String> getCookieByResponseInfo(IResponseInfo info) {
        List<ICookie> respCookies = info.getCookies();
        List<String> cookies = new ArrayList<>();
        for (ICookie cookie : respCookies) {
            String name = cookie.getName();
            String value = cookie.getValue();
            // 鎷兼帴鍚庯紝娣诲姞鍒板垪琛?            cookies.add(String.format("%s=%s", name, value));
        }
        return cookies;
    }

    /**
     * 璋冪敤 BurpSuite 璇锋眰鏂瑰紡
     *
     * @param service     璇锋眰鐩爣鏈嶅姟瀹炰緥
     * @param reqRawBytes 璇锋眰鏁版嵁鍖?     * @param retryCount  閲嶈瘯娆℃暟锛堜负0琛ㄧず涓嶉噸璇曪級
     * @return 璇锋眰鍝嶅簲鏁版嵁
     */
    private IHttpRequestResponse doMakeHttpRequest(IHttpService service, byte[] reqRawBytes, int retryCount, int taskStopVersion) {
        IHttpRequestResponse reqResp;
        String reqHost = getReqHostByHttpService(service);
        if (Config.getBoolean(Config.KEY_INTERCEPT_TIMEOUT_HOST) && checkTimeoutByReqHost(reqHost)) {
            return HttpReqRespAdapter.from(service, reqRawBytes);
        }
        if (Thread.currentThread().isInterrupted() || isTaskStopVersionExpired(taskStopVersion)) {
            Logger.debug("doMakeHttpRequest: task stop version expired, intercept task");
            return HttpReqRespAdapter.from(service, reqRawBytes);
        }
        IHttpRequestResponse browserReqResp = doBrowserRequest(service, reqRawBytes, taskStopVersion);
        if (browserReqResp != null) {
            return browserReqResp;
        }
        try {
            reqResp = mCallbacks.makeHttpRequest(service, reqRawBytes);
            byte[] respRawBytes = reqResp.getResponse();
            if (respRawBytes != null && respRawBytes.length > 0) {
                return reqResp;
            }
        } catch (Exception e) {
            Logger.debug("Do Request error, request host: %s", reqHost);
            reqResp = HttpReqRespAdapter.from(service, reqRawBytes);
        }
        if (Thread.currentThread().isInterrupted() || isTaskStopVersionExpired(taskStopVersion)) {
            Logger.debug("doMakeHttpRequest: thread pool is shutdown, intercept task");
            return reqResp;
        }
        Logger.debug("Check retry request host: %s, count: %d", reqHost, retryCount);
        if (retryCount <= 0) {
            sTimeoutReqHost.add(reqHost);
            return reqResp;
        }
        int retryInterval = Config.getInt(Config.KEY_RETRY_INTERVAL);
        if (retryInterval > 0) {
            try {
                Thread.sleep(retryInterval);
            } catch (InterruptedException e) {
                return reqResp;
            }
        }
        return doMakeHttpRequest(service, reqRawBytes, retryCount - 1, taskStopVersion);
    }

    /**
     * 妫€娴嬪綋鍓嶈姹備富鏈烘槸鍚﹁秴鏃?     *
     * @param reqHost Host锛堟牸寮忥細http://x.x.x.x銆乭ttp://x.x.x.x:8080锛?     * @return true=瀛樺湪锛沠alse=涓嶅瓨鍦?     */
    private IHttpRequestResponse doBrowserRequest(IHttpService service, byte[] reqRawBytes, int taskStopVersion) {
        if (Thread.currentThread().isInterrupted() || isTaskStopVersionExpired(taskStopVersion)) {
            return null;
        }
        if (!canUseBrowserRequest(service, reqRawBytes)) {
            return null;
        }
        synchronized (mBrowserRequestLock) {
            try {
                if (Thread.currentThread().isInterrupted() || isTaskStopVersionExpired(taskStopVersion)) {
                    return null;
                }
                BrowserRequest browserRequest = buildBrowserRequest(service, reqRawBytes);
                if (browserRequest == null) {
                    return null;
                }
                Logger.debug("Do browser request: %s %s", browserRequest.getMethod(), browserRequest.getUrl());
                long browserTimeout = getBrowserRequestTimeout();
                BrowserRequestManager.BrowserResult result = mBrowserRequestManager.navigate(
                        browserRequest, Config.sanitizeBrowserType(Config.get(Config.KEY_BROWSER_TYPE)),
                        Config.get(Config.KEY_BROWSER_BINARY_PATH),
                        browserTimeout, Config.getWorkDir(),
                        Config.get(Config.KEY_BROWSER_PYTHON_PATH),
                        Config.getBoolean(Config.KEY_BROWSER_LOAD_STATIC_RESOURCES));
                IHttpRequestResponse reqResp = HttpReqRespAdapter.from(service, reqRawBytes);
                reqResp.setResponse(buildBrowserResponseBytes(result));
                reqResp.setComment(FROM_BROWSER);
                return reqResp;
            } catch (Exception e) {
                Logger.debug("Browser request error: %s", e.getMessage());
                IHttpRequestResponse reqResp = HttpReqRespAdapter.from(service, reqRawBytes);
                reqResp.setResponse(buildBrowserErrorResponseBytes(e));
                reqResp.setComment(FROM_BROWSER);
                return reqResp;
            }
        }
    }

    private boolean handleBrowserProxyResponse(IHttpRequestResponse httpReqResp) {
        if (httpReqResp == null || httpReqResp.getResponse() == null || httpReqResp.getRequest() == null) {
            return false;
        }
        String requestKey = buildBrowserRequestKey(httpReqResp);
        if (requestKey == null) {
            return shouldSuppressBrowserProxyTraffic(httpReqResp);
        }
        BrowserRequestTask task = mBrowserRequestTasks.get(requestKey);
        if (task != null || isExpectedBrowserRequest(requestKey)) {
            cacheBrowserResponse(requestKey, httpReqResp);
            if (task != null) {
                task.update(httpReqResp);
            }
            extendBrowserTrafficScope();
            return true;
        }
        return shouldSuppressBrowserProxyTraffic(httpReqResp);
    }

    private String buildBrowserRequestKey(IHttpRequestResponse httpReqResp) {
        IRequestInfo info = mHelpers.analyzeRequest(httpReqResp);
        return buildBrowserRequestKey(info);
    }

    private String buildBrowserRequestKey(IHttpService service, byte[] reqRawBytes) {
        IRequestInfo info = mHelpers.analyzeRequest(service, reqRawBytes);
        return buildBrowserRequestKey(info);
    }

    private String buildBrowserRequestKey(IRequestInfo info) {
        if (info == null) {
            return null;
        }
        URL url = getUrlByRequestInfo(info);
        if (url == null) {
            return null;
        }
        return info.getMethod() + " " + url.toString();
    }

    private boolean isBrowserRequestResponse(IHttpRequestResponse reqResp) {
        return reqResp != null && FROM_BROWSER.equals(reqResp.getComment());
    }

    private String appendBrowserFrom(String from) {
        if (from == null || from.contains(FROM_BROWSER)) {
            return from;
        }
        return from + " (" + FROM_BROWSER + ")";
    }

    private int clearBrowserRequestTasks() {
        int count = mBrowserRequestTasks.size();
        for (BrowserRequestTask task : mBrowserRequestTasks.values()) {
            task.update(task.createFallback());
        }
        mBrowserRequestTasks.clear();
        mBrowserExpectedRequests.clear();
        mBrowserResponseCache.clear();
        mBrowserTrafficScope = null;
        return count;
    }

    private void closeBrowserRequestDriver() {
        mBrowserRequestManager.close(Config.getWorkDir(),
                Config.get(Config.KEY_BROWSER_PYTHON_PATH),
                Config.sanitizeBrowserType(Config.get(Config.KEY_BROWSER_TYPE)),
                Config.get(Config.KEY_BROWSER_BINARY_PATH));
    }

    private void cancelBrowserRequestDriver() {
        mBrowserRequestManager.cancelCurrentProcess();
    }

    private void closeBrowserRequestDriverAsync() {
        if (mBrowserCloseExecutor.isShutdown()) {
            return;
        }
        mBrowserCloseExecutor.submit(() -> {
            try {
                closeBrowserRequestDriver();
            } catch (Exception e) {
                Logger.debug("Async close browser bridge error: %s", e.getMessage());
            }
        });
    }

    private void setBrowserTrafficScope(String targetUrl, long ttlMillis) {
        try {
            mBrowserTrafficScope = new BrowserTrafficScope(targetUrl, ttlMillis);
        } catch (MalformedURLException e) {
            mBrowserTrafficScope = null;
        }
    }

    private void extendBrowserTrafficScope() {
        BrowserTrafficScope scope = mBrowserTrafficScope;
        if (scope != null) {
            scope.extend(BROWSER_TRAFFIC_SUPPRESS_TTL);
        }
    }

    private boolean shouldSuppressBrowserProxyTraffic(IHttpRequestResponse httpReqResp) {
        BrowserTrafficScope scope = mBrowserTrafficScope;
        if (scope == null || scope.isExpired()) {
            return false;
        }
        IRequestInfo info = mHelpers.analyzeRequest(httpReqResp);
        URL url = getUrlByRequestInfo(info);
        if (url == null) {
            return false;
        }
        String urlText = url.toString();
        if (scope.isSameTargetUrl(urlText)) {
            scope.extend(BROWSER_TRAFFIC_SUPPRESS_TTL);
            return true;
        }
        List<String> headers = info.getHeaders();
        String referer = getHeaderValue(headers, "Referer");
        boolean relatedReferer = scope.matchesReferer(referer);
        boolean sameHost = scope.isSameHost(url);
        if (relatedReferer) {
            scope.extend(BROWSER_TRAFFIC_SUPPRESS_TTL);
            return true;
        }
        String secFetchDest = getHeaderValue(headers, "Sec-Fetch-Dest");
        if ((relatedReferer || sameHost) && isStaticBrowserFetchDest(secFetchDest)) {
            scope.extend(BROWSER_TRAFFIC_SUPPRESS_TTL);
            return true;
        }
        String accept = getHeaderValue(headers, "Accept");
        if ((relatedReferer || sameHost) && isStaticBrowserAccept(accept)) {
            scope.extend(BROWSER_TRAFFIC_SUPPRESS_TTL);
            return true;
        }
        String secFetchSite = getHeaderValue(headers, "Sec-Fetch-Site");
        if (sameHost && StringUtils.isNotEmpty(secFetchSite) && !"none".equalsIgnoreCase(secFetchSite)) {
            scope.extend(BROWSER_TRAFFIC_SUPPRESS_TTL);
            return true;
        }
        return false;
    }

    private void rememberBrowserExpectedRequest(String requestKey, long ttlMillis) {
        if (StringUtils.isEmpty(requestKey)) {
            return;
        }
        mBrowserExpectedRequests.put(requestKey, System.currentTimeMillis() + ttlMillis);
    }

    private boolean isExpectedBrowserRequest(String requestKey) {
        if (StringUtils.isEmpty(requestKey)) {
            return false;
        }
        Long expireAt = mBrowserExpectedRequests.get(requestKey);
        if (expireAt == null) {
            return false;
        }
        if (System.currentTimeMillis() > expireAt) {
            mBrowserExpectedRequests.remove(requestKey, expireAt);
            mBrowserResponseCache.remove(requestKey);
            return false;
        }
        return true;
    }

    private void cacheBrowserResponse(String requestKey, IHttpRequestResponse reqResp) {
        if (StringUtils.isEmpty(requestKey) || reqResp == null) {
            return;
        }
        reqResp.setComment(FROM_BROWSER);
        rememberBrowserExpectedRequest(requestKey, BROWSER_PROXY_CACHE_TTL);
        mBrowserResponseCache.put(requestKey, new BrowserResponseCacheEntry(reqResp, BROWSER_PROXY_CACHE_TTL));
    }

    private IHttpRequestResponse getCachedBrowserResponse(String requestKey) {
        if (StringUtils.isEmpty(requestKey)) {
            return null;
        }
        BrowserResponseCacheEntry entry = mBrowserResponseCache.get(requestKey);
        if (entry == null) {
            return null;
        }
        if (entry.isExpired()) {
            mBrowserResponseCache.remove(requestKey, entry);
            mBrowserExpectedRequests.remove(requestKey);
            return null;
        }
        entry.reqResp.setComment(FROM_BROWSER);
        return entry.reqResp;
    }

    private IHttpRequestResponse waitForCachedBrowserResponse(String requestKey, long waitMillis) throws InterruptedException {
        long deadline = System.currentTimeMillis() + waitMillis;
        while (System.currentTimeMillis() < deadline) {
            IHttpRequestResponse reqResp = getCachedBrowserResponse(requestKey);
            if (reqResp != null) {
                return reqResp;
            }
            Thread.sleep(100L);
        }
        return getCachedBrowserResponse(requestKey);
    }

    private IHttpRequestResponse awaitBrowserRequestResult(String requestKey, BrowserRequestTask task)
            throws InterruptedException {
        long browserTimeout = getBrowserRequestTimeout();
        IHttpRequestResponse reqResp = getCachedBrowserResponse(requestKey);
        if (reqResp != null) {
            return reqResp;
        }
        if (task != null) {
            reqResp = task.awaitResponse(browserTimeout, BROWSER_REQUEST_SETTLE_TIME);
            if (reqResp != null) {
                reqResp.setComment(FROM_BROWSER);
                cacheBrowserResponse(requestKey, reqResp);
                return reqResp;
            }
        }
        return waitForCachedBrowserResponse(requestKey, BROWSER_REQUEST_SETTLE_TIME);
    }

    private String getHeaderValue(List<String> headers, String headerName) {
        if (headers == null || StringUtils.isEmpty(headerName)) {
            return null;
        }
        String prefix = headerName + ":";
        for (String header : headers) {
            if (header.regionMatches(true, 0, prefix, 0, prefix.length())) {
                return header.substring(prefix.length()).trim();
            }
        }
        return null;
    }

    private boolean isStaticBrowserFetchDest(String secFetchDest) {
        if (StringUtils.isEmpty(secFetchDest)) {
            return false;
        }
        String value = secFetchDest.toLowerCase();
        return Arrays.asList("image", "script", "style", "font", "manifest", "media",
                "audio", "video", "track", "worker", "sharedworker", "serviceworker").contains(value);
    }

    private boolean isStaticBrowserAccept(String accept) {
        if (StringUtils.isEmpty(accept)) {
            return false;
        }
        String value = accept.toLowerCase();
        return value.contains("image/")
                || value.contains("text/css")
                || value.contains("javascript")
                || value.contains("font/");
    }

    private byte[] buildBrowserResponseBytes(BrowserRequestManager.BrowserResult result) {
        if (result == null) {
            return EMPTY_BYTES;
        }
        int status = result.getStatus() > 0 ? result.getStatus() : 200;
        String reason = StringUtils.isNotEmpty(result.getReason()) ? result.getReason() : "OK";
        byte[] bodyBytes = result.getBodyBytes();
        if (bodyBytes == null) {
            bodyBytes = EMPTY_BYTES;
        }
        StringBuilder headers = new StringBuilder();
        headers.append("HTTP/1.1 ").append(status).append(" ").append(reason).append("\r\n");
        boolean hasContentLength = false;
        for (Map.Entry<String, String> entry : result.getHeaders().entrySet()) {
            String key = entry.getKey();
            if (StringUtils.isEmpty(key)) {
                continue;
            }
            if ("transfer-encoding".equalsIgnoreCase(key) || "content-encoding".equalsIgnoreCase(key)) {
                continue;
            }
            if ("content-length".equalsIgnoreCase(key)) {
                hasContentLength = true;
            }
            headers.append(key).append(": ").append(entry.getValue()).append("\r\n");
        }
        if (!hasContentLength) {
            headers.append("Content-Length: ").append(bodyBytes.length).append("\r\n");
        }
        headers.append("\r\n");
        byte[] headerBytes = headers.toString().getBytes(StandardCharsets.ISO_8859_1);
        byte[] responseBytes = new byte[headerBytes.length + bodyBytes.length];
        System.arraycopy(headerBytes, 0, responseBytes, 0, headerBytes.length);
        System.arraycopy(bodyBytes, 0, responseBytes, headerBytes.length, bodyBytes.length);
        return responseBytes;
    }

    private byte[] buildBrowserErrorResponseBytes(Exception e) {
        String message = "Browser bridge request failed.";
        if (e != null && StringUtils.isNotEmpty(e.getMessage())) {
            message = message + "\r\n" + e.getMessage();
        }
        byte[] bodyBytes = message.getBytes(StandardCharsets.UTF_8);
        String headers = "HTTP/1.1 599 Browser Bridge Error\r\n"
                + "Content-Type: text/plain; charset=UTF-8\r\n"
                + "Content-Length: " + bodyBytes.length + "\r\n\r\n";
        byte[] headerBytes = headers.getBytes(StandardCharsets.ISO_8859_1);
        byte[] responseBytes = new byte[headerBytes.length + bodyBytes.length];
        System.arraycopy(headerBytes, 0, responseBytes, 0, headerBytes.length);
        System.arraycopy(bodyBytes, 0, responseBytes, headerBytes.length, bodyBytes.length);
        return responseBytes;
    }

    private long getBrowserRequestTimeout() {
        int timeout = Config.getInt(Config.KEY_BROWSER_TIMEOUT);
        if (timeout < 1000 || timeout > 300000) {
            return 15000L;
        }
        return timeout;
    }

    private boolean checkTimeoutByReqHost(String reqHost) {
        if (sTimeoutReqHost.isEmpty()) {
            return false;
        }
        return sTimeoutReqHost.contains(reqHost);
    }

        private boolean canUseBrowserRequest(IHttpService service, byte[] reqRawBytes) {
        if (!Config.getBoolean(Config.KEY_ENABLE_BROWSER_REQUEST)) {
            return false;
        }
        IRequestInfo info = mHelpers.analyzeRequest(service, reqRawBytes);
        String method = info.getMethod();
        if (!"GET".equalsIgnoreCase(method) && !"POST".equalsIgnoreCase(method)) {
            return false;
        }
        URL url = getUrlByRequestInfo(info);
        return url != null && matchesBrowserRequestTarget(url.getHost());
    } else {
            String reqLine = headers.get(0);
// 鍏堟娴嬩竴涓嬫槸鍚﹀寘鍚?' HTTP/' 瀛楃涓诧紝鍐嶇户缁鐞嗭紙鍙兘鏈変簺鐣稿舰鏁版嵁鍖呬笉瀛樺湪璇ュ唴瀹癸級
            if (reqLine.contains(" HTTP/")) {
                int start = reqLine.lastIndexOf(" HTTP/");
                reqLine = reqLine.substring(0, start) + " HTTP/1.1";
            }
            requestRaw.append(reqLine).append("\r\n");
        }
                // 璇锋眰澶寸殑鍙傛暟澶勭悊锛堥『甯﹀鐞嗙Щ闄ょ殑璇锋眰澶达級锛屼粠 1 寮€濮嬭〃绀鸿烦杩囬琛岋紙璇锋眰琛岋級
        for (int i = 1; i < headers.size(); i++) {
            String item = headers.get(i);
            String key = item.split(": ")[0];
// 鏄惁闇€瑕佺Щ闄ゅ綋鍓嶈姹傚ご瀛楁锛堜紭鍏堢骇鏈€楂橈級
            if (removeHeaders.contains(key)) {
                continue;
            }
        // 濡傛灉鏄壂鎻忕殑璇锋眰锛堝彧鏈?GET 璇锋眰锛夛紝灏?Content-Length 绉婚櫎
            if (from.equals(FROM_SCAN) && "Content-Length".equalsIgnoreCase(key)) {
                continue;
            }
        // 妫€娴嬮厤缃腑鏄惁瀛樺湪褰撳墠璇锋眰澶村瓧娈?            String matchItem = configHeader.stream().filter(configHeaderItem -> {
                if (StringUtils.isNotEmpty(configHeaderItem) && configHeaderItem.contains(": ")) {
                    String configHeaderKey = configHeaderItem.split(": ")[0];
// 妫€娴嬫槸鍚﹂渶瑕佺Щ闄ゅ綋鍓嶈姹傚ご瀛楁
                    if (removeHeaders.contains(key)) {
                        return false;
                    }
                    return configHeaderKey.equals(key);
                }
                return false;
            }).findFirst().orElse(null);
// 閰嶇疆涓瓨鍦ㄥ尮閰嶉」锛屾浛鎹负閰嶇疆涓殑鏁版嵁
            if (matchItem != null) {
                requestRaw.append(matchItem).append("\r\n");
// 灏嗗凡缁忔坊鍔犵殑鏁版嵁浠庡垪琛ㄤ腑绉婚櫎
                configHeader.remove(matchItem);
            } else {
                    // 涓嶅瓨鍦ㄥ尮閰嶉」锛屽～鍏呭師鏁版嵁
                requestRaw.append(item).append("\r\n");
            }
        }
                    // 灏嗛厤缃噷鍓╀笅鐨勫€煎叏閮ㄥ～鍏呭埌璇锋眰澶翠腑
        for (String item : configHeader) {
            String key = item.split(": ")[0];
// 妫€娴嬫槸鍚﹂渶瑕佺Щ闄ゅ綋鍓岾EY
            if (!removeHeaders.contains(key)) {
                requestRaw.append(item).append("\r\n");
            }
        }
        requestRaw.append("\r\n");
// 濡傛灉褰撳墠鏁版嵁鏉ユ簮涓嶆槸 Scan锛屽彲鑳戒細鍖呭惈 POST 璇锋眰锛屽垽鏂槸鍚﹀瓨鍦?body 鏁版嵁
        if (!from.equals(FROM_SCAN)) {
            byte[] httpRequest = httpReqResp.getRequest();
            int bodyOffset = info.getBodyOffset();
            int bodySize = httpRequest.length - bodyOffset;
            if (bodySize > 0) {
                requestRaw.append(new String(httpRequest, bodyOffset, bodySize));
            }
        }

private BrowserRequest buildBrowserRequest(IHttpService service, byte[] reqRawBytes) {
    IRequestInfo info = mHelpers.analyzeRequest(service, reqRawBytes);
    URL url = getUrlByRequestInfo(info);
    if (url == null) {
        return null;
    }
    List<String> infoHeaders = info.getHeaders();
    List<String> headers = new ArrayList<String>();
    for (int i = 1; i < infoHeaders.size(); i++) {
        headers.add(infoHeaders.get(i));
    }
    int bodyOffset = info.getBodyOffset();
    byte[] body = new byte[0];
    if (reqRawBytes != null && bodyOffset >= 0 && bodyOffset < reqRawBytes.length) {
        body = Arrays.copyOfRange(reqRawBytes, bodyOffset, reqRawBytes.length);
    }
    return BrowserRequest.of(info.getMethod(), url.toString(), headers, body);
}
        String newRequestRaw = setupVariable(service, url, requestRaw.toString());
        if (newRequestRaw == null) {
            return null;
        }
        // 鏇存柊 Content-Length
        return updateContentLength(mHelpers.stringToBytes(newRequestRaw));
    }

private boolean matchesBrowserRequestTarget(String host) {
    String regex = Config.get(Config.KEY_BROWSER_TARGET_HOST_REGEX);
    if (StringUtils.isEmpty(regex)) {
        return true;
    }
    if (StringUtils.isEmpty(host)) {
        return false;
    }
    try {
        return Pattern.compile(regex).matcher(host).find();
    } catch (PatternSyntaxException e) {
        Logger.debug("Browser target regex invalid: %s", e.getMessage());
            return false;
        }
    }

/**
     * 澶勭悊璇锋眰澶?     *
     * @param httpReqResp   Burp 鐨?HTTP 璇锋眰鍝嶅簲鎺ュ彛
     * @param pathWithQuery 璇锋眰璺緞锛屾垨鑰呰姹傝矾寰?Query锛堢ず渚嬶細/xxx銆?xxx/index?a=xxx&b=xxx锛?     * @param from          鏁版嵁鏉ユ簮
     * @return 澶勭悊瀹屾垚鐨勬暟鎹寘锛屽け璐ユ椂杩斿洖null
     */
    private byte[] handleHeader(IHttpRequestResponse httpReqResp, IRequestInfo info, String pathWithQuery, String from) {
        // 閰嶇疆鐨勮姹傚ご
        List<String> configHeader = getHeader();
        // 瑕佺Щ闄ょ殑璇锋眰澶碖EY鍒楄〃
        List<String> removeHeaders = getRemoveHeaders();
        // 鏁版嵁鍖呰嚜甯︾殑璇锋眰澶?        List<String> headers = info.getHeaders();
        // 鏋勫缓璇锋眰澶?        StringBuilder requestRaw = new StringBuilder();
        // 鏍规嵁鏁版嵁鏉ユ簮鍖哄垎涓ょ璇锋眰澶?        if (from.equals(FROM_SCAN)) {
            requestRaw.append("GET ").append(pathWithQuery).append(" HTTP/1.1").append("\r\n");
        }

    /**
     * 鑾峰彇璇锋眰澶撮厤缃?     */
    private List<String> getHeader() {
        if (!mDataBoardTab.hasReplaceHeader()) {
            return new ArrayList<>();
        }
        return WordlistManager.getHeader();
    }

    /**
     * 鑾峰彇绉婚櫎璇锋眰澶村垪琛ㄩ厤缃?     */
    private List<String> getRemoveHeaders() {
        if (!mDataBoardTab.hasRemoveHeader()) {
            return new ArrayList<>();
        }
        return WordlistManager.getRemoveHeaders();
    }

    /**
     * 鑾峰彇閰嶇疆鐨?Payload Processing 瑙勫垯
     */
    private List<ProcessingItem> getPayloadProcess() {
        ArrayList<ProcessingItem> list = Config.getPayloadProcessList();
        if (list == null) {
            return new ArrayList<>();
        }
        return list.stream().filter(ProcessingItem::isEnabled).collect(Collectors.toList());
    }
// 濉厖闅忔満鍊肩浉鍏冲姩鎬佸彉閲?            requestRaw = fillVariable(requestRaw, "random.ip", randomIP);
            requestRaw = fillVariable(requestRaw, "random.local-ip", randomLocalIP);
            requestRaw = fillVariable(requestRaw, "random.ua", randomUA);
// 濉厖鏃ユ湡銆佹椂闂寸浉鍏崇殑鍔ㄦ€佸彉閲?            requestRaw = fillVariable(requestRaw, "timestamp", timestamp);
            if (requestRaw.contains("{{date.") || requestRaw.contains("{{time.")) {
                String currentDate = DateUtils.getCurrentDate("yyyy-MM-dd HH:mm:ss;yy-M-d H:m:s");
                String[] split = currentDate.split(";");
                String[] leftDateTime = parseDateTime(split[0]);
                requestRaw = fillVariable(requestRaw, "date.yyyy", leftDateTime[0]);
                requestRaw = fillVariable(requestRaw, "date.MM", leftDateTime[1]);
                requestRaw = fillVariable(requestRaw, "date.dd", leftDateTime[2]);
                requestRaw = fillVariable(requestRaw, "time.HH", leftDateTime[3]);
                requestRaw = fillVariable(requestRaw, "time.mm", leftDateTime[4]);
                requestRaw = fillVariable(requestRaw, "time.ss", leftDateTime[5]);
                String[] rightDateTime = parseDateTime(split[1]);
                requestRaw = fillVariable(requestRaw, "date.yy", rightDateTime[0]);
                requestRaw = fillVariable(requestRaw, "date.M", rightDateTime[1]);
                requestRaw = fillVariable(requestRaw, "date.d", rightDateTime[2]);
                requestRaw = fillVariable(requestRaw, "time.H", rightDateTime[3]);
                requestRaw = fillVariable(requestRaw, "time.m", rightDateTime[4]);
                requestRaw = fillVariable(requestRaw, "time.s", rightDateTime[5]);
            }
            return requestRaw;
        } catch (IllegalArgumentException e) {
            Logger.debug(e.getMessage());
            return null;
        }
    }

    /**
     * 妫€娴?QPS 闄愬埗
     *
     * @return true=鎷︽埅锛沠alse=涓嶆嫤鎴?     */
    private boolean checkQPSLimit() {
        if (mQpsLimit != null) {
            try {
                mQpsLimit.limit();
            } catch (InterruptedException e) {
                // 绾跨▼寮哄埗鍋滄鏃讹紝鎷︽埅璇锋眰
                return true;
            }
        }
        return false;
    }
        return src.replace(key, value);
    }

    /**
     * 缁欐暟鎹寘濉厖鍔ㄦ€佸彉閲?     *
     * @param service    璇锋眰鐩爣瀹炰緥
     * @param url        璇锋眰 URL 瀹炰緥
     * @param requestRaw 璇锋眰鏁版嵁鍖呭瓧绗︿覆
     * @return 澶勭悊澶辫触杩斿洖null
     */
    private String setupVariable(IHttpService service, URL url, String requestRaw) {
        String protocol = service.getProtocol();
        String host = service.getHost() + ":" + service.getPort();
        if (service.getPort() == 80 || service.getPort() == 443) {
            host = service.getHost();
        }
        String domain = service.getHost();
        String timestamp = String.valueOf(DateUtils.getTimestamp());
        String randomIP = IPUtils.randomIPv4();
        String randomLocalIP = IPUtils.randomIPv4ForLocal();
        String randomUA = Utils.getRandomItem(WordlistManager.getUserAgent());
        String domainMain = DomainHelper.getDomain(domain, null);
        String domainName = DomainHelper.getDomainName(domain, null);
        String subdomain = getSubdomain(domain);
        String subdomains = getSubdomains(domain);
        String webroot = getWebrootByURL(url);
        // 鏇挎崲鍙橀噺
        try {
            requestRaw = fillVariable(requestRaw, "protocol", protocol);
            requestRaw = fillVariable(requestRaw, "host", host);
            requestRaw = fillVariable(requestRaw, "webroot", webroot);
            // 闇€瑕佸～鍏呭啀鍙栧€?            if (requestRaw.contains("{{ip}}")) {
                String ip = findIpByHost(domain);
                requestRaw = fillVariable(requestRaw, "ip", ip);
            }
        // 濉厖鍩熷悕鐩稿叧鍔ㄦ€佸彉閲?            requestRaw = fillVariable(requestRaw, "domain", domain);
            requestRaw = fillVariable(requestRaw, "domain.main", domainMain);
            requestRaw = fillVariable(requestRaw, "domain.name", domainName);
        // 濉厖瀛愬煙鍚嶇浉鍏冲姩鎬佸彉閲?            requestRaw = fillVariable(requestRaw, "subdomain", subdomain);
            requestRaw = fillVariable(requestRaw, "subdomains", subdomains);
            if (requestRaw.contains("{{subdomains.")) {
                if (StringUtils.isEmpty(subdomains)) {
                    return null;
                }
                String[] subdomainsSplit = subdomains.split("\\.");
                // 閬嶅巻濉厖 {{subdomains.%d}} 鍔ㄦ€佸彉閲?                for (int i = 0; i < subdomainsSplit.length; i++) {
                    requestRaw = fillVariable(requestRaw, "subdomains." + i, subdomainsSplit[i]);
                }
        // 妫€娴嬫槸鍚﹀瓨鍦ㄦ湭濉厖鐨?{{subdomains.%d}} 鍔ㄦ€佸彉閲忥紝濡傛灉瀛樺湪锛屽拷鐣ュ綋鍓?Payload
                if (requestRaw.contains("{{subdomains.")) {
                    return null;
                }
            }

    /**
     * 濉厖鍔ㄦ€佸彉閲?     *
     * @param src   鏁版嵁婧?     * @param name  鍙橀噺鍚?     * @param value 闇€瑕佸～鍏呯殑鍙橀噺鍊?     * @throws IllegalArgumentException 褰撳～鍏呯殑鍙橀噺鍊间负绌烘椂锛屾姏鍑鸿寮傚父
     */
    private String fillVariable(String src, String name, String value) throws IllegalArgumentException {
        if (StringUtils.isEmpty(src)) {
            return src;
        }
        String key = String.format("{{%s}}", name);
        if (!src.contains(key)) {
            return src;
        }
        // 鍊间负绌烘椂锛岃繑鍥瀗ull鍊间涪寮冨綋鍓嶈姹?        if (StringUtils.isEmpty(value)) {
            throw new IllegalArgumentException(key + " fill failed, value is empty.");
        }

    /**
     * 瑙ｆ瀽鏃ユ湡鏃堕棿锛屽皢姣忎釜瀛楁鐨勬暟鎹瓨鍏ユ暟缁?     *
     * @param dateTime 鏃ユ湡鏃堕棿瀛楃涓诧紙鏍煎紡锛歽yyy-MM-dd HH:mm:ss 鎴栬€?yy-M-d H:m:s锛?     * @return [0]=骞达紱[1]=鏈堬紱[2]=鏃ワ紱[3]=鏃讹紱[4]=鍒嗭紱[5]=绉?     */
    private String[] parseDateTime(String dateTime) {
        String[] result = new String[6];
        String[] split = dateTime.split(" ");
        // 鏃ユ湡
        String date = split[0];
        String[] dateSplit = date.split("-");
        result[0] = dateSplit[0];
        result[1] = dateSplit[1];
        result[2] = dateSplit[2];
        // 鏃堕棿
        String time = split[1];
        String[] timeSplit = time.split(":");
        result[3] = timeSplit[0];
        result[4] = timeSplit[1];
        result[5] = timeSplit[2];
        return result;
    }

    /**
     * 鑾峰彇瀛愬煙鍚?     *
     * @param domain 鍩熷悕锛堟牸寮忕ず渚嬶細www.xxx.com锛?     * @return 鏍煎紡锛歸ww锛涘鏋滄病鏈夊瓙鍩熷悕锛屾垨鑰呰幏鍙栧け璐ワ紝杩斿洖null
     */
    private String getSubdomain(String domain) {
        String subdomains = getSubdomains(domain);
        if (StringUtils.isEmpty(subdomains)) {
            return null;
        }
        if (subdomains.contains(".")) {
            return subdomains.substring(0, subdomains.indexOf("."));
        }
        return subdomains;
    }

    /**
     * 鑾峰彇瀹屾暣瀛愬煙鍚?     *
     * @param domain 鍩熷悕锛堟牸寮忕ず渚嬶細api.xxx.com銆乤pi.admin.xxx.com锛?     * @return 鏍煎紡锛歛pi銆乤pi.admin锛涘鏋滄病鏈夊瓙鍩熷悕锛屾垨鑰呰幏鍙栧け璐ワ紝杩斿洖null
     */
    private String getSubdomains(String domain) {
        if (IPUtils.hasIPv4(domain)) {
            return null;
        }
        if (!domain.contains(".")) {
            return null;
        }
        String parseDomain = DomainHelper.getDomain(domain, null);
        if (StringUtils.isEmpty(parseDomain)) {
            return null;
        }
        int endIndex = domain.lastIndexOf(parseDomain) - 1;
        if (endIndex < 0) {
            return null;
        }
        return domain.substring(0, endIndex);
    }

    /**
     * 浠嶶RL瀹炰緥涓幏鍙朩eb鏍圭洰褰曞悕锛堜緥濡傦細"http://xxx.com/abc/a.php" => "abc"锛?     *
     * @param url URL瀹炰緥
     * @return 澶辫触杩斿洖null
     */
    private String getWebrootByURL(URL url) {
        if (url == null) {
            return null;
        }
        String path = url.getPath();
        // 娌℃湁鏍圭洰褰曞悕锛岀洿鎺ヨ繑鍥瀗ull
        if (StringUtils.isEmpty(path) || "/".equals(path)) {
            return null;
        }
        // 鎵剧浜屼釜'/'鏂滄潬
        int end = path.indexOf("/", 1);
        if (end < 0) {
            return null;
        }
        // 鎵惧埌涔嬪悗锛屽彇涓棿鐨勫€?        return path.substring(1, end);
    }

    /**
     * 鏍规嵁 Payload Process 瑙勫垯锛屽鐞嗘暟鎹寘
     *
     * @param service      璇锋眰鐩爣鏈嶅姟
     * @param requestBytes 璇锋眰鏁版嵁鍖?     * @return 澶勭悊鍚庣殑鏁版嵁鍖?     */
    private byte[] handlePayloadProcess(IHttpService service, byte[] requestBytes, List<PayloadItem> list) {
        if (requestBytes == null || requestBytes.length == 0 || list == null || list.isEmpty()) {
            return null;
        }
        IRequestInfo info = mHelpers.analyzeRequest(service, requestBytes);
        int bodyOffset = info.getBodyOffset();
        int bodySize = requestBytes.length - bodyOffset;
        String url = getReqPathByRequestInfo(info);
        String header = new String(requestBytes, 0, bodyOffset - 4);
        String body = bodySize <= 0 ? "" : new String(requestBytes, bodyOffset, bodySize);
        String request = mHelpers.bytesToString(requestBytes);
        for (PayloadItem item : list) {
            // 鍙皟鐢ㄥ惎鐢ㄧ殑瑙勫垯
            PayloadRule rule = item.getRule();
            try {
                switch (item.getScope()) {
                    case PayloadRule.SCOPE_URL:
                        String newUrl = rule.handleProcess(url);
                        // 鎴彇璇锋眰澶寸涓€琛岋紝鐢ㄤ簬瀹氫綅瑕佸鐞嗙殑浣嶇疆
                        String reqLine = header.substring(0, header.indexOf("\r\n"));
                        Matcher matcher = Constants.REGEX_REQ_LINE_URL.matcher(reqLine);
                        if (matcher.find()) {
                            int start = matcher.start(1);
                            int end = matcher.end(1);
                            // 鍒嗛殧瑕佹彃鍏ユ暟鎹殑浣嶇疆
                            String left = header.substring(0, start);
                            String right = header.substring(end);
                            // 鎷兼帴澶勭悊濂界殑鏁版嵁
                            header = left + newUrl + right;
                            request = header + "\r\n\r\n" + body;
                        }
                        url = newUrl;
                        break;
                    case PayloadRule.SCOPE_HEADER:
                        String newHeader = rule.handleProcess(header);
                        header = newHeader;
                        request = newHeader + "\r\n\r\n" + body;
                        break;
                    case PayloadRule.SCOPE_BODY:
                        String newBody = rule.handleProcess(body);
                        request = header + "\r\n\r\n" + newBody;
                        body = newBody;
                        break;
                    case PayloadRule.SCOPE_REQUEST:
                        request = rule.handleProcess(request);
                        break;
                }
            } catch (Exception e) {
                Logger.debug("handlePayloadProcess exception: " + e.getMessage());
                return null;
            }
        }
        // 鍔ㄦ€佸彉閲忚祴鍊?        URL u = getUrlByRequestInfo(info);
        String newRequest = setupVariable(service, u, request);
        if (newRequest == null) {
            return null;
        }
        // 鏇存柊 Content-Length
        return updateContentLength(mHelpers.stringToBytes(newRequest));
    }

    /**
     * 鏇存柊 Content-Length 鍙傛暟鍊?     *
     * @param rawBytes 璇锋眰鏁版嵁鍖?     * @return 鏇存柊鍚庣殑鏁版嵁鍖?     */
    private byte[] updateContentLength(byte[] rawBytes) {
        String temp = new String(rawBytes, StandardCharsets.US_ASCII);
        int bodyOffset = temp.indexOf("\r\n\r\n");
        if (bodyOffset == -1) {
            Logger.error("Handle payload process error: bodyOffset is -1");
            return null;
        }
        bodyOffset += 4;
        int bodySize = rawBytes.length - bodyOffset;
        if (bodySize < 0) {
            Logger.error("Handle payload process error: bodySize < 0");
            return null;
        } else if (bodySize == 0) {
            return rawBytes;
        }
        String header = new String(rawBytes, 0, bodyOffset - 4);
        if (!header.contains("Content-Length")) {
            header += "\r\nContent-Length: " + bodySize;
        } else {
            header = header.replaceAll("Content-Length:.*", "Content-Length: " + bodySize);
        }
        String body = new String(rawBytes, bodyOffset, bodySize);
        String result = header + "\r\n\r\n" + body;
        return result.getBytes(StandardCharsets.UTF_8);
    }
        data.setFrom(from);
        data.setMethod(method);
        data.setHost(reqHost);
        data.setUrl(reqUrl);
        data.setTitle(title);
        data.setIp(ip);
        data.setStatus(status);
        data.setLength(length);
        data.setFingerprint(checkResult);
        data.setReqResp(httpReqResp);
        return data;
    }

    /**
     * 鏋勫缓Item鏁版嵁
     *
     * @param httpReqResp Burp鐨勮姹傚搷搴斿璞?     * @return 鍒楄〃Item鏁版嵁
     */
    private TaskData buildTaskData(IHttpRequestResponse httpReqResp, String from) {
        IRequestInfo info = mHelpers.analyzeRequest(httpReqResp);
        byte[] respBytes = httpReqResp.getResponse();
        // 鑾峰彇鎵€闇€瑕佺殑鍙傛暟
        String method = info.getMethod();
        IHttpService service = httpReqResp.getHttpService();
        String reqHost = getReqHostByHttpService(service);
        String reqUrl = getReqPathByRequestInfo(info);
        String title = HtmlUtils.findTitleByHtmlBody(respBytes);
        String ip = findIpByHost(service.getHost());
        int status = -1;
        int length = -1;
        // 瀛樺湪鍝嶅簲瀵硅薄锛岃幏鍙栫姸鎬佸拰鍝嶅簲鍖呭ぇ灏?        if (respBytes != null && respBytes.length > 0) {
            IResponseInfo response = mHelpers.analyzeResponse(respBytes);
            status = response.getStatusCode();
        // 澶勭悊鍝嶅簲 body 鐨勯暱搴?            length = respBytes.length - response.getBodyOffset();
            if (length < 0) {
                length = 0;
            }
        }

    /**
     * 閫氳繃 IHttpService 瀹炰緥锛岃幏鍙栬姹傜殑 Host 鍦板潃锛坔ttp://x.x.x.x銆乭ttp://x.x.x.x:8080锛?     *
     * @param service IHttpService 瀹炰緥
     * @return 杩斿洖璇锋眰鐨?Host 鍦板潃
     */
    private String getReqHostByHttpService(IHttpService service) {
        String protocol = service.getProtocol();
        String host = service.getHost();
        int port = service.getPort();
        if (Utils.isIgnorePort(port)) {
            return protocol + "://" + host;
        }
        return protocol + "://" + host + ":" + port;
    }

    /**
     * 鏍规嵁 Host 鏌ヨ IP 鍦板潃
     *
     * @param host Host 鍊?     * @return 澶辫触杩斿洖绌哄瓧绗︿覆
     */
    private String findIpByHost(String host) {
        if (IPUtils.hasIPv4(host)) {
            return host;
        }
        try {
            InetAddress ip = InetAddress.getByName(host);
            return ip.getHostAddress();
        } catch (UnknownHostException e) {
            return "";
        }
    }

    /**
     * 鑾峰彇 IRequestInfo 瀹炰緥鐨勮姹?URL 瀹炰緥
     *
     * @param info IRequestInfo 瀹炰緥
     * @return 杩斿洖璇锋眰鐨?URL 瀹炰緥
     */
    private URL getUrlByRequestInfo(IRequestInfo info) {
        URL url = info.getUrl();
        try {
            // 鍒嗕袱绉嶆儏鍐碉紝涓€绉嶆槸瀹屾暣 Host 鍦板潃锛岃繕鏈変竴绉嶆槸鏅€氳姹傝矾寰?            String reqPath = getReqPathByRequestInfo(info);
            if (UrlUtils.isHTTP(reqPath)) {
                return new URL(reqPath);
            }
            // 鏅€氳姹傝矾寰勫洜涓?IRequestInfo.getUrl 鏂规硶鏈夋椂鍊欒幏鍙栫殑鍊间笉鍑嗙‘锛岄噸鏂拌В鏋愪竴涓?            String reqHost = UrlUtils.getReqHostByURL(url);
            return new URL(reqHost + reqPath);
        } catch (Exception e) {
            Logger.error("getUrlByRequestInfo: convert url error: %s", e.getMessage());
            return url;
        }
    }

    @Override
    public void onChangeSelection(TaskData data) {
        // 濡傛灉 data 涓虹┖锛岃〃绀烘墽琛屼簡娓呯┖鍘嗗彶璁板綍鎿嶄綔
        if (data == null) {
            onClearHistory();
            return;
        }
        mCurrentReqResp = (IHttpRequestResponse) data.getReqResp();
        // 鍔犺浇璇锋眰銆佸搷搴旀暟鎹寘
        byte[] hintBytes = mHelpers.stringToBytes(L.get("message_editor_loading"));
        mRequestTextEditor.setMessage(hintBytes, true);
        mResponseTextEditor.setMessage(hintBytes, false);
        mRefreshMsgTask.execute(this::refreshReqRespMessage);
    }

    @Override
    public IHttpService getHttpService() {
        if (mCurrentReqResp != null) {
            return mCurrentReqResp.getHttpService();
        }
        return null;
    }

    @Override
    public byte[] getRequest() {
        if (mCurrentReqResp != null) {
            return mCurrentReqResp.getRequest();
        }
        return new byte[0];
    }

    @Override
    public byte[] getResponse() {
        if (mCurrentReqResp != null) {
            return mCurrentReqResp.getResponse();
        }
        return new byte[0];
    }

    /**
     * 娓呯┖鍘嗗彶璁板綍
     */
    private void onClearHistory() {
        mCurrentReqResp = null;
        // 娓呯┖鍘婚噸杩囨护闆嗗悎
        sRepeatFilter.clear();
        // 娓呯┖瓒呮椂鐨勮姹備富鏈洪泦鍚?        sTimeoutReqHost.clear();
        cancelBrowserRequestDriver();
        clearBrowserRequestTasks();
        // 娓呯┖鏄剧ず鐨勮姹傘€佸搷搴旀暟鎹寘
        mRequestTextEditor.setMessage(EMPTY_BYTES, true);
        mResponseTextEditor.setMessage(EMPTY_BYTES, false);
        // 娓呴櫎鎸囩汗璇嗗埆鍘嗗彶璁板綍
        FpManager.clearHistory();
        closeBrowserRequestDriverAsync();
    }

    /**
     * 鍒锋柊璇锋眰鍝嶅簲淇℃伅
     */
    private void refreshReqRespMessage() {
        byte[] request = getRequest();
        byte[] response = getResponse();
        if (request == null || request.length == 0) {
            request = EMPTY_BYTES;
        }
        if (response == null || response.length == 0) {
            response = EMPTY_BYTES;
        }
        // 妫€娴嬫槸鍚﹁秴杩囬厤缃殑鏄剧ず闀垮害闄愬埗
        int maxLength = Config.getInt(Config.KEY_MAX_DISPLAY_LENGTH);
        if (maxLength >= 100000 && request.length >= maxLength) {
            String hint = L.get("message_editor_request_length_limit_hint");
            request = mHelpers.stringToBytes(hint);
        }
        if (maxLength >= 100000 && response.length >= maxLength) {
            String hint = L.get("message_editor_response_length_limit_hint");
            response = mHelpers.stringToBytes(hint);
        }
        mRequestTextEditor.setMessage(request, true);
        mResponseTextEditor.setMessage(response, false);
    }

    /**
     * 淇敼 QPS 闄愬埗
     *
     * @param limit QPS 闄愬埗鍊硷紙鏁板瓧锛?     */
    private void changeQpsLimit(String limit) {
        initQpsLimiter();
        Logger.debug("Event: change qps limit: %s", limit);
    }

    @Override
    public void onSendToRepeater(ArrayList<TaskData> list) {
        if (list == null || list.isEmpty()) {
            return;
        }
        for (TaskData data : list) {
            if (data.getReqResp() == null) {
                continue;
            }
            byte[] reqBytes = ((IHttpRequestResponse) data.getReqResp()).getRequest();
            String url = data.getHost() + data.getUrl();
            try {
                URL u = new URL(url);
                int port = u.getPort();
                boolean useHttps = "https".equalsIgnoreCase(u.getProtocol());
                if (port == -1) {
                    port = useHttps ? 443 : 80;
                }
                mCallbacks.sendToRepeater(u.getHost(), port, useHttps, reqBytes, null);
            } catch (Exception e) {
                Logger.debug(e.getMessage());
            }
        }
    }

    @Override
    public byte[] getBodyByTaskData(TaskData data) {
        if (data == null || data.getReqResp() == null) {
            return new byte[]{};
        }
        mCurrentReqResp = (IHttpRequestResponse) data.getReqResp();
        byte[] respBytes = mCurrentReqResp.getResponse();
        if (respBytes == null || respBytes.length == 0) {
            return new byte[]{};
        }
        IResponseInfo info = mCallbacks.getHelpers().analyzeResponse(respBytes);
        int offset = info.getBodyOffset();
        return Arrays.copyOfRange(respBytes, offset, respBytes.length);
    }

    @Override
    public void addHostToBlocklist(ArrayList<String> hosts) {
        if (hosts == null || hosts.isEmpty()) {
            return;
        }
        List<String> list = WordlistManager.getList(WordlistManager.KEY_HOST_BLOCKLIST);
        for (String host : hosts) {
            if (!list.contains(host)) {
                list.add(host);
            }
        }
        WordlistManager.putList(WordlistManager.KEY_HOST_BLOCKLIST, list);
        mOneScan.getConfigPanel().refreshHostTab();
    }

    @Override
    public void onTabEventMethod(String action, Object... params) {
        switch (action) {
            case RequestTab.EVENT_QPS_LIMIT:
                changeQpsLimit(String.valueOf(params[0]));
                break;
            case RequestTab.EVENT_REQUEST_DELAY:
                changeRequestDelay(String.valueOf(params[0]));
                break;
            case OtherTab.EVENT_UNLOAD_PLUGIN:
                mCallbacks.unloadExtension();
                break;
            case DataBoardTab.EVENT_IMPORT_URL:
                importUrl((List<?>) params[0]);
                break;
            case DataBoardTab.EVENT_STOP_TASK:
                stopAllTask();
                break;
        }
    }

    /**
     * 淇敼璇锋眰寤惰繜
     *
     * @param delay 寤惰繜鐨勫€硷紙鏁板瓧锛?     */
    private void changeRequestDelay(String delay) {
        initQpsLimiter();
        Logger.debug("Event: change request delay: %s", delay);
    }

    /**
     * 瀵煎叆 URL
     *
     * @param list URL 鍒楄〃
     */
    private void importUrl(List<?> list) {
        if (list == null || list.isEmpty()) {
            return;
        }
        // 澶勭悊瀵煎叆鐨?URL 鏁版嵁
        new Thread(() -> {
            for (Object item : list) {
                try {
                    String url = String.valueOf(item);
                    IHttpRequestResponse httpReqResp = HttpReqRespAdapter.from(url);
                    doScan(httpReqResp, FROM_IMPORT);
                } catch (IllegalArgumentException e) {
                    Logger.error("Import error: " + e.getMessage());
                }
                // 绾跨▼姹犲叧闂悗锛屽仠姝㈠鍏?Url 鏁版嵁
                if (isTaskThreadPoolShutdown() || isTaskStopVersionExpired(taskStopVersion)) {
                    Logger.debug("importUrl: thread pool is shutdown, stop import url");
                    return;
                }
            }
        }).start();
    }

    /**
     * 鍋滄鎵弿涓殑鎵€鏈変换鍔?     */
    private void stopAllTask() {
        mTaskStopVersion.incrementAndGet();
        // 鍏抽棴绾跨▼姹狅紝澶勭悊鏈墽琛岀殑浠诲姟
        List<Runnable> taskList = mTaskThreadPool.shutdownNow();
        List<Runnable> lfTaskList = mLFTaskThreadPool.shutdownNow();
        cancelBrowserRequestDriver();
        handleStopTasks(taskList);
        handleStopTasks(lfTaskList);
        clearBrowserRequestTasks();
        sRepeatFilter.clear();
        sTimeoutReqHost.clear();
        // 鎻愮ず淇℃伅
        UIHelper.showTipsDialog(L.get("stop_task_tips"));
        // 鍋滄鍚庯紝閲嶆柊鍒濆鍖栦换鍔＄嚎绋嬫睜
        mTaskThreadPool = Executors.newFixedThreadPool(TASK_THREAD_COUNT);
        // 鍋滄鍚庯紝閲嶆柊鍒濆鍖栦綆棰戜换鍔＄嚎绋嬫睜
        mLFTaskThreadPool = Executors.newFixedThreadPool(LF_TASK_THREAD_COUNT);
        // 閲嶆柊鍒濆鍖?QPS 闄愬埗鍣?        initQpsLimiter();
        closeBrowserRequestDriverAsync();
    }

    /**
     * 澶勭悊鍋滄鐨勪换鍔″垪琛?     *
     * @param list 浠诲姟鍒楄〃
     */
    private void handleStopTasks(List<Runnable> list) {
        if (list == null || list.isEmpty()) {
            return;
        }
        for (Runnable run : list) {
            if (run instanceof TaskRunnable) {
                TaskRunnable task = (TaskRunnable) run;
                String reqId = task.getReqId();
                String from = task.getFrom();
                // 灏嗘湭鎵ц鐨勪换鍔′粠鍘婚噸杩囨护闆嗗悎涓Щ闄?                sRepeatFilter.remove(reqId);
                // 灏嗘湭鎵ц鐨勪换鍔¤鏁?                if (isLowFrequencyTask(from)) {
                    mLFTaskOverCounter.incrementAndGet();
                } else {
                    mTaskOverCounter.incrementAndGet();
                }
            }
        }

    @Override
    public void extensionUnloaded() {
        // 绉婚櫎浠ｇ悊鐩戝惉鍣?        mCallbacks.removeProxyListener(this);
        // 绉婚櫎鎻掍欢鍗歌浇鐩戝惉鍣?        mCallbacks.removeExtensionStateListener(this);
        // 绉婚櫎淇℃伅杈呭姪闈㈡澘
        mCallbacks.removeMessageEditorTabFactory(this);
        // 绉婚櫎娉ㄥ唽鐨勮彍鍗?        mCallbacks.removeContextMenuFactory(this);
        // 鍋滄鐘舵€佹爮鍒锋柊瀹氭椂鍣?        mStatusRefresh.stop();
        // 鍏抽棴浠诲姟绾跨▼姹?        int count = mTaskThreadPool.shutdownNow().size();
        Logger.info("Close: task thread pool completed. Task %d records.", count);
        // 鍏抽棴浣庨浠诲姟绾跨▼姹?        count = mLFTaskThreadPool.shutdownNow().size();
        Logger.info("Close: low frequency task thread pool completed. Task %d records.", count);
        // 鍏抽棴鎸囩汗璇嗗埆绾跨▼姹?        count = mFpThreadPool.shutdownNow().size();
        Logger.info("Close: fingerprint recognition thread pool completed. Task %d records.", count);
        // 鍏抽棴鏁版嵁鏀堕泦绾跨▼姹?        count = CollectManager.closeThreadPool();
        Logger.info("Close: data collection thread pool completed. Task %d records.", count);
        // 娓呴櫎鏁版嵁鏀堕泦鐨勫幓閲嶈繃婊ら泦鍚?        count = CollectManager.getRepeatFilterCount();
        CollectManager.clearRepeatFilter();
        Logger.info("Clear: data collection repeat filter list completed. Total %d records.", count);
        // 娓呴櫎鎸囩汗璇嗗埆缂撳瓨
        count = FpManager.getCacheCount();
        FpManager.clearCache();
        Logger.info("Clear: fingerprint recognition cache completed. Total %d records.", count);
        // 娓呴櫎鎸囩汗璇嗗埆鍘嗗彶璁板綍
        count = FpManager.getHistoryCount();
        FpManager.clearHistory();
        Logger.info("Clear: fingerprint recognition history completed. Total %d records.", count);
        // 娓呴櫎鎸囩汗瀛楁淇敼鐩戝惉鍣?        FpManager.clearsFpColumnModifyListeners();
        // 娓呴櫎鍘婚噸杩囨护闆嗗悎
        count = sRepeatFilter.size();
        sRepeatFilter.clear();
        Logger.info("Clear: repeat filter list completed. Total %d records.", count);
        // 娓呴櫎瓒呮椂鐨勮姹備富鏈洪泦鍚?        count = sTimeoutReqHost.size();
        sTimeoutReqHost.clear();
        Logger.info("Clear: timeout request host list completed. Total %d records.", count);
        count = clearBrowserRequestTasks();
        Logger.info("Clear: browser request task list completed. Total %d records.", count);
        cancelBrowserRequestDriver();
        closeBrowserRequestDriver();
        mBrowserRequestManager.cleanupSessionWorkspace(Config.getWorkDir());
        mBrowserCloseExecutor.shutdownNow();
        // 娓呴櫎浠诲姟鍒楄〃
        count = 0;
        if (mDataBoardTab != null) {
            TaskTable taskTable = mDataBoardTab.getTaskTable();
            if (taskTable != null) {
                count = taskTable.getTaskCount();
                taskTable.clearAll();
            }
            // 鍏抽棴瀵煎叆 URL 绐楀彛
            mDataBoardTab.closeImportUrlWindow();
        }
        Logger.info("Clear: task list completed. Total %d records.", count);
        // 鍏抽棴鎸囩汗鐩稿叧绐楀彛
        if (mOneScan != null && mOneScan.getFingerprintTab() != null) {
            FingerprintTab tab = mOneScan.getFingerprintTab();
            // 鎸囩汗娴嬭瘯绐楀彛
            tab.closeFpTestWindow();
            // 鎸囩汗瀛楁绠＄悊绐楀彛
            tab.closeFpColumnManagerWindow();
        }
        // 鍗歌浇瀹屾垚
        Logger.info(Constants.UNLOAD_BANNER);
    }
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController iMessageEditorController, boolean editable) {
        return new OneScanInfoTab(mCallbacks, iMessageEditorController);
    }

/**
 * 鎻掍欢鍏ュ彛
 * <p>
 * Created by vaycore on 2022-08-07.
 */
public class BurpExtender implements IBurpExtender, IProxyListener, IMessageEditorController,
        TaskTable.OnTaskTableEventListener, ITab, OnTabEventListener, IMessageEditorTabFactory,
        IExtensionStateListener, IContextMenuFactory {

    /**
     * 浠诲姟绾跨▼鏁伴噺
     */
    private static final int TASK_THREAD_COUNT = 50;

    /**
     * 浣庨浠诲姟绾跨▼鏁伴噺
     */
    private static final int LF_TASK_THREAD_COUNT = 25;

    /**
     * 鎸囩汗璇嗗埆绾跨▼鏁伴噺
     */
    private static final int FP_THREAD_COUNT = 10;

    /**
     * 绌哄瓧鑺傛暟缁勫父閲忥紙闃叉棰戠箒鍒涘缓锛?     */
    private static final byte[] EMPTY_BYTES = new byte[0];

    /**
     * 璇锋眰鏉ユ簮锛氫唬鐞?     */
    private static final String FROM_PROXY = "Proxy";

    /**
     * 莽鈥欌€∶┾€濃€姑撀懊┾偓拧猫驴鈥∶β德徝喢モ劉篓氓聫鈥樏德?     */
    private static final String FROM_BROWSER = "Browser";

    /**
     * 忙碌聫猫搂藛氓鈩⒙访β扁€毭€懊ヂ锯€γ垛€γ︹€斅睹︹€斅睹┾€斅疵妓喢βр€櫭尖€?     */

    /**
     * 忙碌聫猫搂藛氓鈩⒙访β扁€毭趁ヂ∶€懊ヂ锯€γ︹€斅睹┾€斅疵妓喢βр€櫭尖€?     */
    private static final long BROWSER_REQUEST_SETTLE_TIME = 1500L;
    private static final long BROWSER_TRAFFIC_SUPPRESS_TTL = 5000L;
    private static final long BROWSER_PROXY_CACHE_TTL = 30000L;

    /**
     * 璇锋眰鏉ユ簮锛氬彂閫佸埌 OneScan 鎵弿
     */
    private static final String FROM_SEND = "Send";

    /**
     * 璇锋眰鏉ユ簮锛歅ayload Processing
     */
    private static final String FROM_PROCESS = "Process";

    /**
     * 璇锋眰鏉ユ簮锛氬鍏?     */
    private static final String FROM_IMPORT = "Import";

    /**
     * 璇锋眰鏉ユ簮锛氭壂鎻?     */
    private static final String FROM_SCAN = "Scan";

    /**
     * 璇锋眰鏉ユ簮锛氶噸瀹氬悜
     */
    private static final String FROM_REDIRECT = "Redirect";

    /**
     * 鍘婚噸杩囨护闆嗗悎
     */
    private final Set<String> sRepeatFilter = ConcurrentHashMap.newKeySet(500000);

    /**
     * 瓒呮椂鐨勮姹備富鏈洪泦鍚?     */
    private final Set<String> sTimeoutReqHost = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<String, BrowserRequestTask> mBrowserRequestTasks = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> mBrowserExpectedRequests = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, BrowserResponseCacheEntry> mBrowserResponseCache = new ConcurrentHashMap<>();
    private final Object mBrowserRequestLock = new Object();
    private final BrowserRequestManager mBrowserRequestManager = new BrowserRequestManager();
    private final ExecutorService mBrowserCloseExecutor = Executors.newSingleThreadExecutor();

    private IBurpExtenderCallbacks mCallbacks;
    private IExtensionHelpers mHelpers;
    private OneScan mOneScan;
    private DataBoardTab mDataBoardTab;
    private IMessageEditor mRequestTextEditor;
    private IMessageEditor mResponseTextEditor;
    private ExecutorService mTaskThreadPool;
    private ExecutorService mLFTaskThreadPool;
    private ExecutorService mFpThreadPool;
    private ExecutorService mRefreshMsgTask;
    private IHttpRequestResponse mCurrentReqResp;
    private QpsLimiter mQpsLimit;
    private final AtomicInteger mTaskOverCounter = new AtomicInteger(0);
    private final AtomicInteger mTaskCommitCounter = new AtomicInteger(0);
    private final AtomicInteger mLFTaskOverCounter = new AtomicInteger(0);
    private final AtomicInteger mLFTaskCommitCounter = new AtomicInteger(0);
    private final AtomicInteger mTaskStopVersion = new AtomicInteger(0);
    private volatile BrowserTrafficScope mBrowserTrafficScope;
    private Timer mStatusRefresh;

    private static class BrowserRequestTask {
        private final IHttpService service;
        private final byte[] requestBytes;
        private final CountDownLatch responseLatch = new CountDownLatch(1);
        private volatile IHttpRequestResponse lastReqResp;
        private volatile long lastUpdateTime;

        private BrowserRequestTask(IHttpService service, byte[] requestBytes) {
            this.service = service;
            this.requestBytes = requestBytes;
        }

        private void update(IHttpRequestResponse reqResp) {
            this.lastReqResp = reqResp;
            this.lastUpdateTime = System.currentTimeMillis();
            responseLatch.countDown();
        }

        private IHttpRequestResponse awaitResponse(long timeoutMillis, long settleMillis) throws InterruptedException {
            long startTime = System.currentTimeMillis();
            boolean matched = responseLatch.await(timeoutMillis, TimeUnit.MILLISECONDS);
            if (!matched) {
                return null;
            }
            long deadline = startTime + timeoutMillis;
            while (System.currentTimeMillis() < deadline) {
                long idleTime = System.currentTimeMillis() - lastUpdateTime;
                if (idleTime >= settleMillis) {
                    return lastReqResp;
                }
                Thread.sleep(Math.min(200L, settleMillis));
            }
            return lastReqResp;
        }

        private IHttpRequestResponse createFallback() {
            IHttpRequestResponse reqResp = HttpReqRespAdapter.from(service, requestBytes);
            reqResp.setComment(FROM_BROWSER);
            return reqResp;
        }
    }

    private static class BrowserTrafficScope {
        private final String targetUrl;
        private final String targetOrigin;
        private final String targetHost;
        private volatile long expireAt;

        private BrowserTrafficScope(String targetUrl, long ttlMillis) throws MalformedURLException {
            this.targetUrl = targetUrl;
            URL url = new URL(targetUrl);
            this.targetHost = url.getHost();
            this.targetOrigin = url.getProtocol() + "://" + url.getHost() + buildPortSuffix(url);
            this.expireAt = System.currentTimeMillis() + ttlMillis;
        }

        private boolean isExpired() {
            return System.currentTimeMillis() > expireAt;
        }

        private void extend(long ttlMillis) {
            expireAt = Math.max(expireAt, System.currentTimeMillis() + ttlMillis);
        }

        private boolean isSameTargetUrl(String url) {
            return targetUrl.equals(url);
        }

        private boolean matchesReferer(String referer) {
            return referer != null && (targetUrl.equals(referer) || referer.startsWith(targetOrigin));
        }

        private boolean isSameHost(URL url) {
            return url != null && targetHost.equalsIgnoreCase(url.getHost());
        }

        private static String buildPortSuffix(URL url) {
            int port = url.getPort();
            if (port < 0 || port == url.getDefaultPort()) {
                return "";
            }
            return ":" + port;
        }
    }

    private static class BrowserResponseCacheEntry {
        private final IHttpRequestResponse reqResp;
        private final long expireAt;

        private BrowserResponseCacheEntry(IHttpRequestResponse reqResp, long ttlMillis) {
            this.reqResp = reqResp;
            this.expireAt = System.currentTimeMillis() + ttlMillis;
        }

        private boolean isExpired() {
            return System.currentTimeMillis() > expireAt;
        }
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        initData(callbacks);
        initView();
        initEvent();
        Logger.debug("register Extender ok! Log: %b", Constants.DEBUG);
    }

    private void initData(IBurpExtenderCallbacks callbacks) {
        this.mCallbacks = callbacks;
        this.mHelpers = callbacks.getHelpers();
        this.mTaskThreadPool = Executors.newFixedThreadPool(TASK_THREAD_COUNT);
        this.mLFTaskThreadPool = Executors.newFixedThreadPool(LF_TASK_THREAD_COUNT);
        this.mFpThreadPool = Executors.newFixedThreadPool(FP_THREAD_COUNT);
        this.mRefreshMsgTask = Executors.newSingleThreadExecutor();
        this.mCallbacks.setExtensionName(Constants.PLUGIN_NAME + " v" + Constants.PLUGIN_VERSION);
        // 鍒濆鍖栨棩蹇楁墦鍗?        Logger.init(Constants.DEBUG, mCallbacks.getStdout(), mCallbacks.getStderr());
        // 鍒濆鍖栭粯璁ら厤缃?        Config.init(getWorkDir());
        // 鍒濆鍖栧煙鍚嶈緟鍔╃被
        DomainHelper.init("public_suffix_list.json");
        // 鍒濆鍖朡PS闄愬埗鍣?        initQpsLimiter();
        // 娉ㄥ唽 OneScan 淇℃伅杈呭姪闈㈡澘
        this.mCallbacks.registerMessageEditorTabFactory(this);
        // 娉ㄥ唽鎻掍欢鍗歌浇鐩戝惉鍣?        this.mCallbacks.registerExtensionStateListener(this);
    }

    /**
     * 鑾峰彇宸ヤ綔鐩綍璺緞锛堜紭鍏堣幏鍙栧綋鍓嶆彃浠?jar 鍖呮墍鍦ㄧ洰褰曢厤缃枃浠讹紝濡傛灉閰嶇疆涓嶅瓨鍦紝鍒欎娇鐢ㄩ粯璁ゅ伐浣滅洰褰曪級
     */
    private String getWorkDir() {
        String workDir = Paths.get(mCallbacks.getExtensionFilename())
                .getParent().toString() + File.separator + "OneScan" + File.separator;
        if (FileUtils.isDir(workDir)) {
            return workDir;
        }
        return null;
    }

    /**
     * 鍒濆鍖?QPS 闄愬埗鍣?     */
    private void initQpsLimiter() {
        // 妫€娴嬭寖鍥达紝濡傛灉涓嶇鍚堟潯浠讹紝涓嶅垱寤洪檺鍒跺櫒
        int limit = Config.getInt(Config.KEY_QPS_LIMIT);
        int delay = Config.getInt(Config.KEY_REQUEST_DELAY);
        if (limit > 0 && limit <= 9999) {
            this.mQpsLimit = new QpsLimiter(limit, delay);
        }
    }

    private void initView() {
        mOneScan = new OneScan();
        mDataBoardTab = mOneScan.getDataBoardTab();
        // 娉ㄥ唽浜嬩欢
        mDataBoardTab.setOnTabEventListener(this);
        mOneScan.getConfigPanel().setOnTabEventListener(this);
        // 灏嗛〉闈㈡坊鍔犲埌 BurpSuite
        mCallbacks.addSuiteTab(this);
        // 鍒涘缓璇锋眰鍜屽搷搴旀帶浠?        mRequestTextEditor = mCallbacks.createMessageEditor(this, false);
        mResponseTextEditor = mCallbacks.createMessageEditor(this, false);
        mDataBoardTab.init(mRequestTextEditor.getComponent(), mResponseTextEditor.getComponent());
        mDataBoardTab.getTaskTable().setOnTaskTableEventListener(this);
    }

    private void initEvent() {
        // 鐩戝惉浠ｇ悊鐨勫寘
        mCallbacks.registerProxyListener(this);
        // 娉ㄥ唽鑿滃崟
        mCallbacks.registerContextMenuFactory(this);
        // 鐘舵€佹爮鍒锋柊瀹氭椂鍣?        mStatusRefresh = new Timer(1000, e -> {
            if (mDataBoardTab == null) {
                return;
            }
            mDataBoardTab.refreshTaskStatus(mTaskOverCounter.get(), mTaskCommitCounter.get());
            mDataBoardTab.refreshLFTaskStatus(mLFTaskOverCounter.get(), mLFTaskCommitCounter.get());
            mDataBoardTab.refreshTaskHistoryStatus();
            mDataBoardTab.refreshFpCacheStatus();
        });
        mStatusRefresh.start();
    }
}


