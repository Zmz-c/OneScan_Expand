package burp;

import burp.vaycore.common.helper.DomainHelper;
import burp.vaycore.common.helper.QpsLimiter;
import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.*;
import burp.vaycore.ost.Ost;
import burp.vaycore.ost.bean.CollectNode;
import burp.vaycore.ost.bean.FpData;
import burp.vaycore.ost.bean.TaskData;
import burp.vaycore.ost.browser.BrowserRequest;
import burp.vaycore.ost.browser.BrowserRequestManager;
import burp.vaycore.ost.common.*;
import burp.vaycore.ost.info.OstInfoTab;
import burp.vaycore.ost.manager.CollectManager;
import burp.vaycore.ost.manager.FpManager;
import burp.vaycore.ost.manager.TaskPersistenceManager;
import burp.vaycore.ost.manager.WordlistManager;
import burp.vaycore.ost.mcp.OstMcpServer;
import burp.vaycore.ost.mcp.OstMcpTool;
import burp.vaycore.ost.mcp.OstMcpToolProvider;
import burp.vaycore.ost.ui.tab.DataBoardTab;
import burp.vaycore.ost.ui.tab.FingerprintTab;
import burp.vaycore.ost.ui.tab.config.OtherTab;
import burp.vaycore.ost.ui.tab.config.RequestTab;
import burp.vaycore.ost.ui.widget.TaskTable;
import burp.vaycore.ost.ui.widget.payloadlist.PayloadItem;
import burp.vaycore.ost.ui.widget.payloadlist.PayloadRule;
import burp.vaycore.ost.ui.widget.payloadlist.ProcessingItem;

import javax.swing.*;
import javax.swing.Timer;
import java.awt.*;
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
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

/**
 * 插件入口
 * <p>
 * Created by vaycore on 2022-08-07.
 */
public class BurpExtender implements IBurpExtender, IProxyListener, IMessageEditorController,
        TaskTable.OnTaskTableEventListener, ITab, OnTabEventListener, IMessageEditorTabFactory,
        IExtensionStateListener, IContextMenuFactory, OstMcpToolProvider {

    /**
     * 任务线程数量
     */
    private static final int TASK_THREAD_COUNT = 50;

    /**
     * 低频任务线程数量
     */
    private static final int LF_TASK_THREAD_COUNT = 25;

    /**
     * 指纹识别线程数量
     */
    private static final int FP_THREAD_COUNT = 10;

    /**
     * 空字节数组常量（防止频繁创建）
     */
    private static final byte[] EMPTY_BYTES = new byte[0];

    /**
     * 请求来源：代理
     */
    private static final String FROM_PROXY = "Proxy";

    /**
     * 请求来源：浏览器请求
     */
    private static final String FROM_BROWSER = "Browser";

    /**
     * 浏览器请求稳定等待时间（毫秒）
     */
    private static final long BROWSER_REQUEST_SETTLE_TIME = 1500L;
    private static final long BROWSER_TRAFFIC_SUPPRESS_TTL = 5000L;
    private static final long BROWSER_PROXY_CACHE_TTL = 30000L;

    /**
     * 请求来源：发送到 OST 扫描
     */
    private static final String FROM_SEND = "Send";

    /**
     * 请求来源：右键菜单发送到 OST 扫描（Burp 请求）
     */
    private static final String FROM_SEND_BURP = "Send (Burp)";

    /**
     * 请求来源：右键菜单发送到 OST 扫描（浏览器请求）
     */
    private static final String FROM_SEND_BROWSER = "Send (Browser)";

    /**
     * 请求来源：Payload Processing
     */
    private static final String FROM_PROCESS = "Process";

    /**
     * 请求来源：导入
     */
    private static final String FROM_IMPORT = "Import";

    /**
     * 请求来源：扫描
     */
    private static final String FROM_SCAN = "Scan";

    /**
     * 请求来源：重定向
     */
    private static final String FROM_REDIRECT = "Redirect";

    /**
     * 去重过滤集合
     */
    private final Set<String> sRepeatFilter = ConcurrentHashMap.newKeySet(500000);

    /**
     * 超时的请求主机集合
     */
    private final Set<String> sTimeoutReqHost = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<String, BrowserRequestTask> mBrowserRequestTasks = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> mBrowserExpectedRequests = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, BrowserResponseCacheEntry> mBrowserResponseCache = new ConcurrentHashMap<>();
    private final Object mBrowserRequestLock = new Object();
    private final Object mRequestPauseLock = new Object();
    private final EnumSet<RequestMode> mPausedRequestModes = EnumSet.noneOf(RequestMode.class);
    private final BrowserRequestManager mBrowserRequestManager = new BrowserRequestManager();
    private final ConcurrentHashMap<String, BrowserFallbackStats> mBrowserFallbackStats = new ConcurrentHashMap<>();
    private final ExecutorService mBrowserCloseExecutor = Executors.newSingleThreadExecutor();
    private final AtomicInteger mTaskOverCounter = new AtomicInteger(0);
    private final AtomicInteger mTaskCommitCounter = new AtomicInteger(0);
    private final AtomicInteger mLFTaskOverCounter = new AtomicInteger(0);
    private final AtomicInteger mLFTaskCommitCounter = new AtomicInteger(0);
    private final AtomicLong mTaskGeneration = new AtomicLong(0);
    private final ThreadLocal<Long> mTaskGenerationContext = new ThreadLocal<Long>();
    private IBurpExtenderCallbacks mCallbacks;
    private IExtensionHelpers mHelpers;
    private Ost mOst;
    private DataBoardTab mDataBoardTab;
    private IMessageEditor mRequestTextEditor;
    private IMessageEditor mResponseTextEditor;
    private ExecutorService mTaskThreadPool;
    private ExecutorService mLFTaskThreadPool;
    private ExecutorService mBrowserTaskThreadPool;
    private ExecutorService mFpThreadPool;
    private ExecutorService mRefreshMsgTask;
    private IHttpRequestResponse mCurrentReqResp;
    private QpsLimiter mQpsLimit;
    private volatile BrowserTrafficScope mBrowserTrafficScope;
    private Timer mStatusRefresh;
    private OstMcpServer mMcpServer;

    /**
     * 检测 Host 是否匹配规则
     *
     * @param host Host（不包含协议、端口号）
     * @param rule 规则
     * @return true=匹配；false=不匹配
     */
    private static boolean matchHost(String host, String rule) {
        if (StringUtils.isEmpty(host)) {
            return StringUtils.isEmpty(rule);
        }
        // 规则就是*号，直接返回true
        if (rule.equals("*")) {
            return true;
        }
        // 不包含*号，检测 Host 与规则是否相等
        if (!rule.contains("*")) {
            return host.equals(rule);
        }
        // 根据*号位置，进行匹配
        String ruleValue = rule.replace("*", "");
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
     * 通过 IHttpService 实例，获取请求的 Host 值（示例格式：x.x.x.x、x.x.x.x:8080）
     *
     * @return 失败返回null
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

    /**
     * 通过 URL 实例，构建 IHttpService 实例
     *
     * @return 失败返回null
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

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        initData(callbacks);
        initView();
        initEvent();
        refreshMcpServer();
        Logger.debug("register Extender ok! Log: %b", Constants.DEBUG);
    }

    private void initData(IBurpExtenderCallbacks callbacks) {
        this.mCallbacks = callbacks;
        this.mHelpers = callbacks.getHelpers();
        this.mTaskThreadPool = Executors.newFixedThreadPool(TASK_THREAD_COUNT);
        this.mLFTaskThreadPool = Executors.newFixedThreadPool(LF_TASK_THREAD_COUNT);
        this.mBrowserTaskThreadPool = Executors.newSingleThreadExecutor();
        this.mFpThreadPool = Executors.newFixedThreadPool(FP_THREAD_COUNT);
        this.mRefreshMsgTask = Executors.newSingleThreadExecutor();
        this.mCallbacks.setExtensionName(Constants.PLUGIN_NAME + " v" + Constants.PLUGIN_VERSION);
        // 初始化日志打印
        Logger.init(Constants.DEBUG, mCallbacks.getStdout(), mCallbacks.getStderr());
        // 初始化默认配置
        Config.init(getWorkDir());
        // 初始化域名辅助类
        DomainHelper.init("public_suffix_list.json");
        // 初始化QPS限制器
        initQpsLimiter();
        // 注册 OST 信息辅助面板
        this.mCallbacks.registerMessageEditorTabFactory(this);
        // 注册插件卸载监听器
        this.mCallbacks.registerExtensionStateListener(this);
    }

    /**
     * 获取工作目录路径（优先获取当前插件 jar 包所在目录配置文件，如果配置不存在，则使用默认工作目录）
     */
    private String getWorkDir() {
        String workDir = Paths.get(mCallbacks.getExtensionFilename())
                .getParent().toString() + File.separator + "OST" + File.separator;
        if (FileUtils.isDir(workDir)) {
            return workDir;
        }
        return null;
    }

    /**
     * 初始化 QPS 限制器
     */
    private void initQpsLimiter() {
        // 检测范围，如果不符合条件，不创建限制器
        int limit = Config.getInt(Config.KEY_QPS_LIMIT);
        int delay = Config.getInt(Config.KEY_REQUEST_DELAY);
        if (limit > 0 && limit <= 9999) {
            this.mQpsLimit = new QpsLimiter(limit, delay);
        }
    }

    private long captureTaskGeneration() {
        return mTaskGeneration.get();
    }

    private long resolveTaskGeneration() {
        Long taskGeneration = mTaskGenerationContext.get();
        return taskGeneration == null ? mTaskGeneration.get() : taskGeneration;
    }

    private void runWithTaskGeneration(long taskGeneration, Runnable runnable) {
        mTaskGenerationContext.set(taskGeneration);
        try {
            runnable.run();
        } finally {
            mTaskGenerationContext.remove();
        }
    }

    private boolean isTaskStopRequested() {
        return isTaskStopRequested(resolveTaskGeneration());
    }

    private boolean isTaskStopRequested(long taskGeneration) {
        return taskGeneration != mTaskGeneration.get()
                || Thread.currentThread().isInterrupted()
                || isTaskThreadPoolShutdown();
    }

    private RequestMode normalizeTaskMode(RequestMode requestMode) {
        return requestMode == RequestMode.BROWSER ? RequestMode.BROWSER : RequestMode.BURP;
    }

    private void waitForRequestMode(RequestMode requestMode) throws InterruptedException {
        RequestMode taskMode = normalizeTaskMode(requestMode);
        synchronized (mRequestPauseLock) {
            while (mPausedRequestModes.contains(taskMode)) {
                mRequestPauseLock.wait();
            }
        }
    }

    private void initView() {
        mOst = new Ost();
        mDataBoardTab = mOst.getDataBoardTab();
        // 注册事件
        mDataBoardTab.setOnTabEventListener(this);
        mOst.getConfigPanel().setOnTabEventListener(this);
        // 将页面添加到 BurpSuite
        mCallbacks.addSuiteTab(this);
        // 创建请求和响应控件
        mRequestTextEditor = mCallbacks.createMessageEditor(this, false);
        mResponseTextEditor = mCallbacks.createMessageEditor(this, false);
        mDataBoardTab.init(mRequestTextEditor.getComponent(), mResponseTextEditor.getComponent());
        if (mDataBoardTab.getBurpTaskTable() != null) {
            mDataBoardTab.getBurpTaskTable().setOnTaskTableEventListener(this);
        }
        if (mDataBoardTab.getBrowserTaskTable() != null) {
            mDataBoardTab.getBrowserTaskTable().setOnTaskTableEventListener(this);
        }
    }

    private void initEvent() {
        // 监听代理的包
        mCallbacks.registerProxyListener(this);
        // 注册菜单
        mCallbacks.registerContextMenuFactory(this);
        // 状态栏刷新定时器
        mStatusRefresh = new Timer(1000, e -> {
            if (mDataBoardTab == null) {
                return;
            }
            mDataBoardTab.refreshTaskStatus(mTaskOverCounter.get(), mTaskCommitCounter.get());
            mDataBoardTab.refreshLFTaskStatus(mLFTaskOverCounter.get(), mLFTaskCommitCounter.get());
            mDataBoardTab.refreshTaskHistoryStatus();
            mDataBoardTab.refreshFpCacheStatus();
        });
        mStatusRefresh.start();
        mDataBoardTab.refreshAutoSaveTimer();
    }

    private void initMcpServer() {
        if (mMcpServer != null) {
            return;
        }
        try {
            mMcpServer = new OstMcpServer(this);
            mMcpServer.start();
            Logger.info("OST MCP server listening on %s", mMcpServer.getEndpoint());
            refreshMcpServerInfoPanel();
        } catch (Exception e) {
            Logger.error("OST MCP server start failed: %s", e.getMessage());
            mMcpServer = null;
            refreshMcpServerInfoPanel();
        }
    }

    private void refreshMcpServer() {
        if (Config.getBoolean(Config.KEY_ENABLE_MCP)) {
            initMcpServer();
        } else {
            stopMcpServer();
        }
        refreshMcpServerInfoPanel();
    }

    private void stopMcpServer() {
        if (mMcpServer == null) {
            return;
        }
        mMcpServer.stop();
        mMcpServer = null;
        Logger.info("OST MCP server stopped");
        refreshMcpServerInfoPanel();
    }

    private void refreshMcpServerInfoPanel() {
        if (mOst == null || mOst.getConfigPanel() == null) {
            return;
        }
        boolean running = mMcpServer != null;
        String endpoint = running ? mMcpServer.getEndpoint() : "";
        SwingUtilities.invokeLater(() -> mOst.getConfigPanel().refreshMcpServerInfo(running, endpoint));
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        ArrayList<JMenuItem> items = new ArrayList<>();
        // 扫描选定目标
        JMenu sendToOSTMenu = new JMenu(L.get("send_to_plugin"));
        items.add(sendToOSTMenu);
        addSendToOSTMenuItem(sendToOSTMenu, invocation, L.get("send_to_plugin_burp"), RequestMode.BURP,
                FROM_SEND_BURP);
        addSendToOSTMenuItem(sendToOSTMenu, invocation, L.get("send_to_plugin_browser"),
                RequestMode.BROWSER, FROM_SEND_BROWSER);
        // 选择 Payload 扫描
        List<String> payloadList = WordlistManager.getItemList(WordlistManager.KEY_PAYLOAD);
        if (!payloadList.isEmpty() && payloadList.size() > 1) {
            JMenu menu = new JMenu(L.get("use_payload_scan"));
            items.add(menu);
            for (String itemName : payloadList) {
                JMenu payloadMenu = new JMenu(itemName);
                menu.add(payloadMenu);
                addPayloadScanMenuItem(payloadMenu, invocation, L.get("send_to_plugin_burp"), itemName,
                        RequestMode.BURP, FROM_SEND_BURP);
                addPayloadScanMenuItem(payloadMenu, invocation, L.get("send_to_plugin_browser"), itemName,
                        RequestMode.BROWSER, FROM_SEND_BROWSER);
            }
        }
        return items;
    }

    private void addSendToOSTMenuItem(JMenu menu, IContextMenuInvocation invocation, String name,
                                          RequestMode requestMode, String from) {
        JMenuItem item = new JMenuItem(name);
        menu.add(item);
        item.addActionListener((event) -> {
            final long taskGeneration = captureTaskGeneration();
            new Thread(() -> runWithTaskGeneration(taskGeneration, () -> {
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                for (IHttpRequestResponse httpReqResp : messages) {
                    doScan(httpReqResp, from, requestMode);
                    if (isTaskStopRequested(taskGeneration)) {
                        Logger.debug("sendToPlugin: task stop requested, stop sending scan task");
                        return;
                    }
                }
            })).start();
        });
    }

    private void addPayloadScanMenuItem(JMenu menu, IContextMenuInvocation invocation, String name, String payloadItem,
                                        RequestMode requestMode, String from) {
        JMenuItem item = new JMenuItem(name);
        menu.add(item);
        item.addActionListener((event) -> {
            final long taskGeneration = captureTaskGeneration();
            new Thread(() -> runWithTaskGeneration(taskGeneration, () -> {
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                for (IHttpRequestResponse httpReqResp : messages) {
                    doScan(httpReqResp, from, payloadItem, requestMode);
                    // 线程池关闭后，停止发送扫描任务
                    if (isTaskStopRequested(taskGeneration)) {
                        Logger.debug("usePayloadScan: task stop requested, stop sending scan task");
                        return;
                    }
                }
            })).start();
        });
    }

    @Override
    public String getTabCaption() {
        return Constants.PLUGIN_NAME;
    }

    @Override
    public Component getUiComponent() {
        return mOst;
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        // 当请求和响应都有的时候，才进行下一步操作
        if (messageIsRequest) {
            return;
        }
        // 检测开关状态
        if (!mDataBoardTab.hasListenProxyMessage()) {
            return;
        }
        IHttpRequestResponse httpReqResp = message.getMessageInfo();
        if (handleBrowserProxyResponse(httpReqResp)) {
            return;
        }
        // 扫描任务
        doScan(httpReqResp, FROM_PROXY);
    }

    private void doScan(IHttpRequestResponse httpReqResp, String from) {
        String item = WordlistManager.getItem(WordlistManager.KEY_PAYLOAD);
        doScan(httpReqResp, from, item, RequestMode.AUTO);
    }

    private void doScan(IHttpRequestResponse httpReqResp, String from, RequestMode requestMode) {
        String item = WordlistManager.getItem(WordlistManager.KEY_PAYLOAD);
        doScan(httpReqResp, from, item, requestMode);
    }

    private void doScan(IHttpRequestResponse httpReqResp, String from, String payloadItem) {
        doScan(httpReqResp, from, payloadItem, RequestMode.AUTO);
    }

    private void doScan(IHttpRequestResponse httpReqResp, String from, String payloadItem, RequestMode requestMode) {
        if (httpReqResp == null || httpReqResp.getHttpService() == null) {
            return;
        }
        if (isTaskStopRequested()) {
            Logger.debug("doScan: task stop requested, intercept source: %s", from);
            return;
        }
        IRequestInfo info = mHelpers.analyzeRequest(httpReqResp);
        String host = httpReqResp.getHttpService().getHost();
        byte[] request = httpReqResp.getRequest();
        byte[] response = httpReqResp.getResponse();
        // 对来自代理的包进行检测，检测请求方法是否需要拦截
        if (from.equals(FROM_PROXY)) {
            String method = info.getMethod();
            if (includeMethodFilter(method)) {
                // 拦截不匹配的请求方法
                Logger.debug("doScan filter request method: %s, host: %s", method, host);
                return;
            }
            // 检测 Host 是否在白名单、黑名单中
            if (hostAllowlistFilter(host) || hostBlocklistFilter(host)) {
                Logger.debug("doScan allowlist and blocklist filter host: %s", host);
                return;
            }
            // 收集数据（只收集代理流量的数据）
            CollectManager.collect(true, host, request);
            CollectManager.collect(false, host, response);
        }
        // 如果启用，对来自重定向的包进行检测
        if (from.startsWith(FROM_REDIRECT) && Config.getBoolean(Config.KEY_REDIRECT_TARGET_HOST_LIMIT)) {
            // 检测 Host 是否在白名单、黑名单中
            if (hostAllowlistFilter(host) || hostBlocklistFilter(host)) {
                Logger.debug("doScan allowlist and blocklist filter host: %s", host);
                return;
            }
        }
        // 开启线程识别指纹，将识别结果缓存起来
        if (!mFpThreadPool.isShutdown()) {
            mFpThreadPool.execute(() -> FpManager.check(request, response));
        }
        // 准备生成任务
        URL url = getUrlByRequestInfo(info);
        // 原始请求也需要经过 Payload Process 处理（不过需要过滤一些后缀的流量）
        if (!proxyExcludeSuffixFilter(url.getPath())) {
            runScanTask(httpReqResp, info, null, from, requestMode);
        } else {
            Logger.debug("proxyExcludeSuffixFilter filter request path: %s", url.getPath());
        }
        // 检测是否禁用递归扫描
        if (!mDataBoardTab.hasDirScan()) {
            return;
        }
        // 获取一下请求数据包中的请求路径
        String reqPath = getReqPathByRequestInfo(info);
        // 从请求路径中，尝试获取请求主机地址
        String reqHost = getReqHostByReqPath(reqPath);
        Logger.debug("doScan receive: %s", url.toString());
        ArrayList<String> pathDict = getUrlPathDict(url.getPath());
        List<String> payloads = WordlistManager.getPayload(payloadItem);
        // 一级目录一级目录递减访问
        for (int i = pathDict.size() - 1; i >= 0; i--) {
            if (isTaskStopRequested()) {
                Logger.debug("doScan: task stop requested while generating scan task");
                return;
            }
            String path = pathDict.get(i);
            // 去除结尾的 '/' 符号
            if (path.endsWith("/")) {
                path = path.substring(0, path.length() - 1);
            }
            // 拼接字典，发起请求
            for (String item : payloads) {
                // 线程池关闭后，停止继续生成任务
                if (isTaskStopRequested()) {
                    return;
                }
                // 对完整 Host 地址的字典取消递归扫描（直接替换请求路径扫描）
                if (StringUtils.isNotEmpty(path) && UrlUtils.isHTTP(item)) {
                    continue;
                }
                String urlPath = path + item;
                // 如果配置的字典不含 '/' 前缀，在根目录下扫描时，自动添加 '/' 符号
                if (StringUtils.isEmpty(path) && !item.startsWith("/") && !UrlUtils.isHTTP(item)) {
                    urlPath = "/" + item;
                }
                // 检测一下是否携带完整的 Host 地址（兼容一下携带了完整的 Host 地址的情况）
                // 但有个前提：如果字典存在完整的 Host 地址，直接不做处理
                if (UrlUtils.isHTTP(reqPath) && !UrlUtils.isHTTP(item)) {
                    urlPath = reqHost + urlPath;
                }
                runScanTask(httpReqResp, info, urlPath, FROM_SCAN, requestMode);
            }
        }
    }

    /**
     * 从 IRequestInfo 实例中读取请求行中的请求路径
     *
     * @param info IRequestInfo 实例
     * @return 不存在返回空字符串
     */
    private String getReqPathByRequestInfo(IRequestInfo info) {
        if (info == null) {
            return "";
        }
        // 获取请求行
        List<String> headers = info.getHeaders();
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
     * 从请求路径中（有些站点请求路径中包含完整的 Host 地址）获取请求的 Host 地址
     *
     * @param reqPath 请求路径
     * @return 不包含 Host 地址，返回空字符串
     */
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

    /**
     * 过滤请求方法
     *
     * @param method 请求方法
     * @return true=拦截；false=不拦截
     */
    private boolean includeMethodFilter(String method) {
        String includeMethod = Config.get(Config.KEY_INCLUDE_METHOD);
        // 如果配置为空，不拦截任何请求方法
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

    /**
     * Host 白名单过滤
     *
     * @param host Host
     * @return true=拦截；false=不拦截
     */
    private boolean hostAllowlistFilter(String host) {
        List<String> list = WordlistManager.getHostAllowlist();
        // 白名单为空，不启用白名单
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
     * Host 黑名单过滤
     *
     * @param host Host
     * @return true=拦截；false=不拦截
     */
    private boolean hostBlocklistFilter(String host) {
        List<String> list = WordlistManager.getHostBlocklist();
        // 黑名单为空，不启用黑名单
        if (list.isEmpty()) {
            return false;
        }
        for (String item : list) {
            if (matchHost(host, item)) {
                Logger.debug("hostBlocklistFilter filter host: %s （rule: %s）", host, item);
                return true;
            }
        }
        return false;
    }

    /**
     * 代理请求的后缀过滤
     *
     * @param reqPath 请求路径（不包含 Query 参数）
     * @return true=拦截；false=不拦截
     */
    private boolean proxyExcludeSuffixFilter(String reqPath) {
        if (StringUtils.isEmpty(reqPath) || "/".equals(reqPath)) {
            return false;
        }
        // 统一转换为小写
        String suffix = Config.get(Config.KEY_EXCLUDE_SUFFIX).toLowerCase();
        String path = reqPath.toLowerCase();
        if (StringUtils.isEmpty(suffix)) {
            return false;
        }
        // 配置中不存在多个过滤的后缀名，直接检测
        if (!suffix.contains("|") && path.endsWith("." + suffix)) {
            return true;
        }
        String[] split = suffix.split("\\|");
        for (String item : split) {
            if (path.endsWith("." + item)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 使用 '/' 分割 URL 实例的 path 数据，通过组合第一层级目录，生成字典列表
     *
     * @param urlPath URL 实例的 path 数据
     * @return 失败返回空列表
     */
    private ArrayList<String> getUrlPathDict(String urlPath) {
        String direct = Config.get(Config.KEY_SCAN_LEVEL_DIRECT);
        int scanLevel = Config.getInt(Config.KEY_SCAN_LEVEL);
        ArrayList<String> result = new ArrayList<>();
        result.add("/");
        if (StringUtils.isEmpty(urlPath) || "/".equals(urlPath)) {
            return result;
        }
        // 限制方向从左往右，并且扫描层级为1
        if (Config.DIRECT_LEFT.equals(direct) && scanLevel <= 1) {
            return result;
        }
        // 结尾如果不是'/'符号，去掉访问的文件
        if (!urlPath.endsWith("/")) {
            urlPath = urlPath.substring(0, urlPath.lastIndexOf("/") + 1);
        }
        String[] splitDirname = urlPath.split("/");
        if (splitDirname.length == 0) {
            return result;
        }
        // 限制方向从右往左，默认不扫描根目录
        if (Config.DIRECT_RIGHT.equals(direct) && scanLevel < splitDirname.length) {
            result.remove("/");
        }
        StringBuilder sb = new StringBuilder("/");
        for (String dirname : splitDirname) {
            if (StringUtils.isNotEmpty(dirname)) {
                sb.append(dirname).append("/");
                int level = StringUtils.countMatches(sb.toString(), "/");
                // 根据不同方向，限制目录层级
                if (Config.DIRECT_LEFT.equals(direct) && level > scanLevel) {
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
        return result;
    }

    /**
     * 运行扫描任务
     *
     * @param httpReqResp   请求响应实例
     * @param info          IRequestInfo 实例
     * @param pathWithQuery 路径+query参数
     * @param from          请求来源
     */
    private void runScanTask(IHttpRequestResponse httpReqResp, IRequestInfo info, String pathWithQuery, String from) {
        runScanTask(httpReqResp, info, pathWithQuery, from, RequestMode.AUTO);
    }

    private void runScanTask(IHttpRequestResponse httpReqResp, IRequestInfo info, String pathWithQuery, String from,
                             RequestMode requestMode) {
        if (isTaskStopRequested()) {
            Logger.debug("runScanTask: task stop requested, intercept source: %s", from);
            return;
        }
        IHttpService service = httpReqResp.getHttpService();
        // 处理请求头
        byte[] request = handleHeader(httpReqResp, info, pathWithQuery, from);
        // 处理请求头失败时，丢弃该任务
        if (request == null) {
            return;
        }
        IRequestInfo newInfo = mHelpers.analyzeRequest(service, request);
        String reqId = generateReqId(newInfo, from, requestMode);
        // 如果当前 URL 已经扫描，中止任务
        if (checkRepeatFilterByReqId(reqId)) {
            return;
        }
        // 如果未启用“请求包处理”功能，直接对扫描的任务发起请求
        if (!mDataBoardTab.hasPayloadProcessing()) {
            doBurpRequest(service, reqId, request, from, requestMode);
            return;
        }
        // 运行已经启用并且需要合并的任务
        runEnableAndMergeTask(service, reqId, request, from, requestMode);
        // 运行已经启用并且不需要合并的任务
        runEnabledWithoutMergeProcessingTask(service, reqId, request, requestMode);
    }

    /**
     * 生成请求 ID
     *
     * @param info IRequestInfo 实例
     * @param from 请求来源
     * @return 失败返回 "null" 字符串
     */
    private String generateReqId(IRequestInfo info, String from) {
        return generateReqId(info, from, RequestMode.AUTO);
    }

    private String generateReqId(IRequestInfo info, String from, RequestMode requestMode) {
        if (info == null || StringUtils.isEmpty(from)) {
            return "null";
        }
        String reqPath = getReqPathByRequestInfo(info);
        // 生成携带完整的 Host 地址请求的请求 ID 值
        if (UrlUtils.isHTTP(reqPath)) {
            URL originUrl = info.getUrl();
            String originReqHost = UrlUtils.getReqHostByURL(originUrl);
            return originReqHost + "->" + reqPath;
        }
        URL url = getUrlByRequestInfo(info);
        String reqHost = UrlUtils.getReqHostByURL(url);
        // 生成重定向请求的请求 ID 值
        if (from.startsWith(FROM_REDIRECT)) {
            return reqHost + reqPath;
        }
        if (requestMode != null && requestMode != RequestMode.AUTO) {
            return requestMode.name() + " " + reqHost + url.getPath();
        }
        // 默认使用 http://x.x.x.x/path/to/index.html 格式作为请求 ID 值
        return reqHost + url.getPath();
    }

    /**
     * 根据 Url 检测是否重复扫描
     *
     * @param reqId 请求 ID
     * @return true=重复；false=不重复
     */
    private synchronized boolean checkRepeatFilterByReqId(String reqId) {
        if (sRepeatFilter.contains(reqId)) {
            return true;
        }
        return !sRepeatFilter.add(reqId);
    }

    /**
     * 运行已经启用并且需要合并的任务
     *
     * @param service     请求目标服务实例
     * @param reqId       请求 ID
     * @param reqRawBytes 请求数据包
     * @param from        请求来源
     */
    private void runEnableAndMergeTask(IHttpService service, String reqId, byte[] reqRawBytes, String from,
                                       RequestMode requestMode) {
        // 获取已经启用并且需要合并的“请求包处理”规则
        List<ProcessingItem> processList = getPayloadProcess()
                .stream().filter(ProcessingItem::isEnabledAndMerge)
                .collect(Collectors.toList());
        // 如果规则为空，直接发起请求
        if (processList.isEmpty()) {
            doBurpRequest(service, reqId, reqRawBytes, from, requestMode);
            return;
        }
        byte[] resultBytes = reqRawBytes;
        for (ProcessingItem item : processList) {
            ArrayList<PayloadItem> items = item.getItems();
            resultBytes = handlePayloadProcess(service, resultBytes, items);
        }
        if (resultBytes != null) {
            // 检测是否未进行任何处理
            boolean equals = Arrays.equals(reqRawBytes, resultBytes);
            // 未进行任何处理时，不变更 from 值
            String newFrom = equals ? from : from + "（" + FROM_PROCESS + "）";
            doBurpRequest(service, reqId, resultBytes, newFrom, requestMode);
        } else {
            // 如果规则处理异常导致数据返回为空，则发送原来的请求
            doBurpRequest(service, reqId, reqRawBytes, from, requestMode);
        }
    }

    /**
     * 运行已经启用并且不需要合并的任务
     *
     * @param service     请求目标服务实例
     * @param reqId       请求 ID
     * @param reqRawBytes 请求数据包
     */
    private void runEnabledWithoutMergeProcessingTask(IHttpService service, String reqId, byte[] reqRawBytes,
                                                      RequestMode requestMode) {
        final long taskGeneration = resolveTaskGeneration();
        // 遍历规则列表，进行 Payload Processing 处理后，再次请求数据包
        getPayloadProcess().parallelStream().filter(ProcessingItem::isEnabledWithoutMerge)
                .forEach((item) -> runWithTaskGeneration(taskGeneration, () -> {
                    if (isTaskStopRequested()) {
                        return;
                    }
                    ArrayList<PayloadItem> items = item.getItems();
                    byte[] requestBytes = handlePayloadProcess(service, reqRawBytes, items);
                    // 因为不需要合并的规则是将每条处理完成的数据包都发送请求，所以规则处理异常的请求包，不需要发送请求
                    if (requestBytes == null) {
                        return;
                    }
                    // 检测是否未进行任何处理（如上所述的原因，未进行任何处理的请求包，也不需要发送请求）
                    boolean equals = Arrays.equals(reqRawBytes, requestBytes);
                    if (equals) {
                        return;
                    }
                    doBurpRequest(service, reqId, requestBytes, FROM_PROCESS + "（" + item.getName() + "）",
                            requestMode);
                }));
    }

    /**
     * 使用 Burp 自带的方式请求
     *
     * @param service     请求目标服务实例
     * @param reqId       请求 ID
     * @param reqRawBytes 请求数据包
     * @param from        请求来源
     */
    private void doBurpRequest(IHttpService service, String reqId, byte[] reqRawBytes, String from,
                               RequestMode requestMode) {
        final long taskGeneration = resolveTaskGeneration();
        // 线程池关闭后，不接收任何任务
        if (isTaskStopRequested(taskGeneration)) {
            Logger.debug("doBurpRequest: task stop requested, intercept req id: %s", reqId);
            // 将未执行的任务从去重过滤集合中移除
            sRepeatFilter.remove(reqId);
            return;
        }
        // 创建任务运行实例
        TaskRunnable task = new TaskRunnable(reqId, from) {
            @Override
            public void run() {
                runWithTaskGeneration(taskGeneration, () -> {
                String reqId = getReqId();
                    if (isTaskStopRequested()) {
                        sRepeatFilter.remove(reqId);
                        incrementTaskOverCounter(from);
                        return;
                    }
                // 低频任务不进行 QPS 限制
                    if (requestMode != RequestMode.BROWSER && !isLowFrequencyTask(from) && checkQPSLimit()) {
                    // 拦截后，将未执行的任务从去重过滤集合中移除
                    sRepeatFilter.remove(reqId);
                    // 任务完成计数
                    incrementTaskOverCounter(from);
                    return;
                }
                Logger.debug("Do Send Request id: %s", reqId);
                    try {
                        waitForRequestMode(requestMode);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        sRepeatFilter.remove(reqId);
                        incrementTaskOverCounter(from);
                        return;
                    }
                    if (isTaskStopRequested()) {
                        sRepeatFilter.remove(reqId);
                        incrementTaskOverCounter(from);
                        return;
                    }
                // 获取配置的请求重试次数
                int retryCount = Config.getInt(Config.KEY_RETRY_COUNT);
                // 发起请求
                    IHttpRequestResponse newReqResp = doMakeHttpRequest(service, reqRawBytes, retryCount, requestMode);
                    if (newReqResp == null) {
                        sRepeatFilter.remove(reqId);
                        incrementTaskOverCounter(from);
                        return;
                    }
                    if (isTaskStopRequested()) {
                        sRepeatFilter.remove(reqId);
                        incrementTaskOverCounter(from);
                        return;
                    }
                // 构建展示的数据包
                    boolean browserResult = requestMode == RequestMode.BROWSER || isBrowserRequestResponse(newReqResp);
                    String displayFrom = browserResult ? appendBrowserFrom(from) : from;
                TaskData data = buildTaskData(newReqResp, displayFrom);
                    mDataBoardTab.addTaskData(data, browserResult ? RequestMode.BROWSER : RequestMode.BURP);
                // 收集数据
                CollectManager.collect(false, service.getHost(), newReqResp.getResponse());
                // 处理重定向
                handleFollowRedirect(data);
                // 任务完成计数
                incrementTaskOverCounter(from);
                });
            }
        };
        // 将任务添加线程池
        try {
            // 如果是低频任务，使用低频的任务线程池
            if (requestMode == RequestMode.BROWSER) {
                mBrowserTaskThreadPool.execute(task);
                mTaskCommitCounter.incrementAndGet();
            } else if (isLowFrequencyTask(from)) {
                mLFTaskThreadPool.execute(task);
                // 低频任务提交计数
                mLFTaskCommitCounter.incrementAndGet();
            } else {
                // 否则使用常规的任务线程池
                mTaskThreadPool.execute(task);
                // 任务提交计数
                mTaskCommitCounter.incrementAndGet();
            }
        } catch (Exception e) {
            Logger.error("doBurpRequest thread execute error: %s", e.getMessage());
        }
    }

    /**
     * 任务线程池是否关闭
     *
     * @return true=是；false=否
     */
    private boolean isTaskThreadPoolShutdown() {
        return mTaskThreadPool.isShutdown() || mLFTaskThreadPool.isShutdown() || mBrowserTaskThreadPool.isShutdown();
    }

    /**
     * 当前请求来源，是否为低频任务
     *
     * @param from 请求来源
     * @return true=是；false=否
     */
    private boolean isLowFrequencyTask(String from) {
        if (StringUtils.isEmpty(from)) {
            return false;
        }
        return from.startsWith(FROM_PROXY) || from.startsWith(FROM_SEND) || from.startsWith(FROM_REDIRECT);
    }

    /**
     * 增加任务完成计数
     *
     * @param from 请求来源
     */
    private void incrementTaskOverCounter(String from) {
        if (isLowFrequencyTask(from)) {
            // 低频任务完成计数
            mLFTaskOverCounter.incrementAndGet();
        } else {
            // 任务完成计数
            mTaskOverCounter.incrementAndGet();
        }
    }

    /**
     * 处理跟随重定向
     */
    private void handleFollowRedirect(TaskData data) {
        // 如果未启用“跟随重定向”功能，不继续执行
        if (!Config.getBoolean(Config.KEY_FOLLOW_REDIRECT)) {
            return;
        }
        int status = data.getStatus();
        // 检测 30x 状态码
        if (status < 300 || status >= 400) {
            return;
        }
        // 如果线程中断，不继续往下执行
        if (isTaskStopRequested()) {
            Logger.debug("handleFollowRedirect: task stop requested, intercept data id: %s", data.getId());
            return;
        }
        // 解析响应头的 Location 值
        IHttpRequestResponse reqResp = (IHttpRequestResponse) data.getReqResp();
        IResponseInfo respInfo = mHelpers.analyzeResponse(reqResp.getResponse());
        String location = getLocationByResponseInfo(respInfo);
        if (location == null) {
            return;
        }
        // 如果启用了 Cookie 跟随，获取响应头中的 Cookie 值
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
            // 兼容完整 Host 地址
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
            doScan(httpReqResp, FROM_REDIRECT + "（" + data.getId() + "）");
        } catch (IllegalArgumentException e) {
            Logger.error("Follow redirect error: " + e.getMessage());
        }
    }

    /**
     * 从 IResponseInfo 实例获取响应头 Location 值
     *
     * @param info IResponseInfo 实例
     * @return 失败返回null
     */
    private String getLocationByResponseInfo(IResponseInfo info) {
        String headerPrefix = "location: ";
        List<String> headers = info.getHeaders();
        for (int i = 1; i < headers.size(); i++) {
            String header = headers.get(i);
            // 检测时忽略大小写
            if (header.toLowerCase().startsWith(headerPrefix)) {
                return header.substring(headerPrefix.length());
            }
        }
        return null;
    }

    /**
     * 从 IResponseInfo 实例获取响应头 Set-Cookie 值，并转换为请求头的 Cookie 值列表
     *
     * @param info IResponseInfo 实例
     * @return 失败返回空列表
     */
    private List<String> getCookieByResponseInfo(IResponseInfo info) {
        List<ICookie> respCookies = info.getCookies();
        List<String> cookies = new ArrayList<>();
        for (ICookie cookie : respCookies) {
            String name = cookie.getName();
            String value = cookie.getValue();
            // 拼接后，添加到列表
            cookies.add(String.format("%s=%s", name, value));
        }
        return cookies;
    }

    /**
     * 调用 BurpSuite 请求方式
     *
     * @param service     请求目标服务实例
     * @param reqRawBytes 请求数据包
     * @param retryCount  重试次数（为0表示不重试）
     * @return 请求响应数据
     */
    private IHttpRequestResponse doMakeHttpRequest(IHttpService service, byte[] reqRawBytes, int retryCount) {
        return doMakeHttpRequest(service, reqRawBytes, retryCount, RequestMode.AUTO);
    }

    private IHttpRequestResponse doMakeHttpRequest(IHttpService service, byte[] reqRawBytes, int retryCount,
                                                   RequestMode requestMode) {
        if (isTaskStopRequested()) {
            Logger.debug("doMakeHttpRequest: task stop requested, intercept task");
            return HttpReqRespAdapter.from(service, reqRawBytes);
        }
        IHttpRequestResponse reqResp;
        String reqHost = getReqHostByHttpService(service);
        // 如果启用拦截超时主机，并检测到当前请求主机超时，直接拦截
        if (Config.getBoolean(Config.KEY_INTERCEPT_TIMEOUT_HOST) && checkTimeoutByReqHost(reqHost)) {
            return HttpReqRespAdapter.from(service, reqRawBytes);
        }
        if (requestMode == RequestMode.BROWSER) {
            return doBrowserRequest(service, reqRawBytes, true);
        }
        try {
            reqResp = mCallbacks.makeHttpRequest(service, reqRawBytes);
            byte[] respRawBytes = reqResp.getResponse();
            if (respRawBytes != null && respRawBytes.length > 0) {
                IHttpRequestResponse browserFallback = tryBrowserFallbackForInterception(service, reqRawBytes,
                        reqResp, requestMode);
                if (browserFallback != null) {
                    return browserFallback;
                }
                return reqResp;
            }
        } catch (Exception e) {
            Logger.debug("Do Request error, request host: %s", reqHost);
            reqResp = HttpReqRespAdapter.from(service, reqRawBytes);
        }
        // 如果线程中断，不继续往下执行
        if (Thread.currentThread().isInterrupted()) {
            Logger.debug("doMakeHttpRequest: thread pool is shutdown, intercept task");
            return reqResp;
        }
        Logger.debug("Check retry request host: %s, count: %d", reqHost, retryCount);
        // 检测是否需要重试
        if (retryCount <= 0) {
            // 超时的请求，直接添加到集合中
            sTimeoutReqHost.add(reqHost);
            return reqResp;
        }
        // 获取配置的请求重试间隔时间
        int retryInterval = Config.getInt(Config.KEY_RETRY_INTERVAL);
        if (retryInterval > 0) {
            try {
                Thread.sleep(retryInterval);
            } catch (InterruptedException e) {
                // 如果线程中断，返回目前的响应结果
                return reqResp;
            }
        }
        return doMakeHttpRequest(service, reqRawBytes, retryCount - 1, requestMode);
    }

    /**
     * 检测当前请求主机是否超时
     *
     * @param reqHost Host（格式：http://x.x.x.x、http://x.x.x.x:8080）
     * @return true=存在；false=不存在
     */
    private IHttpRequestResponse doBrowserRequest(IHttpService service, byte[] reqRawBytes, boolean forceBrowser) {
        if (isTaskStopRequested()) {
            Logger.debug("doBrowserRequest: task stop requested, intercept browser request");
            return null;
        }
        if (!canUseBrowserRequest(service, reqRawBytes, forceBrowser)) {
            return null;
        }
        synchronized (mBrowserRequestLock) {
            if (isTaskStopRequested()) {
                Logger.debug("doBrowserRequest: task stop requested after acquiring browser lock");
                return null;
            }
            try {
                waitForRequestMode(RequestMode.BROWSER);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            }
            if (isTaskStopRequested()) {
                Logger.debug("doBrowserRequest: task stop requested after browser pause check");
                return null;
            }
            try {
                IRequestInfo info = mHelpers.analyzeRequest(service, reqRawBytes);
                URL url = getUrlByRequestInfo(info);
                Logger.debug("Do browser request: %s", url);
                BrowserRequest browserRequest = buildBrowserRequest(info, reqRawBytes);
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
                if (isTaskStopRequested() || mPausedRequestModes.contains(RequestMode.BROWSER)) {
                    return null;
                }
                IHttpRequestResponse reqResp = HttpReqRespAdapter.from(service, reqRawBytes);
                reqResp.setResponse(buildBrowserErrorResponseBytes(e));
                reqResp.setComment(FROM_BROWSER);
                return reqResp;
            }
        }
    }

    private boolean canUseBrowserRequest(IHttpService service, byte[] reqRawBytes, boolean forceBrowser) {
        if (!forceBrowser && !Config.getBoolean(Config.KEY_ENABLE_BROWSER_REQUEST)) {
            return false;
        }
        IRequestInfo info = mHelpers.analyzeRequest(service, reqRawBytes);
        String method = info.getMethod();
        if (!"GET".equalsIgnoreCase(method) && !"POST".equalsIgnoreCase(method)) {
            return false;
        }
        return matchesBrowserRequestTarget(service, info);
    }

    private IHttpRequestResponse tryBrowserFallbackForInterception(IHttpService service, byte[] reqRawBytes,
                                                                   IHttpRequestResponse burpResp,
                                                                   RequestMode requestMode) {
        if (requestMode != RequestMode.AUTO || !Config.getBoolean(Config.KEY_ENABLE_BROWSER_REQUEST)) {
            return null;
        }
        if (burpResp == null || burpResp.getResponse() == null || burpResp.getResponse().length == 0) {
            return null;
        }
        if (!canUseBrowserRequest(service, reqRawBytes, false)) {
            return null;
        }
        if (!looksLikeInterceptionPage(service, burpResp)) {
            return null;
        }
        IHttpRequestResponse browserResp = doBrowserRequest(service, reqRawBytes, false);
        if (browserResp == null || browserResp.getResponse() == null || browserResp.getResponse().length == 0) {
            return null;
        }
        Logger.debug("Browser fallback triggered for possible interception page: %s",
                getReqHostByHttpService(service));
        return browserResp;
    }

    private boolean looksLikeInterceptionPage(IHttpService service, IHttpRequestResponse reqResp) {
        byte[] response = reqResp.getResponse();
        if (response == null || response.length == 0) {
            return false;
        }
        IResponseInfo info = mHelpers.analyzeResponse(response);
        int status = info.getStatusCode();
        if (!isInterceptionCandidateStatus(status)) {
            return false;
        }
        int bodyOffset = info.getBodyOffset();
        int bodyLength = Math.max(0, response.length - bodyOffset);
        String title = HtmlUtils.findTitleByHtmlBody(response);
        String bodyPreview = "";
        if (bodyOffset >= 0 && bodyOffset < response.length) {
            int end = Math.min(response.length, bodyOffset + 8192);
            bodyPreview = new String(Arrays.copyOfRange(response, bodyOffset, end), StandardCharsets.UTF_8)
                    .toLowerCase(Locale.ROOT);
        }
        if (containsInterceptionKeyword(title) || containsInterceptionKeyword(bodyPreview)) {
            return true;
        }
        String host = getReqHostByHttpService(service);
        String signature = status + ":" + bodyLength + ":" + safe(title);
        BrowserFallbackStats stats = mBrowserFallbackStats.computeIfAbsent(host, key -> new BrowserFallbackStats());
        BrowserFallbackStats.RecordResult recordResult = stats.record(status, signature);
        if (recordResult.sameSignatureCount() >= 5 && status != 404 && bodyLength > 0) {
            return true;
        }
        return isHardInterceptionStatus(status) && recordResult.sameStatusCount() >= 3;
    }

    private boolean isInterceptionCandidateStatus(int status) {
        return status == 200 || status == 202 || status == 401 || status == 403 || status == 406
                || status == 412 || status == 418 || status == 429 || status == 503;
    }

    private boolean isHardInterceptionStatus(int status) {
        return status == 403 || status == 406 || status == 412 || status == 418 || status == 429 || status == 503;
    }

    private boolean containsInterceptionKeyword(String text) {
        if (StringUtils.isEmpty(text)) {
            return false;
        }
        String value = text.toLowerCase(Locale.ROOT);
        String[] keywords = {
                "captcha",
                "verify",
                "verification",
                "challenge",
                "cloudflare",
                "cf-chl",
                "waf",
                "rsource",
                "rsource.js",
                "rs5",
                "rs6",
                "ruishu",
                "access denied",
                "security check",
                "安全验证",
                "访问验证",
                "验证码",
                "人机验证",
                "滑块",
                "拦截",
                "防火墙",
                "请求过于频繁"
        };
        for (String keyword : keywords) {
            if (value.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    private BrowserRequest buildBrowserRequest(IRequestInfo info, byte[] reqRawBytes) throws MalformedURLException {
        URL url = getUrlByRequestInfo(info);
        if (url == null) {
            throw new IllegalArgumentException("browser request url is empty");
        }
        int bodyOffset = info.getBodyOffset();
        byte[] bodyBytes = bodyOffset >= 0 && bodyOffset < reqRawBytes.length
                ? Arrays.copyOfRange(reqRawBytes, bodyOffset, reqRawBytes.length)
                : EMPTY_BYTES;
        return BrowserRequest.of(info.getMethod(), url.toString(), info.getHeaders(), bodyBytes);
    }

    private boolean matchesBrowserRequestTarget(IHttpService service, IRequestInfo info) {
        String targetRegex = Config.get(Config.KEY_BROWSER_TARGET_HOST_REGEX);
        if (StringUtils.isEmpty(targetRegex)) {
            return true;
        }
        String host = service == null ? null : service.getHost();
        if (StringUtils.isEmpty(host) && info != null) {
            URL url = getUrlByRequestInfo(info);
            if (url != null) {
                host = url.getHost();
            }
        }
        if (StringUtils.isEmpty(host)) {
            return false;
        }
        try {
            return Pattern.compile(targetRegex).matcher(host).find();
        } catch (PatternSyntaxException e) {
            Logger.debug("Browser target host regex invalid: %s", e.getMessage());
            return false;
        }
    }

    /**
     * 处理请求头
     *
     * @param httpReqResp   Burp 的 HTTP 请求响应接口
     * @param pathWithQuery 请求路径，或者请求路径+Query（示例：/xxx、/xxx/index?a=xxx&b=xxx）
     * @param from          数据来源
     * @return 处理完成的数据包，失败时返回null
     */
    private byte[] handleHeader(IHttpRequestResponse httpReqResp, IRequestInfo info, String pathWithQuery, String from) {
        // 配置的请求头
        List<String> configHeader = getHeader();
        // 要移除的请求头KEY列表
        List<String> removeHeaders = getRemoveHeaders();
        // 数据包自带的请求头
        List<String> headers = info.getHeaders();
        // 构建请求头
        StringBuilder requestRaw = new StringBuilder();
        // 根据数据来源区分两种请求头
        if (from.equals(FROM_SCAN)) {
            requestRaw.append("GET ").append(pathWithQuery).append(" HTTP/1.1").append("\r\n");
        } else {
            String reqLine = headers.get(0);
            // 先检测一下是否包含 ' HTTP/' 字符串，再继续处理（可能有些畸形数据包不存在该内容）
            if (reqLine.contains(" HTTP/")) {
                int start = reqLine.lastIndexOf(" HTTP/");
                reqLine = reqLine.substring(0, start) + " HTTP/1.1";
            }
            requestRaw.append(reqLine).append("\r\n");
        }
        // 请求头的参数处理（顺带处理移除的请求头），从 1 开始表示跳过首行（请求行）
        for (int i = 1; i < headers.size(); i++) {
            String item = headers.get(i);
            String key = item.split(": ")[0];
            // 是否需要移除当前请求头字段（优先级最高）
            if (removeHeaders.contains(key)) {
                continue;
            }
            // 如果是扫描的请求（只有 GET 请求），将 Content-Length 移除
            if (from.equals(FROM_SCAN) && "Content-Length".equalsIgnoreCase(key)) {
                continue;
            }
            // 检测配置中是否存在当前请求头字段
            String matchItem = configHeader.stream().filter(configHeaderItem -> {
                if (StringUtils.isNotEmpty(configHeaderItem) && configHeaderItem.contains(": ")) {
                    String configHeaderKey = configHeaderItem.split(": ")[0];
                    // 检测是否需要移除当前请求头字段
                    if (removeHeaders.contains(key)) {
                        return false;
                    }
                    return configHeaderKey.equals(key);
                }
                return false;
            }).findFirst().orElse(null);
            // 配置中存在匹配项，替换为配置中的数据
            if (matchItem != null) {
                requestRaw.append(matchItem).append("\r\n");
                // 将已经添加的数据从列表中移除
                configHeader.remove(matchItem);
            } else {
                // 不存在匹配项，填充原数据
                requestRaw.append(item).append("\r\n");
            }
        }
        // 将配置里剩下的值全部填充到请求头中
        for (String item : configHeader) {
            String key = item.split(": ")[0];
            // 检测是否需要移除当前KEY
            if (!removeHeaders.contains(key)) {
                requestRaw.append(item).append("\r\n");
            }
        }
        requestRaw.append("\r\n");
        // 如果当前数据来源不是 Scan，可能会包含 POST 请求，判断是否存在 body 数据
        if (!from.equals(FROM_SCAN)) {
            byte[] httpRequest = httpReqResp.getRequest();
            int bodyOffset = info.getBodyOffset();
            int bodySize = httpRequest.length - bodyOffset;
            if (bodySize > 0) {
                requestRaw.append(new String(httpRequest, bodyOffset, bodySize));
            }
        }
        // 请求头构建完成后，对里面包含的动态变量进行赋值
        IHttpService service = httpReqResp.getHttpService();
        URL url = getUrlByRequestInfo(info);
        String newRequestRaw = setupVariable(service, url, requestRaw.toString());
        if (newRequestRaw == null) {
            return null;
        }
        // 更新 Content-Length
        return updateContentLength(mHelpers.stringToBytes(newRequestRaw));
    }

    private boolean handleBrowserProxyResponse(IHttpRequestResponse httpReqResp) {
        if (httpReqResp == null || httpReqResp.getResponse() == null || httpReqResp.getRequest() == null) {
            return false;
        }
        String requestKey = buildBrowserRequestKey(httpReqResp);
        if (requestKey == null) {
            return shouldSuppressBrowserProxyTraffic(httpReqResp);
        }
        if (mPausedRequestModes.contains(RequestMode.BROWSER)
                && (mBrowserRequestTasks.containsKey(requestKey) || isExpectedBrowserRequest(requestKey))) {
            return true;
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
        for (Map.Entry<String, String> entry : result.getHeaders().entrySet()) {
            String key = entry.getKey();
            if (StringUtils.isEmpty(key)) {
                continue;
            }
            if ("transfer-encoding".equalsIgnoreCase(key)
                    || "content-encoding".equalsIgnoreCase(key)
                    || "content-length".equalsIgnoreCase(key)) {
                continue;
            }
            headers.append(key).append(": ").append(entry.getValue()).append("\r\n");
        }
        headers.append("Content-Length: ").append(bodyBytes.length).append("\r\n");
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

    /**
     * 获取请求头配置
     */
    private List<String> getHeader() {
        if (!mDataBoardTab.hasReplaceHeader()) {
            return new ArrayList<>();
        }
        return WordlistManager.getHeader();
    }

    /**
     * 获取移除请求头列表配置
     */
    private List<String> getRemoveHeaders() {
        if (!mDataBoardTab.hasRemoveHeader()) {
            return new ArrayList<>();
        }
        return WordlistManager.getRemoveHeaders();
    }

    /**
     * 获取配置的 Payload Processing 规则
     */
    private List<ProcessingItem> getPayloadProcess() {
        ArrayList<ProcessingItem> list = Config.getPayloadProcessList();
        if (list == null) {
            return new ArrayList<>();
        }
        return list.stream().filter(ProcessingItem::isEnabled).collect(Collectors.toList());
    }

    /**
     * 检测 QPS 限制
     *
     * @return true=拦截；false=不拦截
     */
    private boolean checkQPSLimit() {
        if (mQpsLimit != null) {
            try {
                mQpsLimit.limit();
            } catch (InterruptedException e) {
                // 线程强制停止时，拦截请求
                return true;
            }
        }
        return false;
    }

    /**
     * 给数据包填充动态变量
     *
     * @param service    请求目标实例
     * @param url        请求 URL 实例
     * @param requestRaw 请求数据包字符串
     * @return 处理失败返回null
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
        // 替换变量
        try {
            requestRaw = fillVariable(requestRaw, "protocol", protocol);
            requestRaw = fillVariable(requestRaw, "host", host);
            requestRaw = fillVariable(requestRaw, "webroot", webroot);
            // 需要填充再取值
            if (requestRaw.contains("{{ip}}")) {
                String ip = findIpByHost(domain);
                requestRaw = fillVariable(requestRaw, "ip", ip);
            }
            // 填充域名相关动态变量
            requestRaw = fillVariable(requestRaw, "domain", domain);
            requestRaw = fillVariable(requestRaw, "domain.main", domainMain);
            requestRaw = fillVariable(requestRaw, "domain.name", domainName);
            // 填充子域名相关动态变量
            requestRaw = fillVariable(requestRaw, "subdomain", subdomain);
            requestRaw = fillVariable(requestRaw, "subdomains", subdomains);
            if (requestRaw.contains("{{subdomains.")) {
                if (StringUtils.isEmpty(subdomains)) {
                    return null;
                }
                String[] subdomainsSplit = subdomains.split("\\.");
                // 遍历填充 {{subdomains.%d}} 动态变量
                for (int i = 0; i < subdomainsSplit.length; i++) {
                    requestRaw = fillVariable(requestRaw, "subdomains." + i, subdomainsSplit[i]);
                }
                // 检测是否存在未填充的 {{subdomains.%d}} 动态变量，如果存在，忽略当前 Payload
                if (requestRaw.contains("{{subdomains.")) {
                    return null;
                }
            }
            // 填充随机值相关动态变量
            requestRaw = fillVariable(requestRaw, "random.ip", randomIP);
            requestRaw = fillVariable(requestRaw, "random.local-ip", randomLocalIP);
            requestRaw = fillVariable(requestRaw, "random.ua", randomUA);
            // 填充日期、时间相关的动态变量
            requestRaw = fillVariable(requestRaw, "timestamp", timestamp);
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
     * 填充动态变量
     *
     * @param src   数据源
     * @param name  变量名
     * @param value 需要填充的变量值
     * @throws IllegalArgumentException 当填充的变量值为空时，抛出该异常
     */
    private String fillVariable(String src, String name, String value) throws IllegalArgumentException {
        if (StringUtils.isEmpty(src)) {
            return src;
        }
        String key = String.format("{{%s}}", name);
        if (!src.contains(key)) {
            return src;
        }
        // 值为空时，返回null值丢弃当前请求
        if (StringUtils.isEmpty(value)) {
            throw new IllegalArgumentException(key + " fill failed, value is empty.");
        }
        return src.replace(key, value);
    }

    /**
     * 解析日期时间，将每个字段的数据存入数组
     *
     * @param dateTime 日期时间字符串（格式：yyyy-MM-dd HH:mm:ss 或者 yy-M-d H:m:s）
     * @return [0]=年；[1]=月；[2]=日；[3]=时；[4]=分；[5]=秒
     */
    private String[] parseDateTime(String dateTime) {
        String[] result = new String[6];
        String[] split = dateTime.split(" ");
        // 日期
        String date = split[0];
        String[] dateSplit = date.split("-");
        result[0] = dateSplit[0];
        result[1] = dateSplit[1];
        result[2] = dateSplit[2];
        // 时间
        String time = split[1];
        String[] timeSplit = time.split(":");
        result[3] = timeSplit[0];
        result[4] = timeSplit[1];
        result[5] = timeSplit[2];
        return result;
    }

    /**
     * 获取子域名
     *
     * @param domain 域名（格式示例：www.xxx.com）
     * @return 格式：www；如果没有子域名，或者获取失败，返回null
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
     * 获取完整子域名
     *
     * @param domain 域名（格式示例：api.xxx.com、api.admin.xxx.com）
     * @return 格式：api、api.admin；如果没有子域名，或者获取失败，返回null
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
     * 从URL实例中获取Web根目录名（例如："http://xxx.com/abc/a.php" => "abc"）
     *
     * @param url URL实例
     * @return 失败返回null
     */
    private String getWebrootByURL(URL url) {
        if (url == null) {
            return null;
        }
        String path = url.getPath();
        // 没有根目录名，直接返回null
        if (StringUtils.isEmpty(path) || "/".equals(path)) {
            return null;
        }
        // 找第二个'/'斜杠
        int end = path.indexOf("/", 1);
        if (end < 0) {
            return null;
        }
        // 找到之后，取中间的值
        return path.substring(1, end);
    }

    /**
     * 根据 Payload Process 规则，处理数据包
     *
     * @param service      请求目标服务
     * @param requestBytes 请求数据包
     * @return 处理后的数据包
     */
    private byte[] handlePayloadProcess(IHttpService service, byte[] requestBytes, List<PayloadItem> list) {
        if (requestBytes == null || requestBytes.length == 0 || list == null || list.isEmpty()) {
            return null;
        }
        IRequestInfo info = mHelpers.analyzeRequest(service, requestBytes);
        int bodyOffset = info.getBodyOffset();
        int bodySize = requestBytes.length - bodyOffset;
        String url = getReqPathByRequestInfo(info);
        byte[] headerBytes = Arrays.copyOfRange(requestBytes, 0, Math.max(0, bodyOffset - 4));
        byte[] bodyBytes = bodySize <= 0 ? EMPTY_BYTES : Arrays.copyOfRange(requestBytes, bodyOffset, requestBytes.length);
        String header = mHelpers.bytesToString(headerBytes);
        String body = bodyBytes.length == 0 ? "" : mHelpers.bytesToString(bodyBytes);
        String request = mHelpers.bytesToString(requestBytes);
        for (PayloadItem item : list) {
            // 只调用启用的规则
            PayloadRule rule = item.getRule();
            try {
                switch (item.getScope()) {
                    case PayloadRule.SCOPE_URL:
                        String newUrl = rule.handleProcess(url);
                        // 截取请求头第一行，用于定位要处理的位置
                        String reqLine = header.substring(0, header.indexOf("\r\n"));
                        Matcher matcher = Constants.REGEX_REQ_LINE_URL.matcher(reqLine);
                        if (matcher.find()) {
                            int start = matcher.start(1);
                            int end = matcher.end(1);
                            // 分隔要插入数据的位置
                            String left = header.substring(0, start);
                            String right = header.substring(end);
                            // 拼接处理好的数据
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
        // 动态变量赋值
        URL u = getUrlByRequestInfo(info);
        String newRequest = setupVariable(service, u, request);
        if (newRequest == null) {
            return null;
        }
        // 更新 Content-Length
        return updateContentLength(mHelpers.stringToBytes(newRequest));
    }

    /**
     * 更新 Content-Length 参数值
     *
     * @param rawBytes 请求数据包
     * @return 更新后的数据包
     */
    private byte[] updateContentLength(byte[] rawBytes) {
        if (rawBytes == null || rawBytes.length == 0) {
            return rawBytes;
        }
        IRequestInfo info;
        try {
            info = mHelpers.analyzeRequest(rawBytes);
        } catch (Exception e) {
            Logger.error("Handle payload process error: analyze request failed");
            return null;
        }
        int bodyOffset = info.getBodyOffset();
        int bodySize = rawBytes.length - bodyOffset;
        if (bodySize < 0) {
            Logger.error("Handle payload process error: bodySize < 0");
            return null;
        }
        byte[] bodyBytes = bodySize == 0
                ? EMPTY_BYTES
                : Arrays.copyOfRange(rawBytes, bodyOffset, rawBytes.length);
        List<String> headers = new ArrayList<>();
        boolean hadContentLength = false;
        for (String header : info.getHeaders()) {
            if (header.regionMatches(true, 0, "Content-Length:", 0, "Content-Length:".length())) {
                hadContentLength = true;
                continue;
            }
            headers.add(header);
        }
        String method = info.getMethod();
        if (bodyBytes.length == 0
                && (hadContentLength || !"GET".equalsIgnoreCase(method) && !"HEAD".equalsIgnoreCase(method))) {
            headers.add("Content-Length: 0");
        }
        return mHelpers.buildHttpMessage(headers, bodyBytes);
    }

    /**
     * 构建Item数据
     *
     * @param httpReqResp Burp的请求响应对象
     * @return 列表Item数据
     */
    private TaskData buildTaskData(IHttpRequestResponse httpReqResp, String from) {
        IRequestInfo info = mHelpers.analyzeRequest(httpReqResp);
        byte[] respBytes = httpReqResp.getResponse();
        // 获取所需要的参数
        String method = info.getMethod();
        IHttpService service = httpReqResp.getHttpService();
        String reqHost = getReqHostByHttpService(service);
        String reqUrl = getReqPathByRequestInfo(info);
        String title = HtmlUtils.findTitleByHtmlBody(respBytes);
        String ip = findIpByHost(service.getHost());
        int status = -1;
        int length = -1;
        // 存在响应对象，获取状态和响应包大小
        if (respBytes != null && respBytes.length > 0) {
            IResponseInfo response = mHelpers.analyzeResponse(respBytes);
            status = response.getStatusCode();
            // 处理响应 body 的长度
            length = respBytes.length - response.getBodyOffset();
            if (length < 0) {
                length = 0;
            }
        }
        // 检测指纹数据
        List<FpData> checkResult = FpManager.check(httpReqResp.getRequest(), httpReqResp.getResponse());
        // 构建表格对象
        TaskData data = new TaskData();
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
        // 同步保存原始字节，供历史数据加载后恢复展示
        data.setReqBytes(httpReqResp.getRequest());
        data.setRespBytes(httpReqResp.getResponse());
        return data;
    }

    /**
     * 通过 IHttpService 实例，获取请求的 Host 地址（http://x.x.x.x、http://x.x.x.x:8080）
     *
     * @param service IHttpService 实例
     * @return 返回请求的 Host 地址
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
     * 根据 Host 查询 IP 地址
     *
     * @param host Host 值
     * @return 失败返回空字符串
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
     * 获取 IRequestInfo 实例的请求 URL 实例
     *
     * @param info IRequestInfo 实例
     * @return 返回请求的 URL 实例
     */
    private URL getUrlByRequestInfo(IRequestInfo info) {
        URL url = info.getUrl();
        try {
            // 分两种情况，一种是完整 Host 地址，还有一种是普通请求路径
            String reqPath = getReqPathByRequestInfo(info);
            if (UrlUtils.isHTTP(reqPath)) {
                return new URL(reqPath);
            }
            // 普通请求路径因为 IRequestInfo.getUrl 方法有时候获取的值不准确，重新解析一下
            String reqHost = UrlUtils.getReqHostByURL(url);
            return new URL(reqHost + reqPath);
        } catch (Exception e) {
            Logger.error("getUrlByRequestInfo: convert url error: %s", e.getMessage());
            return url;
        }
    }

    @Override
    public void onChangeSelection(TaskData data) {
        // 如果 data 为空，表示执行了清空历史记录操作
        if (data == null) {
            onClearHistory();
            return;
        }
        if (data.getReqResp() instanceof IHttpRequestResponse reqResp) {
            mCurrentReqResp = reqResp;
        } else {
            // 历史加载的数据：从持久化的原始字节重建 IHttpRequestResponse
            mCurrentReqResp = rebuildReqRespFromBytes(data);
            if (mCurrentReqResp == null) {
                mRequestTextEditor.setMessage(EMPTY_BYTES, true);
                mResponseTextEditor.setMessage(EMPTY_BYTES, false);
                return;
            }
        }
        // 加载请求、响应数据包
        byte[] hintBytes = mHelpers.stringToBytes(L.get("message_editor_loading"));
        mRequestTextEditor.setMessage(hintBytes, true);
        mResponseTextEditor.setMessage(hintBytes, false);
        mRefreshMsgTask.execute(this::refreshReqRespMessage);
    }

    /**
     * 从 TaskData 中保存的原始字节重建 IHttpRequestResponse（用于历史数据展示）
     *
     * @param data TaskData 实例
     * @return 重建后的实例；如果字节为空则返回 null
     */
    private IHttpRequestResponse rebuildReqRespFromBytes(TaskData data) {
        byte[] reqBytes = data.getReqBytes();
        if (reqBytes == null || reqBytes.length == 0) {
            return null;
        }
        IHttpService service = buildHttpServiceByHostString(data.getHost());
        if (service == null) {
            return null;
        }
        HttpReqRespAdapter adapter = HttpReqRespAdapter.from(service, reqBytes);
        byte[] respBytes = data.getRespBytes();
        if (respBytes != null && respBytes.length > 0) {
            adapter.setResponse(respBytes);
        }
        return adapter;
    }

    /**
     * 从持久化的 host 字符串（格式：protocol://host 或 protocol://host:port）重建 IHttpService
     *
     * @param hostStr host 字符串
     * @return IHttpService 实例；解析失败返回 null
     */
    private IHttpService buildHttpServiceByHostString(String hostStr) {
        if (StringUtils.isEmpty(hostStr)) {
            return null;
        }
        try {
            URL u = new URL(hostStr);
            return buildHttpServiceByURL(u);
        } catch (MalformedURLException e) {
            return null;
        }
    }

    /**
     * 清空历史记录
     */
    private void onClearHistory() {
        mCurrentReqResp = null;
        // 清空去重过滤集合
        sRepeatFilter.clear();
        // 清空超时的请求主机集合
        sTimeoutReqHost.clear();
        mBrowserFallbackStats.clear();
        cancelBrowserRequestDriver();
        clearBrowserRequestTasks();
        // 清空显示的请求、响应数据包
        mRequestTextEditor.setMessage(EMPTY_BYTES, true);
        mResponseTextEditor.setMessage(EMPTY_BYTES, false);
        // 清除指纹识别历史记录
        FpManager.clearHistory();
        closeBrowserRequestDriverAsync();
    }

    /**
     * 刷新请求响应信息
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
        // 检测是否超过配置的显示长度限制
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
     * 修改 QPS 限制
     *
     * @param limit QPS 限制值（数字）
     */
    private void changeQpsLimit(String limit) {
        initQpsLimiter();
        Logger.debug("Event: change qps limit: %s", limit);
    }

    /**
     * 修改请求延迟
     *
     * @param delay 延迟的值（数字）
     */
    private void changeRequestDelay(String delay) {
        initQpsLimiter();
        Logger.debug("Event: change request delay: %s", delay);
    }

    /**
     * 导入 URL
     *
     * @param list URL 列表
     */
    private void importUrl(List<?> list, RequestMode requestMode) {
        if (list == null || list.isEmpty()) {
            return;
        }
        // 处理导入的 URL 数据
        final long taskGeneration = captureTaskGeneration();
        new Thread(() -> runWithTaskGeneration(taskGeneration, () -> {
            for (Object item : list) {
                try {
                    String url = String.valueOf(item);
                    IHttpRequestResponse httpReqResp = HttpReqRespAdapter.from(url);
                    doScan(httpReqResp, FROM_IMPORT, requestMode);
                } catch (IllegalArgumentException e) {
                    Logger.error("Import error: " + e.getMessage());
                }
                // 线程池关闭后，停止导入 Url 数据
                if (isTaskStopRequested(taskGeneration)) {
                    Logger.debug("importUrl: task stop requested, stop import url");
                    return;
                }
            }
        })).start();
    }

    @Override
    public void onSendToRepeater(ArrayList<TaskData> list) {
        if (list == null || list.isEmpty()) {
            return;
        }
        for (TaskData data : list) {
            if (!(data.getReqResp() instanceof IHttpRequestResponse reqResp)) {
                continue;
            }
            byte[] reqBytes = reqResp.getRequest();
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
        if (data == null || !(data.getReqResp() instanceof IHttpRequestResponse reqResp)) {
            return new byte[]{};
        }
        mCurrentReqResp = reqResp;
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
        mOst.getConfigPanel().refreshHostTab();
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
            case OtherTab.EVENT_REFRESH_DATA_PERSISTENCE:
                if (mDataBoardTab != null) {
                    mDataBoardTab.refreshAutoSaveTimer();
                }
                break;
            case OtherTab.EVENT_REFRESH_MCP_SERVER:
                refreshMcpServer();
                break;
            case DataBoardTab.EVENT_IMPORT_URL:
                RequestMode requestMode = params.length > 1 && params[1] instanceof RequestMode
                        ? (RequestMode) params[1]
                        : RequestMode.AUTO;
                importUrl((List<?>) params[0], requestMode);
                break;
            case DataBoardTab.EVENT_STOP_TASK:
                RequestScope stopScope = params.length > 0 && params[0] instanceof RequestScope
                        ? (RequestScope) params[0]
                        : RequestScope.ALL;
                pauseTask(stopScope);
                break;
            case DataBoardTab.EVENT_CONTINUE_TASK:
                RequestScope continueScope = params.length > 0 && params[0] instanceof RequestScope
                        ? (RequestScope) params[0]
                        : RequestScope.ALL;
                continueTask(continueScope);
                break;
            case DataBoardTab.EVENT_CLEAR_ALL_TASK:
                stopAllTask();
                break;
        }
    }

    private void pauseTask(RequestScope scope) {
        synchronized (mRequestPauseLock) {
            if (scope == null || scope == RequestScope.ALL) {
                mPausedRequestModes.add(RequestMode.BURP);
                mPausedRequestModes.add(RequestMode.BROWSER);
                cancelBrowserRequestDriver();
            } else if (scope == RequestScope.BURP) {
                mPausedRequestModes.add(RequestMode.BURP);
            } else if (scope == RequestScope.BROWSER) {
                mPausedRequestModes.add(RequestMode.BROWSER);
                cancelBrowserRequestDriver();
            }
        }
        UIHelper.showTipsDialog(L.get("stop_task_tips"));
    }

    private void continueTask(RequestScope scope) {
        synchronized (mRequestPauseLock) {
            if (scope == null || scope == RequestScope.ALL) {
                mPausedRequestModes.clear();
            } else if (scope == RequestScope.BURP) {
                mPausedRequestModes.remove(RequestMode.BURP);
            } else if (scope == RequestScope.BROWSER) {
                mPausedRequestModes.remove(RequestMode.BROWSER);
            }
            mRequestPauseLock.notifyAll();
        }
        UIHelper.showTipsDialog(L.get("continue_task_tips"));
    }

    /**
     * 停止扫描中的所有任务
     */
    private void stopAllTask() {
        mTaskGeneration.incrementAndGet();
        // 关闭线程池，处理未执行的任务
        List<Runnable> taskList = mTaskThreadPool.shutdownNow();
        List<Runnable> lfTaskList = mLFTaskThreadPool.shutdownNow();
        List<Runnable> browserTaskList = mBrowserTaskThreadPool.shutdownNow();
        cancelBrowserRequestDriver();
        handleStopTasks(taskList);
        handleStopTasks(lfTaskList);
        handleStopTasks(browserTaskList);
        clearBrowserRequestTasks();
        synchronized (mRequestPauseLock) {
            mPausedRequestModes.clear();
            mRequestPauseLock.notifyAll();
        }
        sRepeatFilter.clear();
        sTimeoutReqHost.clear();
        mBrowserFallbackStats.clear();
        // 提示信息
        UIHelper.showTipsDialog(L.get("clear_all_task_tips"));
        // 停止后，重新初始化任务线程池
        mTaskThreadPool = Executors.newFixedThreadPool(TASK_THREAD_COUNT);
        // 停止后，重新初始化低频任务线程池
        mLFTaskThreadPool = Executors.newFixedThreadPool(LF_TASK_THREAD_COUNT);
        mBrowserTaskThreadPool = Executors.newSingleThreadExecutor();
        // 重新初始化 QPS 限制器
        initQpsLimiter();
        closeBrowserRequestDriverAsync();
    }

    /**
     * 处理停止的任务列表
     *
     * @param list 任务列表
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
                // 将未执行的任务从去重过滤集合中移除
                sRepeatFilter.remove(reqId);
                // 将未执行的任务计数
                if (isLowFrequencyTask(from)) {
                    mLFTaskOverCounter.incrementAndGet();
                } else {
                    mTaskOverCounter.incrementAndGet();
                }
            }
        }
    }

    @Override
    public List<OstMcpTool> listTools() {
        return List.of(
                mcpTool("ost.capabilities.list", "List OST MCP capabilities.", objectSchema()),
                mcpTool("ost.status.get", "Get OST runtime status and key configuration.", objectSchema()),
                mcpTool("ost.scan.urls", "Submit one or more URLs to OST scanning.", objectSchema(
                        required("urls"),
                        property("urls", arraySchema(stringSchema()), "URL list."),
                        property("mode", enumSchema("auto", "burp", "browser"), "Request mode.")
                )),
                mcpTool("ost.scan.request", "Submit a raw HTTP request to OST scanning.", objectSchema(
                        required("request", "protocol", "host"),
                        property("request", stringSchema(), "Raw HTTP request."),
                        property("protocol", enumSchema("http", "https"), "Request protocol."),
                        property("host", stringSchema(), "Target host."),
                        property("port", numberSchema(), "Target port."),
                        property("mode", enumSchema("auto", "burp", "browser"), "Request mode."),
                        property("payload", stringSchema(), "Payload wordlist name.")
                )),
                mcpTool("ost.tasks.list", "List OST task results with pagination.", objectSchema(
                        property("scope", enumSchema("all", "burp", "browser"), "Task table scope."),
                        property("offset", numberSchema(), "Zero-based offset."),
                        property("limit", numberSchema(), "Maximum results, default 50."),
                        property("include_body", booleanSchema(), "Include raw request/response body.")
                )),
                mcpTool("ost.tasks.search", "Search OST task results by structured filters.", objectSchema(
                        property("scope", enumSchema("all", "burp", "browser"), "Task table scope."),
                        property("host", stringSchema(), "Host contains filter."),
                        property("url", stringSchema(), "URL path contains filter."),
                        property("title", stringSchema(), "Title contains filter."),
                        property("fingerprint", stringSchema(), "Fingerprint parameter contains filter."),
                        property("status", numberSchema(), "HTTP status code."),
                        property("limit", numberSchema(), "Maximum results, default 50."),
                        property("include_body", booleanSchema(), "Include raw request/response body.")
                )),
                mcpTool("ost.tasks.get", "Get a task result by id.", objectSchema(
                        required("id"),
                        property("id", numberSchema(), "Task id."),
                        property("scope", enumSchema("all", "burp", "browser"), "Task table scope."),
                        property("include_body", booleanSchema(), "Include raw request/response body.")
                )),
                mcpTool("ost.fingerprint.check", "Run OST fingerprint matching on request/response bytes.", objectSchema(
                        property("request", stringSchema(), "Raw HTTP request."),
                        property("response", stringSchema(), "Raw HTTP response."),
                        property("task_id", numberSchema(), "Existing task id."),
                        property("scope", enumSchema("all", "burp", "browser"), "Task table scope.")
                )),
                mcpTool("ost.fingerprint.rules.list", "List fingerprint rule summaries.", objectSchema(
                        property("limit", numberSchema(), "Maximum results, default 100."),
                        property("offset", numberSchema(), "Zero-based offset.")
                )),
                mcpTool("ost.collect.modules.list", "List OST data collection modules.", objectSchema()),
                mcpTool("ost.collect.node.get", "Get collected data by node path.", objectSchema(
                        property("path", stringSchema(), "Collect node path, default /."),
                        property("recursive", booleanSchema(), "Include child nodes.")
                )),
                mcpTool("ost.wordlists.list", "List wordlist groups and selected wordlists.", objectSchema()),
                mcpTool("ost.wordlist.get", "Get one wordlist content.", objectSchema(
                        required("key"),
                        property("key", enumSchema("payload", "headers", "user-agent", "host-allowlist", "host-blocklist", "remove-headers"),
                                "Wordlist key."),
                        property("name", stringSchema(), "Wordlist name. Defaults to selected item."),
                        property("limit", numberSchema(), "Maximum items, default 200.")
                )),
                mcpTool("ost.wordlist.select", "Select the active wordlist for a wordlist group.", objectSchema(
                        required("key", "name"),
                        property("key", enumSchema("payload", "headers", "user-agent", "host-allowlist", "host-blocklist", "remove-headers"),
                                "Wordlist key."),
                        property("name", stringSchema(), "Existing wordlist name.")
                )),
                mcpTool("ost.wordlist.create", "Create an empty wordlist.", objectSchema(
                        required("key", "name"),
                        property("key", enumSchema("payload", "headers", "user-agent", "host-allowlist", "host-blocklist", "remove-headers"),
                                "Wordlist key."),
                        property("name", stringSchema(), "New wordlist name."),
                        property("select", booleanSchema(), "Select it after creation.")
                )),
                mcpTool("ost.wordlist.append", "Append unique items to a wordlist.", objectSchema(
                        required("key", "items"),
                        property("key", enumSchema("payload", "headers", "user-agent", "host-allowlist", "host-blocklist", "remove-headers"),
                                "Wordlist key."),
                        property("name", stringSchema(), "Wordlist name. Defaults to selected item."),
                        property("items", arraySchema(stringSchema()), "Items to append.")
                )),
                mcpTool("ost.wordlist.put", "Replace a wordlist with provided items. Requires confirm=true.", objectSchema(
                        required("key", "items", "confirm"),
                        property("key", enumSchema("payload", "headers", "user-agent", "host-allowlist", "host-blocklist", "remove-headers"),
                                "Wordlist key."),
                        property("name", stringSchema(), "Wordlist name. Defaults to selected item."),
                        property("items", arraySchema(stringSchema()), "Replacement items."),
                        property("confirm", booleanSchema(), "Must be true to replace content.")
                )),
                mcpTool("ost.wordlist.import_file", "Import a local text file into a wordlist.", objectSchema(
                        required("key", "path"),
                        property("key", enumSchema("payload", "headers", "user-agent", "host-allowlist", "host-blocklist", "remove-headers"),
                                "Wordlist key."),
                        property("path", stringSchema(), "Local text file path."),
                        property("name", stringSchema(), "Destination wordlist name. Defaults to file name."),
                        property("mode", enumSchema("append", "replace"), "Import mode. Replace requires confirm=true."),
                        property("select", booleanSchema(), "Select destination after import."),
                        property("confirm", booleanSchema(), "Must be true for replace mode.")
                )),
                mcpTool("ost.wordlist.delete", "Delete a wordlist. Requires confirm=true.", objectSchema(
                        required("key", "name", "confirm"),
                        property("key", enumSchema("payload", "headers", "user-agent", "host-allowlist", "host-blocklist", "remove-headers"),
                                "Wordlist key."),
                        property("name", stringSchema(), "Wordlist name."),
                        property("confirm", booleanSchema(), "Must be true to delete.")
                )),
                mcpTool("ost.history.labels", "List persisted history labels.", objectSchema()),
                mcpTool("ost.export.csv", "Export persisted OST data to CSV.", objectSchema(
                        required("path"),
                        property("path", stringSchema(), "CSV output path."),
                        property("label", stringSchema(), "Optional history label."),
                        property("fields", arraySchema(stringSchema()), "Field keys to export.")
                ))
        );
    }

    @Override
    public Object callTool(String name, Map<String, Object> arguments) throws Exception {
        Map<String, Object> args = arguments == null ? new LinkedHashMap<>() : arguments;
        name = normalizeMcpToolName(name);
        return switch (name) {
            case "ost.capabilities.list" -> mcpCapabilities();
            case "ost.status.get" -> mcpStatus();
            case "ost.scan.urls" -> mcpScanUrls(args);
            case "ost.scan.request" -> mcpScanRequest(args);
            case "ost.tasks.list" -> mcpListTasks(args);
            case "ost.tasks.search" -> mcpSearchTasks(args);
            case "ost.tasks.get" -> mcpGetTask(args);
            case "ost.fingerprint.check" -> mcpFingerprintCheck(args);
            case "ost.fingerprint.rules.list" -> mcpFingerprintRules(args);
            case "ost.collect.modules.list" -> mcpCollectModules();
            case "ost.collect.node.get" -> mcpCollectNode(args);
            case "ost.wordlists.list" -> mcpWordlists();
            case "ost.wordlist.get" -> mcpWordlistGet(args);
            case "ost.wordlist.select" -> mcpWordlistSelect(args);
            case "ost.wordlist.create" -> mcpWordlistCreate(args);
            case "ost.wordlist.append" -> mcpWordlistAppend(args);
            case "ost.wordlist.put" -> mcpWordlistPut(args);
            case "ost.wordlist.import_file" -> mcpWordlistImportFile(args);
            case "ost.wordlist.delete" -> mcpWordlistDelete(args);
            case "ost.history.labels" -> mcpHistoryLabels();
            case "ost.export.csv" -> mcpExportCsv(args);
            default -> throw new IllegalArgumentException("Unknown tool: " + name);
        };
    }

    private String normalizeMcpToolName(String name) {
        return name;
    }

    private Map<String, Object> mcpCapabilities() {
        return mapOf(
                "server", mapOf("name", "ost-burp-mcp", "endpoint", mMcpServer == null ? "" : mMcpServer.getEndpoint()),
                "capabilities", List.of(
                        capability("ost.status.get", "passive", "Read runtime status."),
                        capability("ost.tasks.list", "passive", "Read summarized task results."),
                        capability("ost.tasks.search", "passive", "Search summarized task results."),
                        capability("ost.tasks.get", "passive", "Read one task result, raw data opt-in."),
                        capability("ost.fingerprint.check", "passive", "Run local fingerprint rules."),
                        capability("ost.collect.node.get", "passive", "Read collected data."),
                        capability("ost.wordlists.list", "passive", "Read wordlist metadata."),
                        capability("ost.wordlist.select", "configuration-write", "Switch active wordlists."),
                        capability("ost.wordlist.append", "filesystem-write", "Append items to local wordlists."),
                        capability("ost.wordlist.put", "filesystem-write", "Replace local wordlists, confirm required."),
                        capability("ost.wordlist.import_file", "filesystem-write", "Import local text files into wordlists."),
                        capability("ost.wordlist.delete", "destructive", "Delete local wordlists, confirm required."),
                        capability("ost.history.labels", "passive", "Read persistence labels."),
                        capability("ost.scan.urls", "active", "Submit URL scan tasks."),
                        capability("ost.scan.request", "active", "Submit raw request scan tasks."),
                        capability("ost.export.csv", "filesystem-write", "Write CSV export to a local path.")
                ),

                "default_response_policy", "Summaries are returned by default. Raw request/response bodies require include_body=true."
        );
    }

    private Map<String, Object> mcpStatus() {
        return mapOf(
                "plugin", mapOf("name", Constants.PLUGIN_NAME, "version", Constants.PLUGIN_VERSION),
                "mcp", mapOf("enabled", Config.getBoolean(Config.KEY_ENABLE_MCP),
                        "endpoint", mMcpServer == null ? "" : mMcpServer.getEndpoint()),
                "config", mapOf(
                        "listen_proxy", mDataBoardTab != null && mDataBoardTab.hasListenProxyMessage(),
                        "dir_scan", mDataBoardTab != null && mDataBoardTab.hasDirScan(),
                        "payload_processing", mDataBoardTab != null && mDataBoardTab.hasPayloadProcessing(),
                        "browser_request", Config.getBoolean(Config.KEY_ENABLE_BROWSER_REQUEST),
                        "browser_fallback_on_interception", Config.getBoolean(Config.KEY_ENABLE_BROWSER_REQUEST),
                        "browser_type", Config.get(Config.KEY_BROWSER_TYPE),
                        "qps_limit", Config.getInt(Config.KEY_QPS_LIMIT),
                        "request_delay", Config.getInt(Config.KEY_REQUEST_DELAY),
                        "follow_redirect", Config.getBoolean(Config.KEY_FOLLOW_REDIRECT),
                        "persistence_enabled", TaskPersistenceManager.isEnabled(),
                        "persistence_db_path", TaskPersistenceManager.getDatabasePath()
                ),
                "tasks", mapOf(
                        "burp_count", taskCount(RequestScope.BURP),
                        "browser_count", taskCount(RequestScope.BROWSER),
                        "submitted", mTaskCommitCounter.get(),
                        "completed", mTaskOverCounter.get(),
                        "low_frequency_submitted", mLFTaskCommitCounter.get(),
                        "low_frequency_completed", mLFTaskOverCounter.get()
                ),
                "fingerprint", mapOf(
                        "rules", FpManager.getCount(),
                        "columns", FpManager.getColumnsCount(),
                        "cache_count", FpManager.getCacheCount(),
                        "history_count", FpManager.getHistoryCount()
                ),
                "collect", mapOf("repeat_filter_count", CollectManager.getRepeatFilterCount())
        );
    }

    private Map<String, Object> mcpScanUrls(Map<String, Object> args) {
        List<?> rawUrls = listArg(args, "urls");
        if (rawUrls.isEmpty()) {
            throw new IllegalArgumentException("urls is required");
        }
        ArrayList<String> urls = new ArrayList<>();
        for (Object item : rawUrls) {
            if (item != null && StringUtils.isNotEmpty(String.valueOf(item))) {
                urls.add(String.valueOf(item));
            }
        }
        if (urls.isEmpty()) {
            throw new IllegalArgumentException("urls is empty");
        }
        RequestMode mode = parseRequestMode(stringArg(args, "mode"), RequestMode.AUTO);
        importUrl(urls, mode);
        return mapOf("submitted_urls", urls.size(), "mode", mode.name().toLowerCase(Locale.ROOT));
    }

    private Map<String, Object> mcpScanRequest(Map<String, Object> args) {
        String request = stringArg(args, "request");
        String host = stringArg(args, "host");
        String protocol = stringArg(args, "protocol");
        if (StringUtils.isEmpty(request) || StringUtils.isEmpty(host) || StringUtils.isEmpty(protocol)) {
            throw new IllegalArgumentException("request, host and protocol are required");
        }
        int port = intArg(args, "port", "https".equalsIgnoreCase(protocol) ? 443 : 80);
        RequestMode mode = parseRequestMode(stringArg(args, "mode"), RequestMode.AUTO);
        String payload = stringArg(args, "payload");
        if (StringUtils.isEmpty(payload)) {
            payload = WordlistManager.getItem(WordlistManager.KEY_PAYLOAD);
        }
        IHttpService service = mHelpers.buildHttpService(host, port, protocol);
        IHttpRequestResponse reqResp = HttpReqRespAdapter.from(service, mHelpers.stringToBytes(request));
        doScan(reqResp, "MCP", payload, mode);
        return mapOf(
                "submitted", true,
                "host", host,
                "port", port,
                "protocol", protocol,
                "payload", payload,
                "mode", mode.name().toLowerCase(Locale.ROOT)
        );
    }

    private Map<String, Object> mcpListTasks(Map<String, Object> args) {
        RequestScope scope = parseRequestScope(stringArg(args, "scope"), RequestScope.ALL);
        int offset = Math.max(0, intArg(args, "offset", 0));
        int limit = clamp(intArg(args, "limit", 50), 1, 500);
        boolean includeBody = booleanArg(args, "include_body", false);
        List<TaskRecord> records = getTaskRecords(scope);
        return paginateTaskRecords(records, offset, limit, includeBody);
    }

    private Map<String, Object> mcpSearchTasks(Map<String, Object> args) {
        RequestScope scope = parseRequestScope(stringArg(args, "scope"), RequestScope.ALL);
        int limit = clamp(intArg(args, "limit", 50), 1, 500);
        boolean includeBody = booleanArg(args, "include_body", false);
        String host = lower(stringArg(args, "host"));
        String url = lower(stringArg(args, "url"));
        String title = lower(stringArg(args, "title"));
        String fingerprint = lower(stringArg(args, "fingerprint"));
        Integer status = hasArg(args, "status") ? intArg(args, "status", -1) : null;
        ArrayList<TaskRecord> matches = new ArrayList<>();
        for (TaskRecord record : getTaskRecords(scope)) {
            TaskData data = record.data();
            if (StringUtils.isNotEmpty(host) && !lower(data.getHost()).contains(host)) {
                continue;
            }
            if (StringUtils.isNotEmpty(url) && !lower(data.getUrl()).contains(url)) {
                continue;
            }
            if (StringUtils.isNotEmpty(title) && !lower(data.getTitle()).contains(title)) {
                continue;
            }
            if (status != null && data.getStatus() != status) {
                continue;
            }
            if (StringUtils.isNotEmpty(fingerprint)
                    && !lower(GsonUtils.toJson(data.getParams())).contains(fingerprint)) {
                continue;
            }
            matches.add(record);
            if (matches.size() >= limit) {
                break;
            }
        }
        return mapOf(
                "total_matches", matches.size(),
                "items", matches.stream().map(record -> taskRecordToMap(record, includeBody)).collect(Collectors.toList())
        );
    }

    private Map<String, Object> mcpGetTask(Map<String, Object> args) {
        int id = intArg(args, "id", -1);
        if (id < 0) {
            throw new IllegalArgumentException("id is required");
        }
        RequestScope scope = parseRequestScope(stringArg(args, "scope"), RequestScope.ALL);
        boolean includeBody = booleanArg(args, "include_body", false);
        for (TaskRecord record : getTaskRecords(scope)) {
            if (record.data().getId() == id) {
                return taskRecordToMap(record, includeBody);
            }
        }
        throw new IllegalArgumentException("task not found: " + id);
    }

    private Map<String, Object> mcpFingerprintCheck(Map<String, Object> args) {
        byte[] requestBytes = bytesArg(args, "request");
        byte[] responseBytes = bytesArg(args, "response");
        if ((requestBytes.length == 0 && responseBytes.length == 0) && hasArg(args, "task_id")) {
            int taskId = intArg(args, "task_id", -1);
            RequestScope scope = parseRequestScope(stringArg(args, "scope"), RequestScope.ALL);
            TaskRecord record = findTaskRecord(scope, taskId);
            if (record == null) {
                throw new IllegalArgumentException("task not found: " + taskId);
            }
            IHttpRequestResponse reqResp = getReqResp(record.data());
            if (reqResp != null) {
                requestBytes = reqResp.getRequest();
                responseBytes = reqResp.getResponse();
            }
        }
        List<FpData> matches = FpManager.check(requestBytes, responseBytes);
        return mapOf("count", matches.size(), "items", matches.stream().map(this::fpDataToMap).collect(Collectors.toList()));
    }

    private Map<String, Object> mcpFingerprintRules(Map<String, Object> args) {
        int offset = Math.max(0, intArg(args, "offset", 0));
        int limit = clamp(intArg(args, "limit", 100), 1, 1000);
        List<FpData> rules = FpManager.getList();
        int end = Math.min(rules.size(), offset + limit);
        ArrayList<Map<String, Object>> items = new ArrayList<>();
        for (int i = offset; i < end; i++) {
            FpData data = rules.get(i);
            items.add(mapOf(
                    "index", i,
                    "color", data.getColor(),
                    "params", fpParamsToMap(data),
                    "rule_groups", data.getRules().size()
            ));
        }
        return mapOf("total", rules.size(), "offset", offset, "limit", limit, "items", items);
    }

    private Map<String, Object> mcpCollectModules() {
        ArrayList<String> modules = new ArrayList<>();
        CollectManager.forEachModule(module -> modules.add(module.getName()));
        return mapOf("modules", modules);
    }

    private Map<String, Object> mcpCollectNode(Map<String, Object> args) {
        String path = stringArg(args, "path");
        if (StringUtils.isEmpty(path)) {
            path = "/";
        }
        boolean recursive = booleanArg(args, "recursive", false);
        CollectNode node = CollectManager.getNodeByPath(path);
        if (node == null) {
            throw new IllegalArgumentException("collect node not found: " + path);
        }
        return collectNodeToMap(path, node, recursive);
    }

    private Map<String, Object> mcpWordlists() {
        ArrayList<Map<String, Object>> groups = new ArrayList<>();
        for (String key : wordlistKeys()) {
            groups.add(mapOf(
                    "key", key,
                    "selected", WordlistManager.getItem(key),
                    "items", WordlistManager.getItemList(key)
            ));
        }
        return mapOf("groups", groups);
    }

    private Map<String, Object> mcpWordlistGet(Map<String, Object> args) {
        String key = stringArg(args, "key");
        if (!wordlistKeys().contains(key)) {
            throw new IllegalArgumentException("unsupported wordlist key: " + key);
        }
        String name = stringArg(args, "name");
        if (StringUtils.isEmpty(name)) {
            name = WordlistManager.getItem(key);
        }
        int limit = clamp(intArg(args, "limit", 200), 1, 5000);
        List<String> list = WordlistManager.getList(key, name);
        return mapOf(
                "key", key,
                "name", name,
                "total", list.size(),
                "items", list.stream().limit(limit).collect(Collectors.toList()),
                "truncated", list.size() > limit
        );
    }

    private Map<String, Object> mcpWordlistSelect(Map<String, Object> args) {
        String key = requireWordlistKey(args);
        String name = requireWordlistName(args, "name");
        ensureWordlistExists(key, name);
        String previous = WordlistManager.getItem(key);
        WordlistManager.putItem(key, name);
        return wordlistMutationResult("select", key, name, previous, WordlistManager.getList(key, name).size(), 0);
    }

    private Map<String, Object> mcpWordlistCreate(Map<String, Object> args) {
        String key = requireWordlistKey(args);
        String name = requireWordlistName(args, "name");
        if (WordlistManager.getItemList(key).contains(name)) {
            throw new IllegalArgumentException("wordlist already exists: " + name);
        }
        String previous = WordlistManager.getItem(key);
        WordlistManager.createList(key, name);
        if (booleanArg(args, "select", false)) {
            WordlistManager.putItem(key, name);
        }
        return wordlistMutationResult("create", key, name, previous, 0, 0);
    }

    private Map<String, Object> mcpWordlistAppend(Map<String, Object> args) {
        String key = requireWordlistKey(args);
        String name = optionalWordlistName(args);
        ensureWordlistExists(key, name);
        List<String> current = WordlistManager.getList(key, name);
        List<String> incoming = normalizeWordlistItems(listArg(args, "items"));
        int before = current.size();
        LinkedHashSet<String> merged = new LinkedHashSet<>(current);
        int added = 0;
        for (String item : incoming) {
            if (merged.add(item)) {
                added++;
            }
        }
        WordlistManager.putList(key, name, new ArrayList<>(merged));
        return wordlistMutationResult("append", key, name, WordlistManager.getItem(key), before + added, added);
    }

    private Map<String, Object> mcpWordlistPut(Map<String, Object> args) {
        if (!booleanArg(args, "confirm", false)) {
            throw new IllegalArgumentException("confirm=true is required to replace a wordlist");
        }
        String key = requireWordlistKey(args);
        String name = optionalWordlistName(args);
        ensureWordlistExists(key, name);
        List<String> items = normalizeWordlistItems(listArg(args, "items"));
        int before = WordlistManager.getList(key, name).size();
        WordlistManager.putList(key, name, items);
        return mapOf(
                "action", "put",
                "key", key,
                "name", name,
                "selected", WordlistManager.getItem(key),
                "before_count", before,
                "after_count", items.size(),
                "changed_count", items.size() - before
        );
    }

    private Map<String, Object> mcpWordlistImportFile(Map<String, Object> args) {
        String key = requireWordlistKey(args);
        String path = stringArg(args, "path");
        if (StringUtils.isEmpty(path) || !FileUtils.isFile(path)) {
            throw new IllegalArgumentException("import file not found: " + path);
        }
        String name = stringArg(args, "name");
        if (StringUtils.isEmpty(name)) {
            String fileName = new File(path).getName();
            int dot = fileName.lastIndexOf('.');
            name = dot > 0 ? fileName.substring(0, dot) : fileName;
        }
        name = normalizeWordlistName(name);
        String mode = stringArg(args, "mode");
        if (StringUtils.isEmpty(mode)) {
            mode = "append";
        }
        if (!"append".equalsIgnoreCase(mode) && !"replace".equalsIgnoreCase(mode)) {
            throw new IllegalArgumentException("mode must be append or replace");
        }
        if (!WordlistManager.getItemList(key).contains(name)) {
            WordlistManager.createList(key, name);
        }
        List<String> imported = normalizeWordlistItems(FileUtils.readFileToList(path));
        int before = WordlistManager.getList(key, name).size();
        int added;
        if ("replace".equalsIgnoreCase(mode)) {
            if (!booleanArg(args, "confirm", false)) {
                throw new IllegalArgumentException("confirm=true is required for replace import");
            }
            WordlistManager.putList(key, name, imported);
            added = imported.size() - before;
        } else {
            LinkedHashSet<String> merged = new LinkedHashSet<>(WordlistManager.getList(key, name));
            added = 0;
            for (String item : imported) {
                if (merged.add(item)) {
                    added++;
                }
            }
            WordlistManager.putList(key, name, new ArrayList<>(merged));
        }
        if (booleanArg(args, "select", false)) {
            WordlistManager.putItem(key, name);
        }
        return mapOf(
                "action", "import_file",
                "key", key,
                "name", name,
                "path", path,
                "mode", mode.toLowerCase(Locale.ROOT),
                "selected", WordlistManager.getItem(key),
                "imported_count", imported.size(),
                "before_count", before,
                "after_count", WordlistManager.getList(key, name).size(),
                "changed_count", added
        );
    }

    private Map<String, Object> mcpWordlistDelete(Map<String, Object> args) {
        if (!booleanArg(args, "confirm", false)) {
            throw new IllegalArgumentException("confirm=true is required to delete a wordlist");
        }
        String key = requireWordlistKey(args);
        String name = requireWordlistName(args, "name");
        ensureWordlistExists(key, name);
        List<String> itemList = WordlistManager.getItemList(key);
        if (itemList.size() <= 1) {
            throw new IllegalArgumentException("cannot delete the only wordlist for key: " + key);
        }
        String previous = WordlistManager.getItem(key);
        int before = WordlistManager.getList(key, name).size();
        WordlistManager.deleteList(key, name);
        if (name.equals(previous)) {
            List<String> remaining = WordlistManager.getItemList(key);
            if (!remaining.isEmpty()) {
                WordlistManager.putItem(key, remaining.contains("default") ? "default" : remaining.get(0));
            }
        }
        return mapOf(
                "action", "delete",
                "key", key,
                "name", name,
                "deleted_count", before,
                "previous_selected", previous,
                "selected", WordlistManager.getItem(key),
                "remaining", WordlistManager.getItemList(key)
        );
    }

    private Map<String, Object> mcpHistoryLabels() throws Exception {
        List<TaskPersistenceManager.HistoryLabel> labels = TaskPersistenceManager.listLabels();
        return mapOf(
                "enabled", TaskPersistenceManager.isEnabled(),
                "database_path", TaskPersistenceManager.getDatabasePath(),
                "labels", labels.stream()
                        .map(item -> mapOf("label", item.label(), "count", item.count()))
                        .collect(Collectors.toList())
        );
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> mcpExportCsv(Map<String, Object> args) throws Exception {
        String path = stringArg(args, "path");
        if (StringUtils.isEmpty(path)) {
            throw new IllegalArgumentException("path is required");
        }
        List<String> fields;
        List<?> rawFields = listArg(args, "fields");
        if (rawFields.isEmpty()) {
            fields = TaskPersistenceManager.getConfiguredFieldKeys();
        } else {
            fields = rawFields.stream().filter(Objects::nonNull).map(String::valueOf).collect(Collectors.toList());
        }
        String label = stringArg(args, "label");
        int count = TaskPersistenceManager.exportCsv(new File(path), fields, label);
        return mapOf("path", path, "label", label == null ? "" : label, "fields", fields, "count", count);
    }

    private OstMcpTool mcpTool(String name, String description, Map<String, Object> inputSchema) {
        return new OstMcpTool(name, description, inputSchema);
    }

    private Map<String, Object> capability(String name, String risk, String description) {
        return mapOf("name", name, "risk", risk, "description", description);
    }

    private Map<String, Object> paginateTaskRecords(List<TaskRecord> records, int offset, int limit, boolean includeBody) {
        int total = records.size();
        int start = Math.min(offset, total);
        int end = Math.min(total, start + limit);
        ArrayList<Map<String, Object>> items = new ArrayList<>();
        for (int i = start; i < end; i++) {
            items.add(taskRecordToMap(records.get(i), includeBody));
        }
        return mapOf("total", total, "offset", offset, "limit", limit, "items", items);
    }

    private List<TaskRecord> getTaskRecords(RequestScope scope) {
        ArrayList<TaskRecord> records = new ArrayList<>();
        if (mDataBoardTab == null) {
            return records;
        }
        if (scope == RequestScope.ALL || scope == RequestScope.BURP) {
            TaskTable table = mDataBoardTab.getBurpTaskTable();
            if (table != null) {
                for (TaskData data : table.getTaskDataList()) {
                    records.add(new TaskRecord("burp", data));
                }
            }
        }
        if (scope == RequestScope.ALL || scope == RequestScope.BROWSER) {
            TaskTable table = mDataBoardTab.getBrowserTaskTable();
            if (table != null) {
                for (TaskData data : table.getTaskDataList()) {
                    records.add(new TaskRecord("browser", data));
                }
            }
        }
        return records;
    }

    private TaskRecord findTaskRecord(RequestScope scope, int taskId) {
        for (TaskRecord record : getTaskRecords(scope)) {
            if (record.data().getId() == taskId) {
                return record;
            }
        }
        return null;
    }

    private int taskCount(RequestScope scope) {
        if (mDataBoardTab == null) {
            return 0;
        }
        int count = 0;
        if (scope == RequestScope.ALL || scope == RequestScope.BURP) {
            TaskTable table = mDataBoardTab.getBurpTaskTable();
            count += table == null ? 0 : table.getTaskCount();
        }
        if (scope == RequestScope.ALL || scope == RequestScope.BROWSER) {
            TaskTable table = mDataBoardTab.getBrowserTaskTable();
            count += table == null ? 0 : table.getTaskCount();
        }
        return count;
    }

    private Map<String, Object> taskRecordToMap(TaskRecord record, boolean includeBody) {
        TaskData data = record.data();
        IHttpRequestResponse reqResp = getReqResp(data);
        Map<String, Object> result = mapOf(
                "id", data.getId(),
                "scope", record.scope(),
                "from", safe(data.getFrom()),
                "method", safe(data.getMethod()),
                "host", safe(data.getHost()),
                "url", safe(data.getUrl()),
                "title", safe(data.getTitle()),
                "ip", safe(data.getIp()),
                "status", data.getStatus(),
                "length", data.getLength(),
                "color", safe(data.getHighlight()),
                "fingerprint", new LinkedHashMap<>(data.getParams())
        );
        if (reqResp != null) {
            byte[] request = emptyBytes(reqResp.getRequest());
            byte[] response = emptyBytes(reqResp.getResponse());
            result.put("request_length", request.length);
            result.put("response_length", response.length);
            result.put("request_md5", Utils.md5(request));
            result.put("response_md5", Utils.md5(response));
            if (includeBody) {
                result.put("request", bytesToString(request));
                result.put("response", bytesToString(response));
            }
        }
        return result;
    }

    private IHttpRequestResponse getReqResp(TaskData data) {
        if (data == null || !(data.getReqResp() instanceof IHttpRequestResponse reqResp)) {
            return null;
        }
        return reqResp;
    }

    private Map<String, Object> fpDataToMap(FpData data) {
        return mapOf(
                "color", data.getColor(),
                "info", data.toInfo(),
                "params", fpParamsToMap(data),
                "rule_groups", data.getRules().size()
        );
    }

    private Map<String, Object> fpParamsToMap(FpData data) {
        LinkedHashMap<String, Object> params = new LinkedHashMap<>();
        if (data == null) {
            return params;
        }
        for (FpData.Param param : data.getParams()) {
            String key = param.getK();
            String columnName = FpManager.findColumnNameById(key);
            params.put(StringUtils.isEmpty(columnName) ? key : columnName, param.getV());
        }
        return params;
    }

    private Map<String, Object> collectNodeToMap(String path, CollectNode node, boolean recursive) {
        LinkedHashMap<String, Object> data = new LinkedHashMap<>();
        CollectManager.forEachModule(module -> data.put(module.getName(), new ArrayList<>(node.getData(module.getName()))));
        ArrayList<Map<String, Object>> children = new ArrayList<>();
        for (CollectNode child : node.getNodes()) {
            String childPath = "/".equals(path) ? "/" + child.getName() : path + "/" + child.getName();
            if (recursive) {
                children.add(collectNodeToMap(childPath, child, true));
            } else {
                children.add(mapOf("path", childPath, "name", child.getName(), "child_count", child.getNodes().size()));
            }
        }
        return mapOf(
                "path", path,
                "name", node.getName(),
                "data", data,
                "child_count", node.getNodes().size(),
                "children", children
        );
    }

    private List<String> wordlistKeys() {
        return List.of(
                WordlistManager.KEY_PAYLOAD,
                WordlistManager.KEY_HEADERS,
                WordlistManager.KEY_USER_AGENT,
                WordlistManager.KEY_HOST_ALLOWLIST,
                WordlistManager.KEY_HOST_BLOCKLIST,
                WordlistManager.KEY_REMOVE_HEADERS
        );
    }

    private String requireWordlistKey(Map<String, Object> args) {
        String key = stringArg(args, "key");
        if (!wordlistKeys().contains(key)) {
            throw new IllegalArgumentException("unsupported wordlist key: " + key);
        }
        return key;
    }

    private String optionalWordlistName(Map<String, Object> args) {
        String name = stringArg(args, "name");
        if (StringUtils.isEmpty(name)) {
            String key = requireWordlistKey(args);
            return WordlistManager.getItem(key);
        }
        return normalizeWordlistName(name);
    }

    private String requireWordlistName(Map<String, Object> args, String field) {
        String name = normalizeWordlistName(stringArg(args, field));
        if (StringUtils.isEmpty(name)) {
            throw new IllegalArgumentException(field + " is required");
        }
        return name;
    }

    private String normalizeWordlistName(String name) {
        if (name == null) {
            return "";
        }
        String result = name.trim();
        if (result.endsWith(".txt")) {
            result = result.substring(0, result.length() - 4);
        }
        if (result.contains("/") || result.contains("\\") || result.contains("..")) {
            throw new IllegalArgumentException("invalid wordlist name: " + name);
        }
        return result;
    }

    private void ensureWordlistExists(String key, String name) {
        if (!WordlistManager.getItemList(key).contains(name)) {
            throw new IllegalArgumentException("wordlist not found: " + key + "/" + name);
        }
    }

    private List<String> normalizeWordlistItems(List<?> rawItems) {
        LinkedHashSet<String> items = new LinkedHashSet<>();
        for (Object rawItem : rawItems) {
            if (rawItem == null) {
                continue;
            }
            String item = String.valueOf(rawItem).trim();
            if (StringUtils.isNotEmpty(item)) {
                items.add(item);
            }
        }
        return new ArrayList<>(items);
    }

    private Map<String, Object> wordlistMutationResult(String action, String key, String name,
                                                       String previousSelected, int afterCount, int changedCount) {
        return mapOf(
                "action", action,
                "key", key,
                "name", name,
                "previous_selected", previousSelected,
                "selected", WordlistManager.getItem(key),
                "after_count", afterCount,
                "changed_count", changedCount,
                "items", WordlistManager.getItemList(key)
        );
    }

    private RequestMode parseRequestMode(String value, RequestMode fallback) {
        if ("burp".equalsIgnoreCase(value)) {
            return RequestMode.BURP;
        }
        if ("browser".equalsIgnoreCase(value)) {
            return RequestMode.BROWSER;
        }
        if ("auto".equalsIgnoreCase(value)) {
            return RequestMode.AUTO;
        }
        return fallback;
    }

    private RequestScope parseRequestScope(String value, RequestScope fallback) {
        if ("burp".equalsIgnoreCase(value)) {
            return RequestScope.BURP;
        }
        if ("browser".equalsIgnoreCase(value)) {
            return RequestScope.BROWSER;
        }
        if ("all".equalsIgnoreCase(value)) {
            return RequestScope.ALL;
        }
        return fallback;
    }

    private boolean hasArg(Map<String, Object> args, String key) {
        return args != null && args.containsKey(key) && args.get(key) != null;
    }

    private String stringArg(Map<String, Object> args, String key) {
        if (!hasArg(args, key)) {
            return "";
        }
        return String.valueOf(args.get(key));
    }

    private int intArg(Map<String, Object> args, String key, int fallback) {
        if (!hasArg(args, key)) {
            return fallback;
        }
        Object value = args.get(key);
        if (value instanceof Number number) {
            return number.intValue();
        }
        return StringUtils.parseInt(String.valueOf(value), fallback);
    }

    private boolean booleanArg(Map<String, Object> args, String key, boolean fallback) {
        if (!hasArg(args, key)) {
            return fallback;
        }
        Object value = args.get(key);
        if (value instanceof Boolean bool) {
            return bool;
        }
        return Boolean.parseBoolean(String.valueOf(value));
    }

    private List<?> listArg(Map<String, Object> args, String key) {
        if (!hasArg(args, key)) {
            return new ArrayList<>();
        }
        Object value = args.get(key);
        if (value instanceof List<?> list) {
            return list;
        }
        return new ArrayList<>();
    }

    private byte[] bytesArg(Map<String, Object> args, String key) {
        String value = stringArg(args, key);
        if (StringUtils.isEmpty(value)) {
            return EMPTY_BYTES;
        }
        return mHelpers == null ? value.getBytes(StandardCharsets.ISO_8859_1) : mHelpers.stringToBytes(value);
    }

    private String bytesToString(byte[] bytes) {
        return mHelpers == null ? new String(emptyBytes(bytes), StandardCharsets.ISO_8859_1) : mHelpers.bytesToString(emptyBytes(bytes));
    }

    private byte[] emptyBytes(byte[] bytes) {
        return bytes == null ? EMPTY_BYTES : bytes;
    }

    private String safe(String value) {
        return value == null ? "" : value;
    }

    private String lower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT);
    }

    private int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }

    private Map<String, Object> objectSchema(Object... specs) {
        LinkedHashMap<String, Object> schema = new LinkedHashMap<>();
        LinkedHashMap<String, Object> properties = new LinkedHashMap<>();
        ArrayList<String> required = new ArrayList<>();
        schema.put("type", "object");
        for (Object spec : specs) {
            if (spec instanceof PropertySpec property) {
                properties.put(property.name(), property.schema());
            } else if (spec instanceof RequiredSpec requiredSpec) {
                required.addAll(requiredSpec.names());
            }
        }
        schema.put("properties", properties);
        if (!required.isEmpty()) {
            schema.put("required", required);
        }
        return schema;
    }

    private PropertySpec property(String name, Map<String, Object> schema, String description) {
        schema.put("description", description);
        return new PropertySpec(name, schema);
    }

    private RequiredSpec required(String... names) {
        return new RequiredSpec(Arrays.asList(names));
    }

    private Map<String, Object> stringSchema() {
        return mapOf("type", "string");
    }

    private Map<String, Object> numberSchema() {
        return mapOf("type", "number");
    }

    private Map<String, Object> booleanSchema() {
        return mapOf("type", "boolean");
    }

    private Map<String, Object> enumSchema(String... values) {
        return mapOf("type", "string", "enum", Arrays.asList(values));
    }

    private Map<String, Object> arraySchema(Map<String, Object> itemSchema) {
        return mapOf("type", "array", "items", itemSchema);
    }

    private Map<String, Object> mapOf(Object... values) {
        LinkedHashMap<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i + 1 < values.length; i += 2) {
            map.put(String.valueOf(values[i]), values[i + 1]);
        }
        return map;
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController iMessageEditorController, boolean editable) {
        return new OstInfoTab(mCallbacks, iMessageEditorController);
    }

    @Override
    public void extensionUnloaded() {
        stopMcpServer();
        // 移除代理监听器
        mCallbacks.removeProxyListener(this);
        // 移除插件卸载监听器
        mCallbacks.removeExtensionStateListener(this);
        // 移除信息辅助面板
        mCallbacks.removeMessageEditorTabFactory(this);
        // 移除注册的菜单
        mCallbacks.removeContextMenuFactory(this);
        // 停止状态栏刷新定时器
        mStatusRefresh.stop();
        mRefreshMsgTask.shutdownNow();
        // 关闭任务线程池
        int count = mTaskThreadPool.shutdownNow().size();
        Logger.info("Close: task thread pool completed. Task %d records.", count);
        // 关闭低频任务线程池
        count = mLFTaskThreadPool.shutdownNow().size();
        Logger.info("Close: low frequency task thread pool completed. Task %d records.", count);
        count = mBrowserTaskThreadPool.shutdownNow().size();
        Logger.info("Close: browser task thread pool completed. Task %d records.", count);
        // 关闭指纹识别线程池
        count = mFpThreadPool.shutdownNow().size();
        Logger.info("Close: fingerprint recognition thread pool completed. Task %d records.", count);
        // 关闭数据收集线程池
        count = CollectManager.closeThreadPool();
        Logger.info("Close: data collection thread pool completed. Task %d records.", count);
        TaskPersistenceManager.close();
        // 清除数据收集的去重过滤集合
        count = CollectManager.getRepeatFilterCount();
        CollectManager.clearRepeatFilter();
        Logger.info("Clear: data collection repeat filter list completed. Total %d records.", count);
        // 清除指纹识别缓存
        count = FpManager.getCacheCount();
        FpManager.clearCache();
        Logger.info("Clear: fingerprint recognition cache completed. Total %d records.", count);
        // 清除指纹识别历史记录
        count = FpManager.getHistoryCount();
        FpManager.clearHistory();
        Logger.info("Clear: fingerprint recognition history completed. Total %d records.", count);
        // 清除指纹字段修改监听器
        FpManager.clearsFpColumnModifyListeners();
        // 清除去重过滤集合
        count = sRepeatFilter.size();
        sRepeatFilter.clear();
        Logger.info("Clear: repeat filter list completed. Total %d records.", count);
        // 清除超时的请求主机集合
        count = sTimeoutReqHost.size();
        sTimeoutReqHost.clear();
        mBrowserFallbackStats.clear();
        Logger.info("Clear: timeout request host list completed. Total %d records.", count);
        count = clearBrowserRequestTasks();
        Logger.info("Clear: browser request task list completed. Total %d records.", count);
        cancelBrowserRequestDriver();
        closeBrowserRequestDriver();
        mBrowserRequestManager.cleanupSessionWorkspace(Config.getWorkDir());
        mBrowserCloseExecutor.shutdownNow();
        // 清除任务列表
        count = 0;
        if (mDataBoardTab != null) {
            for (TaskTable taskTable : mDataBoardTab.getTaskTables()) {
                if (taskTable == null) {
                    continue;
                }
                count += taskTable.getTaskCount();
                taskTable.clearAll();
            }
            mDataBoardTab.closeAutoSaveTimer();
            mDataBoardTab.closeDataSaveExecutor();
            // 关闭导入 URL 窗口
            mDataBoardTab.closeImportUrlWindow();
        }
        Logger.info("Clear: task list completed. Total %d records.", count);
        // 关闭指纹相关窗口
        if (mOst != null && mOst.getFingerprintTab() != null) {
            FingerprintTab tab = mOst.getFingerprintTab();
            // 指纹测试窗口
            tab.closeFpTestWindow();
            // 指纹字段管理窗口
            tab.closeFpColumnManagerWindow();
        }
        // 卸载完成
        Logger.info(Constants.UNLOAD_BANNER);
    }

    private record TaskRecord(String scope, TaskData data) {
    }

    private record PropertySpec(String name, Map<String, Object> schema) {
    }

    private record RequiredSpec(List<String> names) {
    }

    private static class BrowserFallbackStats {
        private String lastSignature;
        private int lastStatus = -1;
        private int sameSignatureCount;
        private int sameStatusCount;

        private synchronized RecordResult record(int status, String signature) {
            if (StringUtils.isNotEmpty(signature) && signature.equals(lastSignature)) {
                sameSignatureCount++;
            } else {
                lastSignature = signature;
                sameSignatureCount = 1;
            }
            if (status == lastStatus) {
                sameStatusCount++;
            } else {
                lastStatus = status;
                sameStatusCount = 1;
            }
            return new RecordResult(sameSignatureCount, sameStatusCount);
        }

        private record RecordResult(int sameSignatureCount, int sameStatusCount) {
        }
    }

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

        private static String buildPortSuffix(URL url) {
            int port = url.getPort();
            if (port < 0 || port == url.getDefaultPort()) {
                return "";
            }
            return ":" + port;
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
}
