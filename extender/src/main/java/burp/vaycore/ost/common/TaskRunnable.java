package burp.vaycore.ost.common;

/**
 * 任务运行类
 *
 * <p>
 * Created by vaycore on 2025-01-07.
 */
public abstract class TaskRunnable implements Runnable {

    /**
     * 扫描任务请求的 ID
     */
    private final String mReqId;

    /**
     * 扫描任务的请求来源
     */
    private final String mFrom;

    private final RequestMode mRequestMode;

    public TaskRunnable(String reqId, String from) {
        this(reqId, from, RequestMode.AUTO);
    }

    public TaskRunnable(String reqId, String from, RequestMode requestMode) {
        this.mReqId = reqId;
        this.mFrom = from;
        this.mRequestMode = requestMode == null ? RequestMode.AUTO : requestMode;
    }

    public RequestMode getRequestMode() {
        return mRequestMode;
    }

    public String getReqId() {
        return mReqId;
    }

    public String getFrom() {
        return mFrom;
    }
}
