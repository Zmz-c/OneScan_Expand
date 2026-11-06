package burp.vaycore.ost.ui.widget;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.vaycore.ost.common.Config;
import burp.vaycore.ost.common.L;

import javax.swing.SwingUtilities;
import java.awt.Component;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicLong;

/** Independent Burp editors and context-menu state for one traffic view. */
public final class HttpMessageView implements IMessageEditorController {
    private static final byte[] EMPTY = new byte[0];
    private final IMessageEditor requestEditor;
    private final IMessageEditor responseEditor;
    private final Executor loader;
    private final AtomicLong selectionVersion = new AtomicLong();
    private volatile IHttpRequestResponse current;

    public HttpMessageView(IBurpExtenderCallbacks callbacks, Executor loader) {
        this.loader = loader;
        requestEditor = callbacks.createMessageEditor(this, false);
        responseEditor = callbacks.createMessageEditor(this, false);
    }

    public Component requestComponent() { return requestEditor.getComponent(); }
    public Component responseComponent() { return responseEditor.getComponent(); }
    public IHttpRequestResponse currentMessage() { return current; }

    public void showMessage(IHttpRequestResponse message) {
        long version = selectionVersion.incrementAndGet();
        current = message;
        onEdt(() -> {
            if (version != selectionVersion.get()) return;
            if (message == null) {
                setMessages(EMPTY, EMPTY);
                return;
            }
            byte[] loading = text(L.get("message_editor_loading"));
            setMessages(loading, loading);
            try {
                loader.execute(() -> loadMessage(message, version));
            } catch (RejectedExecutionException e) {
                if (version == selectionVersion.get()) setMessages(EMPTY, EMPTY);
            }
        });
    }

    private void loadMessage(IHttpRequestResponse message, long version) {
        if (version != selectionVersion.get()) return;
        byte[] request;
        byte[] response;
        try {
            // Read both halves from the captured selection, never from shared mutable state.
            request = forDisplay(message.getRequest(), "message_editor_request_length_limit_hint");
            response = forDisplay(message.getResponse(), "message_editor_response_length_limit_hint");
        } catch (RuntimeException e) {
            request = EMPTY;
            response = EMPTY;
        }
        byte[] finalRequest = request;
        byte[] finalResponse = response;
        onEdt(() -> {
            if (version == selectionVersion.get()) setMessages(finalRequest, finalResponse);
        });
    }

    private byte[] forDisplay(byte[] bytes, String limitKey) {
        if (bytes == null) return EMPTY;
        int limit = Config.getInt(Config.KEY_MAX_DISPLAY_LENGTH);
        return limit >= 100000 && bytes.length >= limit ? text(L.get(limitKey)) : bytes;
    }

    private void setMessages(byte[] request, byte[] response) {
        requestEditor.setMessage(request, true);
        responseEditor.setMessage(response, false);
    }

    private static byte[] text(String text) { return text.getBytes(StandardCharsets.UTF_8); }
    private static void onEdt(Runnable task) {
        if (SwingUtilities.isEventDispatchThread()) task.run();
        else SwingUtilities.invokeLater(task);
    }

    @Override
    public IHttpService getHttpService() {
        IHttpRequestResponse message = current;
        return message == null ? null : message.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        IHttpRequestResponse message = current;
        byte[] bytes = message == null ? null : message.getRequest();
        return bytes == null ? EMPTY : bytes;
    }

    @Override
    public byte[] getResponse() {
        IHttpRequestResponse message = current;
        byte[] bytes = message == null ? null : message.getResponse();
        return bytes == null ? EMPTY : bytes;
    }
}
