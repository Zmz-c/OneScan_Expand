package burp.vaycore.ost.ui.widget;

import burp.*;
import burp.vaycore.ost.common.HttpReqRespAdapter;
import javax.swing.*;
import java.awt.Component;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import static org.junit.Assert.assertTrue;

public final class MessageEditorFixture {
    public final List<Editor> editors = new ArrayList<>();
    public final List<IMessageEditorController> controllers = new ArrayList<>();
    public final IBurpExtenderCallbacks callbacks = (IBurpExtenderCallbacks) Proxy.newProxyInstance(
            IBurpExtenderCallbacks.class.getClassLoader(), new Class<?>[]{IBurpExtenderCallbacks.class},
            (proxy, method, args) -> {
                if (method.getName().equals("createMessageEditor")) {
                    Editor editor = new Editor();
                    editors.add(editor);
                    controllers.add((IMessageEditorController) args[0]);
                    return editor;
                }
                throw new AssertionError("Unexpected callback: " + method.getName());
            });

    public static IHttpRequestResponse message(String host, String value) {
        IHttpService service = new IHttpService() {
            public String getHost() { return host; }
            public int getPort() { return 443; }
            public String getProtocol() { return "https"; }
        };
        HttpReqRespAdapter message = HttpReqRespAdapter.from(service,
                ("GET /" + value + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n").getBytes(StandardCharsets.UTF_8));
        message.setResponse(("HTTP/1.1 200 OK\r\n\r\n" + value).getBytes(StandardCharsets.UTF_8));
        return message;
    }

    public static final class Editor implements IMessageEditor {
        private byte[] bytes = new byte[0];
        private final JTextArea component = new JTextArea();
        public Component getComponent() { return component; }
        public void setMessage(byte[] value, boolean isRequest) {
            assertTrue("Burp editors must be updated on EDT", SwingUtilities.isEventDispatchThread());
            bytes = value.clone();
            component.setText(new String(bytes, StandardCharsets.UTF_8));
        }
        public byte[] getMessage() { return bytes; }
        public boolean isMessageModified() { return false; }
        public byte[] getSelectedData() { return null; }
        public int[] getSelectionBounds() { return new int[]{0, 0}; }
    }
}
