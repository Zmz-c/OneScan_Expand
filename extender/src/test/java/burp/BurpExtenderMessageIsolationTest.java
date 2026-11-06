package burp;

import burp.vaycore.ost.bean.TaskData;
import burp.vaycore.ost.common.Config;
import burp.vaycore.ost.ui.widget.HttpMessageView;
import burp.vaycore.ost.ui.widget.MessageEditorFixture;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import javax.swing.SwingUtilities;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import static org.junit.Assert.*;

public class BurpExtenderMessageIsolationTest {
    @Rule public TemporaryFolder temp = new TemporaryFolder();

    @Test @SuppressWarnings("unchecked")
    public void bodyActionsDoNotChangeSelectionAndClearingDoesNotResetRunningScanState() throws Exception {
        Config.init(temp.newFolder().getAbsolutePath() + File.separator);
        BurpExtender extender = new BurpExtender();
        MessageEditorFixture fixture = new MessageEditorFixture();
        IHttpRequestResponse selected = MessageEditorFixture.message("main.test", "selected");
        IHttpRequestResponse other = MessageEditorFixture.message("fuzz.test", "other");
        IExtensionHelpers helpers = (IExtensionHelpers) Proxy.newProxyInstance(IExtensionHelpers.class.getClassLoader(),
                new Class<?>[]{IExtensionHelpers.class}, (proxy, method, args) -> {
                    assertEquals("analyzeResponse", method.getName());
                    int offset = new String((byte[]) args[0], StandardCharsets.UTF_8).indexOf("\r\n\r\n") + 4;
                    return Proxy.newProxyInstance(IResponseInfo.class.getClassLoader(), new Class<?>[]{IResponseInfo.class},
                            (info, getter, unused) -> {
                                assertEquals("getBodyOffset", getter.getName());
                                return offset;
                            });
                });
        IBurpExtenderCallbacks callbacks = (IBurpExtenderCallbacks) Proxy.newProxyInstance(
                IBurpExtenderCallbacks.class.getClassLoader(), new Class<?>[]{IBurpExtenderCallbacks.class},
                (proxy, method, args) -> {
                    assertEquals("getHelpers", method.getName());
                    return helpers;
                });
        set(extender, "mCallbacks", callbacks);
        Set<String> timeouts = (Set<String>) get(extender, "sTimeoutReqHost");
        timeouts.add("existing-scan-state");
        SwingUtilities.invokeAndWait(() -> {
            try {
                HttpMessageView view = new HttpMessageView(fixture.callbacks, Runnable::run);
                set(extender, "mMainMessageView", view);
                TaskData task = new TaskData(); task.setReqResp(selected);
                extender.onChangeSelection(task);
                TaskData otherTask = new TaskData(); otherTask.setReqResp(other);
                assertArrayEquals("other".getBytes(StandardCharsets.UTF_8), extender.getBodyByTaskData(otherTask));
                assertArrayEquals(selected.getRequest(), extender.getRequest());
                assertSame(selected.getHttpService(), extender.getHttpService());
                extender.onChangeSelection(null);
                assertEquals(0, extender.getRequest().length);
                assertTrue(timeouts.contains("existing-scan-state"));
            } catch (Exception e) { throw new RuntimeException(e); }
        });
    }

    private static void set(Object target, String name, Object value) throws Exception {
        Field field = BurpExtender.class.getDeclaredField(name); field.setAccessible(true); field.set(target, value);
    }
    private static Object get(Object target, String name) throws Exception {
        Field field = BurpExtender.class.getDeclaredField(name); field.setAccessible(true); return field.get(target);
    }
}
