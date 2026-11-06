package burp.vaycore.ost.ui.widget;

import burp.IHttpRequestResponse;
import burp.vaycore.ost.common.Config;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import javax.swing.SwingUtilities;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.RejectedExecutionException;
import static org.junit.Assert.*;

public class HttpMessageViewTest {
    @Rule public TemporaryFolder temp = new TemporaryFolder();
    @Before public void setup() throws Exception {
        Config.init(temp.newFolder().getAbsolutePath() + File.separator);
    }

    @Test public void keepsControllersIndependentAcrossPanels() throws Exception {
        MessageEditorFixture fixture = new MessageEditorFixture();
        IHttpRequestResponse first = MessageEditorFixture.message("main.test", "main");
        IHttpRequestResponse second = MessageEditorFixture.message("fuzz.test", "fuzz");
        SwingUtilities.invokeAndWait(() -> {
            HttpMessageView main = new HttpMessageView(fixture.callbacks, Runnable::run);
            HttpMessageView fuzz = new HttpMessageView(fixture.callbacks, Runnable::run);
            main.showMessage(first);
            fuzz.showMessage(second);
            assertNotSame(fixture.controllers.get(0), fixture.controllers.get(2));
            assertArrayEquals(first.getRequest(), fixture.editors.get(0).getMessage());
            assertArrayEquals(second.getResponse(), fixture.editors.get(3).getMessage());
            fuzz.showMessage(null);
            assertEquals(0, fixture.editors.get(2).getMessage().length);
            assertArrayEquals(first.getRequest(), main.getRequest());
            assertSame(first.getHttpService(), main.getHttpService());
            assertNull(fuzz.getHttpService());
        });
    }

    @Test public void staleAsyncLoadsCannotOverwriteNewSelectionOrResurrectClearedMessages() throws Exception {
        MessageEditorFixture fixture = new MessageEditorFixture();
        List<Runnable> pending = new ArrayList<>();
        HttpMessageView[] view = new HttpMessageView[1];
        IHttpRequestResponse first = MessageEditorFixture.message("test", "one");
        IHttpRequestResponse second = MessageEditorFixture.message("test", "two");
        SwingUtilities.invokeAndWait(() -> {
            view[0] = new HttpMessageView(fixture.callbacks, pending::add);
            view[0].showMessage(first);
            view[0].showMessage(second);
        });
        pending.get(1).run(); // Complete the newest load first, on a worker.
        pending.get(0).run();
        SwingUtilities.invokeAndWait(() -> {
            assertArrayEquals(second.getRequest(), fixture.editors.get(0).getMessage());
            assertArrayEquals(second.getResponse(), fixture.editors.get(1).getMessage());
            view[0].showMessage(first);
            view[0].showMessage(null);
        });
        pending.get(2).run();
        SwingUtilities.invokeAndWait(() -> {
            assertEquals(0, fixture.editors.get(0).getMessage().length);
            assertEquals(0, fixture.editors.get(1).getMessage().length);
        });
    }

    @Test public void shutdownLoaderDoesNotThrowOnUiThread() throws Exception {
        MessageEditorFixture fixture = new MessageEditorFixture();
        SwingUtilities.invokeAndWait(() -> {
            HttpMessageView view = new HttpMessageView(fixture.callbacks, task -> { throw new RejectedExecutionException(); });
            view.showMessage(MessageEditorFixture.message("test", "one"));
            assertEquals(0, fixture.editors.get(0).getMessage().length);
        });
    }
}
