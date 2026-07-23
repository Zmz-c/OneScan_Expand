package burp.vaycore.common.helper;

import org.junit.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class DataTableItemLoaderTest {

    @Test
    @SuppressWarnings("unchecked")
    public void flushWaitsForAnInFlightBatchCallback() throws Exception {
        CountDownLatch callbackEntered = new CountDownLatch(1);
        CountDownLatch releaseCallback = new CountDownLatch(1);
        CountDownLatch flushStarted = new CountDownLatch(1);
        CountDownLatch flushReturned = new CountDownLatch(1);
        AtomicReference<Throwable> failure = new AtomicReference<>();

        DataTableItemLoader<String> loader = new DataTableItemLoader<>(items -> {
            callbackEntered.countDown();
            try {
                if (!releaseCallback.await(2, TimeUnit.SECONDS)) {
                    throw new AssertionError("callback release timed out");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AssertionError(e);
            }
        }, 500);

        Field queueField = DataTableItemLoader.class.getDeclaredField("mDataQueue");
        queueField.setAccessible(true);
        ((ConcurrentLinkedQueue<String>) queueField.get(loader)).offer("queued");
        Method runMethod = DataTableItemLoader.class.getDeclaredMethod("run");
        runMethod.setAccessible(true);

        Thread batchThread = new Thread(() -> invoke(runMethod, loader, failure), "loader-batch-test");
        batchThread.start();
        assertTrue(callbackEntered.await(2, TimeUnit.SECONDS));

        Thread flushThread = new Thread(() -> {
            flushStarted.countDown();
            try {
                loader.flush();
            } catch (Throwable error) {
                failure.compareAndSet(null, error);
            } finally {
                flushReturned.countDown();
            }
        }, "loader-flush-test");
        flushThread.start();

        assertTrue(flushStarted.await(2, TimeUnit.SECONDS));
        assertFalse("flush crossed an unfinished callback", flushReturned.await(150, TimeUnit.MILLISECONDS));
        releaseCallback.countDown();
        assertTrue(flushReturned.await(2, TimeUnit.SECONDS));
        batchThread.join(2000);
        flushThread.join(2000);
        assertFalse(batchThread.isAlive());
        assertFalse(flushThread.isAlive());
        assertNull(failure.get());
    }

    private static void invoke(Method method, Object target, AtomicReference<Throwable> failure) {
        try {
            method.invoke(target);
        } catch (Throwable error) {
            failure.compareAndSet(null, error);
        }
    }
}