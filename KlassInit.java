import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.CountDownLatch;
import java.util.stream.Stream;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.Arguments;
import static org.junit.jupiter.api.Assertions.*;

class KlassInit {
    private static final int MAX_VTHREAD_COUNT = 8 * Runtime.getRuntime().availableProcessors();

    private static final CountDownLatch finishInvokeStatic1 = new CountDownLatch(1);
    private static final CountDownLatch finishInvokeStatic2 = new CountDownLatch(1);
    private static final CountDownLatch finishInvokeStatic3 = new CountDownLatch(1);
    private static final CountDownLatch finishNew = new CountDownLatch(1);
    private static final CountDownLatch finishGetStatic = new CountDownLatch(1);
    private static final CountDownLatch finishPutStatic = new CountDownLatch(1);
    private static final CountDownLatch finishFailedInit = new CountDownLatch(1);

    public static void main(String[] args) {
        try {
            //Thread.sleep(60_000);
            new KlassInit().testReleaseAtKlassInitInvokeStatic1();
        } catch (Throwable ex) {
            ex.printStackTrace();
        }
    }

    /**
     * Test that threads blocked waiting for klass to be initialized
     * on invokestatic bytecode release the carrier.
     */
    @Test
    void testReleaseAtKlassInitInvokeStatic1() throws Exception {
        class TestClass {
            static {
                try {
                    finishInvokeStatic1.await();
                } catch (InterruptedException e) {}
                System.out.println("VT-" + Thread.currentThread().threadId() + " TestClass static initializer done");
            }
            static void m() {
                System.out.println("VT-" + Thread.currentThread().threadId() + " TestClass.m()");
            }
        }

        Thread[] vthreads = new Thread[MAX_VTHREAD_COUNT];
        CountDownLatch[] started = new CountDownLatch[MAX_VTHREAD_COUNT];
        for (int i = 0; i < MAX_VTHREAD_COUNT; i++) {
            final int id = i;
            started[i] = new CountDownLatch(1);
            vthreads[i] = Thread.ofVirtual().start(() -> {
                //System.out.println("VT-" + Thread.currentThread().threadId() + " thread started");
                started[id].countDown();
                //System.out.println("VT-" + Thread.currentThread().threadId() + " thread started latch count down done");
                TestClass.m();
                //System.out.println("VT-" + Thread.currentThread().threadId() + " thread call TestClass.m() done");
            });
        }
        //System.out.println("pause...");
        //Thread.sleep(60_000);
        for (int i = 0; i < MAX_VTHREAD_COUNT; i++) {
            System.out.println("VT-" + vthreads[i].threadId() + ": waiting for its CountDownLatch, state=" + vthreads[i].getState());
            started[i].await();
            System.out.println("VT-" + vthreads[i].threadId() + " has started (" + i + "/" + MAX_VTHREAD_COUNT + "), state=" + vthreads[i].getState());
        }
        System.out.println("await() done for all threads");
        for (int i = 0; i < MAX_VTHREAD_COUNT; i++) {
            //started[i].await();
            System.out.println("VT-" + Thread.currentThread().threadId() + " awaiting count down latch for VT-" + vthreads[i].threadId());
            await(vthreads[i], Thread.State.WAITING);
        }
        finishInvokeStatic1.countDown();
        for (int i = 0; i < MAX_VTHREAD_COUNT; i++) {
            vthreads[i].join();
        }
    }

    /**
     * Waits for the given thread to reach a given state.
     */
    private void await(Thread thread, Thread.State expectedState) throws InterruptedException {
        Thread.State state = thread.getState();
        System.out.println(Thread.currentThread().threadId() + " awaiting state for " + thread.threadId() + ": " + state);
        while (state != expectedState) {
            assertTrue(state != Thread.State.TERMINATED, "Thread has terminated");
            Thread.sleep(10);
            state = thread.getState();
            System.out.println(Thread.currentThread().threadId() + " awaiting state for " + thread.threadId() + ": " + state);
        }
    }
}
