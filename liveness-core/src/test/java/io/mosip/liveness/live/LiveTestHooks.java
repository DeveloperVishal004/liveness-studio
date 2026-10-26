package io.mosip.liveness.live;

/** Test-source bridge to package-private test hooks of {@link LiveTrialController}. */
public final class LiveTestHooks {
    private LiveTestHooks() {
    }

    public static void onTrialFinishing(Runnable r) {
        LiveTrialController.testHookTrialFinishing = r;
    }
}
