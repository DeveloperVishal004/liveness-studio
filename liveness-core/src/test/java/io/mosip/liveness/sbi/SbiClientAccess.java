package io.mosip.liveness.sbi;

/** Test access to package-private helpers. */
public final class SbiClientAccess {
    private SbiClientAccess() {}

    public static String emptySha256Hex() {
        return SbiClient.emptySha256Hex();
    }
}
