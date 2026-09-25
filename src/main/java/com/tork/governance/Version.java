package com.tork.governance;

/**
 * SDK version reported on receipts (e.g. {@code tool_result_scan.sdk_version}).
 *
 * <p>Java has no build-time string injection equivalent to the JS SDK's
 * tsup {@code define} (see tork-js-sdk/src/version.ts), so this constant is
 * hand-kept in sync with the {@code <version>} in {@code pom.xml}.</p>
 */
public final class Version {

    /** Current SDK version. Keep in sync with pom.xml's {@code <version>}. */
    public static final String SDK_VERSION = "0.3.0";

    private Version() {
    }
}
