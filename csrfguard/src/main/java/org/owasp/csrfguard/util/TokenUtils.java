package org.owasp.csrfguard.util;

import org.owasp.csrfguard.CsrfGuard;

public final class TokenUtils {

    private TokenUtils() {
    }

    /**
     * Create a random token according with configuration.
     *
     * @return a random token
     */
    public static String getRandomToken() {
        return RandomGenerator.generateRandomId(CsrfGuard.getInstance().getPrng(),
                CsrfGuard.getInstance().getTokenLength());
    }

}
