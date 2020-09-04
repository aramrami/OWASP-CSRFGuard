/*
 * The OWASP CSRFGuard Project, BSD License
 * Copyright (c) 2011, Eric Sheridan (eric@infraredsecurity.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     1. Redistributions of source code must retain the above copyright notice,
 *        this list of conditions and the following disclaimer.
 *     2. Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *     3. Neither the name of OWASP nor the names of its contributors may be used
 *        to endorse or promote products derived from this software without specific
 *        prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.owasp.csrfguard.token;

import org.owasp.csrfguard.CsrfGuard;
import org.owasp.csrfguard.exception.CSRFGuardTokenException;
import org.owasp.csrfguard.util.MessageConstants;
import org.owasp.csrfguard.util.RandomGenerator;

import java.util.Map;

public final class TokenUtils {

    private TokenUtils() {}

    /**
     * Create a random token according with configuration.
     *
     * @return a random token
     */
    public static String generateRandomToken() {
        try {
            final CsrfGuard csrfGuard = CsrfGuard.getInstance();
            return RandomGenerator.generateRandomId(csrfGuard.getPrng(), csrfGuard.getTokenLength());
        } catch (final Exception e) {
            final String errorLiteral = MessageConstants.RANDOM_TOKEN_FAILURE_MSG + " - " + "%s";
            throw new CSRFGuardTokenException(String.format(errorLiteral, e.getLocalizedMessage()), e);
        }
    }

    /**
     * TODO is it worth the added performance penalty in case of a large application with a lot of pages? What would be the risk if this would be contextual to the assigned resource?
     * TODO do not modify tokens outside their helper classes/services because it's hard to follow/debug
     * Disposes the current token from all the stored valid page tokens, disregarding to which resource it was assigned and replaces with a newly generated one.
     *
     * @param pageTokens the currently stored, valid page tokens
     * @param tokenFromRequest the token received with the request
     */
    public static void regenerateUsedPageToken(final Map<String, String> pageTokens, final String tokenFromRequest) {
        pageTokens.replaceAll((k, v) -> v.equals(tokenFromRequest) ? generateRandomToken() : v);
    }

    /**
     * TODO do not modify tokens outside their helper classes/services because it's hard to follow/debug
     * Re-generates all the tokens for all the resources (pages).
     * @param pageTokens the currently stored, valid page tokens
     */
    public static void rotateAllPageTokens(final Map<String, String> pageTokens) {
        pageTokens.entrySet().forEach(e -> e.setValue(TokenUtils.generateRandomToken()));
    }
}