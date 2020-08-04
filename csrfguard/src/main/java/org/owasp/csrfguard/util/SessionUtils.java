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

package org.owasp.csrfguard.util;

import org.owasp.csrfguard.CsrfGuard;

import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;

/**
 * This class handles with logic between session and token manipulation.
 */
public final class SessionUtils {

    private SessionUtils() {}

    private static final String TOKENS_GENERATED = "org.owasp.csrfguard.TokensGenerated";

    public static boolean tokensGenerated(final HttpSession session) {
        return session.getAttribute(TOKENS_GENERATED) != null
                && (Boolean) session.getAttribute(TOKENS_GENERATED);
    }

    public static void setTokensGenerated(final HttpSession session) {
        if (session != null) {
            session.setAttribute(TOKENS_GENERATED, true);
        }
    }

    public static Map<String, String> extractPageTokensFromSession(final HttpSession session) {
        final Map<String, String> pageTokens = (Map<String, String>) session.getAttribute(CsrfGuard.PAGE_TOKENS_KEY);

        if (pageTokens != null) {
            return pageTokens;
        }

        return new HashMap<>(CsrfGuard.getInstance().getProtectedPages().size());
    }

    public static void updatePageTokensOnSession(final HttpSession session, final Map<String, String> pageTokens) {
        if (session != null && pageTokens != null) {
            session.setAttribute(CsrfGuard.PAGE_TOKENS_KEY, pageTokens);
            setTokensGenerated(session);
        }
    }

    /**
     * Invalidates the session token and the token from the resource that
     * has experienced an access attempt with an invalid token.
     *
     * @param session      - current session
     * @param sessionToken - token from session
     * @param requestToken - token send on request (can be a invalid token or a token from another valid resource)
     */
    public static void invalidateTokenForResource(final HttpSession session,
                                                  final String sessionToken,
                                                  final String requestToken) {

        final Map<String, String> pageTokens = extractPageTokensFromSession(session);

        final String actualSessionToken = getSessionToken(session);

        if (actualSessionToken.equals(sessionToken)) {
            invalidateSessionToken(session);
        }

        // Invalidate request token if it's from another existing resource
        final String existentResource = CsrfGuardUtils.getMapKeyByValue(pageTokens, requestToken);
        if (existentResource != null) {
            pageTokens.put(existentResource, TokenUtils.getRandomToken());
        }

        setTokensGenerated(session);
    }

    /**
     * Overrides the current session token with a new one.
     *
     * @param session - current session
     */
    public static void invalidateSessionToken(final HttpSession session) {
        session.setAttribute(CsrfGuard.getInstance().getSessionKey(), TokenUtils.getRandomToken());
    }

    public static String getSessionToken(final HttpSession session) {
        return (String) session.getAttribute(CsrfGuard.getInstance().getSessionKey());
    }
}