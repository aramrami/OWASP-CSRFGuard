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
import org.owasp.csrfguard.token.TokenUtils;

import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;

/**
 * This class handles with logic between session and token manipulation.
 *
 * Should only be used from org.owasp.csrfguard.token.service.impl.SessionBoundTokenService and org.owasp.csrfguard.CsrfGuardHttpSessionListener
 */
public final class SessionUtils {

    private SessionUtils() {}

    public static final String PAGE_TOKENS_KEY = "Owasp_CsrfGuard_Pages_Tokens_Key";

    private static final String TOKENS_GENERATED = "org.owasp.csrfguard.TokensGenerated";

    public static boolean areTokensGenerated(final HttpSession session) {
        return session.getAttribute(TOKENS_GENERATED) != null
                && (Boolean) session.getAttribute(TOKENS_GENERATED);
    }

    public static void setTokensGenerated(final HttpSession session) {
        if (session != null) {
            session.setAttribute(TOKENS_GENERATED, true);
        }
    }

    public static Map<String, String> getPageTokens(final HttpSession session) {
        @SuppressWarnings("unchecked")
        final Map<String, String> pageTokens = (Map<String, String>) session.getAttribute(PAGE_TOKENS_KEY);

        if (pageTokens == null) {
            final Map<String, String> emptyMap = new HashMap<>(CsrfGuard.getInstance().getProtectedPages().size());
            session.setAttribute(PAGE_TOKENS_KEY, emptyMap);
            return emptyMap;
        } else {
            return pageTokens;
        }
    }

    public static String getPageToken(final HttpSession session, final String requestUri) {
        final Map<String, String> pageTokens = SessionUtils.getPageTokens(session);
        return pageTokens.get(requestUri);
    }

    public static void generateNewPageToken(final HttpSession session, final String requestUri) {
        final Map<String, String> pageTokens = SessionUtils.getPageTokens(session);
        pageTokens.put(requestUri, TokenUtils.generateRandomToken());
    }

    public static void generatePageTokenIfNotExists(final HttpSession session, final String requestUri) {
        final Map<String, String> pageTokens = SessionUtils.getPageTokens(session);
        pageTokens.computeIfAbsent(requestUri, k -> TokenUtils.generateRandomToken());
    }

    public static void setPageTokens(final HttpSession session, final Map<String, String> pageTokens) {
        if (session != null && pageTokens != null) {
            session.setAttribute(PAGE_TOKENS_KEY, pageTokens);
            setTokensGenerated(session);
        }
    }

    /**
     * Invalidates the session token and the token from the resource that
     * has experienced an access attempt with an invalid token.
     * @param session      - current session
     * @param invalidToken - token send on request (can be a invalid token or a token from another valid resource)
     */
    public static void invalidateTokenForResource(final HttpSession session, final String invalidToken) {
        final Map<String, String> pageTokens = getPageTokens(session);

        final String masterToken = getMasterToken(session);

        if (masterToken.equals(invalidToken)) {
            session.setAttribute(CsrfGuard.getInstance().getSessionKey(), TokenUtils.generateRandomToken());
        }

        // Invalidate request token if it's from another existing resource
        TokenUtils.regenerateUsedPageToken(pageTokens, invalidToken);

        setTokensGenerated(session);
    }

    public static String getMasterToken(final HttpSession session) {
        return (String) session.getAttribute(CsrfGuard.getInstance().getSessionKey());
    }

    public static void generateNewMasterToken(final HttpSession session, final String sessionKey) {
        session.setAttribute(sessionKey, TokenUtils.generateRandomToken());
    }

    public static void rotateAllPageTokens(final HttpSession session) {
        TokenUtils.rotateAllPageTokens(SessionUtils.getPageTokens(session));
    }
}