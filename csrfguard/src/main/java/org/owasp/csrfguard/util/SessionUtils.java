package org.owasp.csrfguard.util;

import org.owasp.csrfguard.CsrfGuard;

import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;

/**
 * This class handles with logic between session and token manipulation.
 */
public final class SessionUtils {

    private SessionUtils() {
    }

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

    @SuppressWarnings("unchecked")
    public static Map<String, String> extractPageTokensFromSession(final HttpSession session) {

        final Map<String, String> pageTokens = (Map<String, String>) session.getAttribute(CsrfGuard.PAGE_TOKENS_KEY);

        if (pageTokens != null) {
            return pageTokens;
        }

        return new HashMap<String, String>(CsrfGuard.getInstance().getProtectedPages().size());
    }

    public static void updatePageTokensOnSession(final HttpSession session,
                                                 final Map<String, String> pageTokens) {

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