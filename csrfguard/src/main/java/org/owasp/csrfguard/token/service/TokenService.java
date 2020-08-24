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
package org.owasp.csrfguard.token.service;

import org.owasp.csrfguard.CsrfGuard;
import org.owasp.csrfguard.CsrfGuardException;
import org.owasp.csrfguard.token.storage.TokenHolder;
import org.owasp.csrfguard.token.storage.TokenKeyExtractor;
import org.owasp.csrfguard.util.CsrfGuardUtils;
import org.owasp.csrfguard.util.MessageConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Map;
import java.util.Objects;

/**
 * Parent class for unified usage of different Token Service implementations
 */
public abstract class TokenService {

    // TODO use a TokenHolder on the session and remove SessionUtils?

    private final CsrfGuard csrfGuard;

    public TokenService(final CsrfGuard csrfGuard) {
        this.csrfGuard = csrfGuard;
    }

    public CsrfGuard getCsrfGuard() {
        return this.csrfGuard;
    }

    /**
     * If session based token storage is used, then it invalidates the session,
     * otherwise removes all tokens from the custom storage {@link TokenHolder}, identified by the requests token key, extracted by the {@link TokenKeyExtractor}.
     *
     * @param request current HTTP Servlet Request
     */
    public abstract void invalidate(final HttpServletRequest request);

    /**
     * Creates the following HTTP response header string: <p>"<b>&lt;CSRFGuard Token Name&gt;:&lt;Master Token Value&gt;</b>"</p>
     * <br><p>e.g. "OWASP-CSRFTOKEN:WFE8-7ESO-0AK7-264W-1U18-F2VA-UAYB-HD26"</p>
     *
     * @param request current HTTP Servlet Request
     * @return returns the calculated HTTP response header string
     */
    public String getMasterTokenHeader(final HttpServletRequest request) {
        return CsrfGuard.getInstance().getTokenName() + ':' + getMasterToken(request);
    }

    /**
     * Returns the master token assigned to the unique identifier extracted from the current request.
     * This identifier could be for example the sessionId of the current user, or the user name extracted from a JWT token
     *
     * @param request current HTTP Servlet Request
     * @return the master token
     */
    public abstract String getMasterToken(final HttpServletRequest request);

    /**
     * Return the page tokens if the functionality is enabled and the client has already accessed a protected resource,
     * or if in case of session bound configuration the token pre-creation is enabled.
     *
     * Note: this method returns a copy of the page tokens in order to prevent outside modification.
     *
     * @param request current HTTP Servlet Request
     * @return the page tokens or an empty map
     */
    public abstract Map<String, String> getPageTokens(final HttpServletRequest request);

    /**
     * Generates master token and page token for the current resource if the token-per-page configuration is enabled
     *
     * @param request current HTTP Servlet Request
     */
    public abstract void generateTokensIfNotExists(final HttpServletRequest request);

    /**
     * Creates master token if it does not exist already. This method is only used for the session bound service implementation.
     *
     * @param session the current HTTP session
     */
    public abstract void createMasterTokenIfNotExists(final HttpSession session);

    /**
     * TODO document
     *
     * @param request          current HTTP Servlet Request
     * @param masterToken
     * @param tokenFromRequest
     * @return
     * @throws CsrfGuardException
     */
    public abstract String verifyPageToken(final HttpServletRequest request, final String masterToken, final String tokenFromRequest) throws CsrfGuardException;

    /**
     * Generates a new random master token or overwrites the existing one
     *
     * @param request current HTTP Servlet Request
     */
    public abstract void generateNewMasterToken(final HttpServletRequest request);

    /**
     * Generate or overwrite new random tokens for configured protected pages
     *
     * @param session current HTTP session
     */
    public abstract void generateProtectedPageTokens(final HttpSession session);

    /**
     * Rotates the used master or the currently requested page token if the token-per-page functionality is enabled.
     *
     * @param request        current HTTP Servlet Request
     * @param usedValidToken a verified token that has validated the current request
     */
    public abstract void rotateUsedToken(final HttpServletRequest request, final String usedValidToken);

    /**
     * Rotates (re-generates) the master token and all page tokens if the token-per-page functionality is enabled.
     * @param request  current HTTP Servlet Request
     */
    public abstract void rotateAllTokens(final HttpServletRequest request);

    /**
     * Returns the master or the page token for the associated resource depending on whether the token-per-page
     * configuration is enabled or not.
     * <p>
     * If the token is not currently exists, it creates a new one.
     *
     * @param request current HTTP Servlet Request
     * @param uri     the desired HTTP resource
     * @return a valid token for the specified uri
     */
    public abstract String getTokenValue(final HttpServletRequest request, final String uri);

    /**
     * Verifies the validity of the current request.
     *
     * @param request     current HTTP Servlet Request
     * @param masterToken the master token
     * @return The token used to validate the current request
     * @throws CsrfGuardException if the request does not have a valid token associated
     */
    public String verifyToken(final HttpServletRequest request, final String masterToken) throws CsrfGuardException {
        final CsrfGuard csrfGuard = CsrfGuard.getInstance();
        final String tokenName = csrfGuard.getTokenName();

        final String tokenFromRequest = csrfGuard.isAjaxEnabled() && CsrfGuardUtils.isAjaxRequest(request) ? request.getHeader(tokenName)
                                                                                                           : request.getParameter(tokenName);
        final String usedValidToken;
        if (Objects.isNull(tokenFromRequest)) {
            throw new CsrfGuardException(MessageConstants.REQUEST_MISSING_TOKEN_MSG);
        } else {
            usedValidToken = csrfGuard.isTokenPerPageEnabled() ? verifyPageToken(request, masterToken, tokenFromRequest)
                                                               : verifyMasterToken(request, masterToken, tokenFromRequest);
        }

        return usedValidToken;
    }

    protected String verifyMasterToken(final HttpServletRequest request, final String storedToken, final String tokenFromRequest) throws CsrfGuardException {
        if (storedToken.equals(tokenFromRequest)) {
            return tokenFromRequest;
        } else {
            /* TODO Is this necessary? If the Rotate action is registered, the exception handler will call it and re-generate the tokens */
            generateNewMasterToken(request);

            throw new CsrfGuardException(MessageConstants.MISMATCH_MASTER_TOKEN_MSG);
        }
    }
}
