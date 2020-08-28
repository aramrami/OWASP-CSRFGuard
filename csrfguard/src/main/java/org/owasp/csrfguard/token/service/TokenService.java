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
import org.owasp.csrfguard.session.LogicalSession;
import org.owasp.csrfguard.token.TokenUtils;
import org.owasp.csrfguard.token.storage.TokenHolder;
import org.owasp.csrfguard.token.storage.impl.Token;
import org.owasp.csrfguard.util.CsrfGuardUtils;
import org.owasp.csrfguard.util.MessageConstants;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

public class TokenService {

    private final CsrfGuard csrfGuard;

    public TokenService(final CsrfGuard csrfGuard) {
        this.csrfGuard = csrfGuard;
    }

    /**
     * Invalidates the logical session and removes all tokens from the storage
     *
     * @param logicalSession a not null logical session implementation
     */
    public void invalidate(final LogicalSession logicalSession) {
        final String logicalSessionKey = logicalSession.getKey();

        final TokenHolder tokenHolder = this.csrfGuard.getTokenHolder();

        tokenHolder.remove(logicalSessionKey);

        logicalSession.invalidate();
    }

    /**
     * Returns the master token assigned to the unique identifier extracted from the current request.
     * This identifier could be for example the sessionId of the current user, or the user name extracted from a JWT token
     * <p>
     *
     * @param logicalSessionKey identifies the current logical session uniquely
     * @return the master token
     */
    public String getMasterToken(final String logicalSessionKey) {
        final TokenHolder tokenHolder = this.csrfGuard.getTokenHolder();

        return getMasterToken(tokenHolder, logicalSessionKey);
    }

    /**
     * Return the page tokens if the functionality is enabled and the client has already accessed a protected resource,
     * or if the token pre-creation is enabled.
     * <p>
     * Note: this method returns a copy of the page tokens in order to prevent outside modification.
     * <p>
     *
     * @param logicalSessionKey identifies the current logical session uniquely
     * @return the page tokens or an empty map
     */
    public Map<String, String> getPageTokens(final String logicalSessionKey) {
        final TokenHolder tokenHolder = this.csrfGuard.getTokenHolder();

        return new HashMap<>(tokenHolder.getPageTokens(logicalSessionKey));
    }

    /**
     * Generates master token and page token for the current resource if the token-per-page configuration is enabled
     * <p>
     *
     * @param logicalSessionKey identifies the current logical session uniquely
     * @param requestURI        the URI of the desired HTTP resource
     * @return returns the generated page or master token
     */
    public String generateTokensIfAbsent(final String logicalSessionKey, final String requestURI) {
        final TokenHolder tokenHolder = this.csrfGuard.getTokenHolder();

        return this.csrfGuard.isTokenPerPageEnabled() ? tokenHolder.createPageTokenIfAbsent(logicalSessionKey, requestURI, TokenUtils::generateRandomToken)
                                                      : tokenHolder.createMasterTokenIfAbsent(logicalSessionKey, TokenUtils::generateRandomToken);
    }

    /**
     * Creates master token if it does not exist already.
     *
     * @param logicalSessionKey identifies the current logical session uniquely
     */
    public void createMasterTokenIfAbsent(final String logicalSessionKey) {
        final TokenHolder tokenHolder = this.csrfGuard.getTokenHolder();
        tokenHolder.createMasterTokenIfAbsent(logicalSessionKey, TokenUtils::generateRandomToken);
    }

    /**
     * Generates new random tokens for configured protected pages.
     * This methods creates a new master token if it did not exist previously.
     * Existing page tokens with the same session key will be overwritten.
     *
     * @param logicalSessionKey identifies the current logical session uniquely
     */
    public void generateProtectedPageTokens(final String logicalSessionKey) {
        final HashMap<String, String> generatedPageTokens = this.csrfGuard.getProtectedPages().stream()
                                                                          .collect(Collectors.toMap(Function.identity(),
                                                                                                    k -> TokenUtils.generateRandomToken(),
                                                                                                    (a, b) -> b,
                                                                                                    HashMap::new));
        final TokenHolder tokenHolder = this.csrfGuard.getTokenHolder();

        tokenHolder.createMasterTokenIfAbsent(logicalSessionKey, TokenUtils::generateRandomToken);
        tokenHolder.setPageTokens(logicalSessionKey, generatedPageTokens);
    }

    /**
     * Rotates the used master or the currently requested page token if the token-per-page functionality is enabled.
     *
     * @param logicalSessionKey identifies the current logical session uniquely
     * @param requestURI        the URI of the desired HTTP resource
     * @param usedValidToken    a verified token that has validated the current request
     */
    public void rotateUsedToken(final String logicalSessionKey, final String requestURI, final String usedValidToken) {
        final TokenHolder tokenHolder = this.csrfGuard.getTokenHolder();

        final String masterToken = getMasterToken(tokenHolder, logicalSessionKey);

        if (Objects.nonNull(masterToken) && masterToken.equals(usedValidToken)) {
            tokenHolder.setMasterToken(logicalSessionKey, TokenUtils.generateRandomToken());
        } else {
            if (this.csrfGuard.isTokenPerPageEnabled()) {
                if (usedValidToken.equals(tokenHolder.getPageToken(logicalSessionKey, requestURI))) {
                    tokenHolder.setPageToken(logicalSessionKey, requestURI, TokenUtils.generateRandomToken());
                } else {
                    throw new IllegalStateException("The verified token was not associated to the current resource.");
                }
            } else {
                throw new IllegalStateException("Token-per-page is not enabled and the verified token is not the master token.");
            }
        }
    }

    /**
     * Rotates (re-generates) the master token and all page tokens if the token-per-page functionality is enabled.
     *
     * @param logicalSessionKey identifies the current logical session uniquely
     */
    public void rotateAllTokens(final String logicalSessionKey) {
        final TokenHolder tokenHolder = this.csrfGuard.getTokenHolder();

        tokenHolder.setMasterToken(logicalSessionKey, TokenUtils.generateRandomToken());

        tokenHolder.rotateAllPageTokens(logicalSessionKey);
    }

    /**
     * Returns the master or the page token for the associated resource depending on whether the token-per-page
     * configuration is enabled or not.
     * <p>
     * If the token does not currently exists, it creates a new one.
     * <p>
     *
     * @param logicalSessionKey identifies the current logical session uniquely
     * @param resourceUri       the URI of the desired HTTP resource
     * @return a valid token for the specified resourceUri
     */
    public String getTokenValue(final String logicalSessionKey, final String resourceUri) {
        final TokenHolder tokenHolder = this.csrfGuard.getTokenHolder();

        return this.csrfGuard.isTokenPerPageEnabled() ? tokenHolder.createPageTokenIfAbsent(logicalSessionKey, resourceUri, TokenUtils::generateRandomToken)
                                                      : tokenHolder.createMasterTokenIfAbsent(logicalSessionKey, TokenUtils::generateRandomToken);

    }

    /**
     * Verifies the validity of the current request.
     * <p>
     *
     * @param request           current HTTP Servlet Request
     * @param logicalSessionKey identifies the current logical session uniquely
     * @param masterToken       the master token
     * @return The token used to validate the current request
     * @throws CsrfGuardException if the request does not have a valid token associated
     */
    public String verifyToken(final HttpServletRequest request, final String logicalSessionKey, final String masterToken) throws CsrfGuardException {
        final String tokenName = this.csrfGuard.getTokenName();

        final String tokenFromRequest = this.csrfGuard.isAjaxEnabled() && CsrfGuardUtils.isAjaxRequest(request) ? request.getHeader(tokenName)
                                                                                                                : request.getParameter(tokenName);
        final String usedValidToken;
        if (Objects.isNull(tokenFromRequest)) {
            throw new CsrfGuardException(MessageConstants.REQUEST_MISSING_TOKEN_MSG);
        } else {
            usedValidToken = this.csrfGuard.isTokenPerPageEnabled() ? verifyPageToken(masterToken, tokenFromRequest, logicalSessionKey, request.getRequestURI())
                                                                    : verifyMasterToken(masterToken, tokenFromRequest);
        }

        return usedValidToken;
    }

    private String getMasterToken(final TokenHolder tokenHolder, final String tokenKey) {
        final Token token = tokenHolder.getToken(tokenKey);
        return Objects.nonNull(token) ? token.getMasterToken() : null;
    }

    private String verifyPageToken(final String masterToken, final String tokenFromRequest, final String logicalSessionKey, final String requestURI) throws CsrfGuardException {
        final TokenHolder tokenHolder = this.csrfGuard.getTokenHolder();

        final Token token = tokenHolder.getToken(logicalSessionKey);
        final String pageToken = token.getPageToken(requestURI);

        final String usedValidToken;

        if (pageToken == null) {
            /* if there is no token for the current resource, create it and the rely on the master token for validation */
            tokenHolder.setPageToken(logicalSessionKey, requestURI, TokenUtils.generateRandomToken()); // TODO how this token will get back to the client?

            usedValidToken = verifyMasterToken(masterToken, tokenFromRequest);
        } else {
            if (pageToken.equals(tokenFromRequest)) {
                usedValidToken = tokenFromRequest;
            } else {
                /* TODO Is this necessary? If the Rotate action is registered, the exception handler will call it and re-generate the tokens */
                if (masterToken.equals(pageToken)) {
                    tokenHolder.setMasterToken(logicalSessionKey, TokenUtils.generateRandomToken());
                }

                tokenHolder.regenerateUsedPageToken(logicalSessionKey, tokenFromRequest);

                throw new CsrfGuardException(MessageConstants.MISMATCH_PAGE_TOKEN_MSG);
            }
        }
        return usedValidToken;
    }

    private String verifyMasterToken(final String storedToken, final String tokenFromRequest) throws CsrfGuardException {
        if (storedToken.equals(tokenFromRequest)) {
            return tokenFromRequest;
        } else {
            throw new CsrfGuardException(MessageConstants.MISMATCH_MASTER_TOKEN_MSG);
        }
    }
}
