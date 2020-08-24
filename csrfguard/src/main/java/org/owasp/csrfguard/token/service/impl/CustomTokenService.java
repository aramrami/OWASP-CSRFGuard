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
package org.owasp.csrfguard.token.service.impl;

import org.owasp.csrfguard.CsrfGuard;
import org.owasp.csrfguard.CsrfGuardException;
import org.owasp.csrfguard.token.TokenUtils;
import org.owasp.csrfguard.token.service.TokenService;
import org.owasp.csrfguard.token.storage.TokenHolder;
import org.owasp.csrfguard.token.storage.TokenKeyExtractor;
import org.owasp.csrfguard.token.storage.impl.Token;
import org.owasp.csrfguard.util.MessageConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class CustomTokenService extends TokenService {

    public CustomTokenService(final CsrfGuard csrfGuard) {
        super(csrfGuard);
    }

    @Override
    public void invalidate(final HttpServletRequest request) {
        final String tokenKey = extractTokenKey(request, getCsrfGuard());
        final TokenHolder tokenHolder = getCsrfGuard().getTokenHolder();

        tokenHolder.remove(tokenKey);
    }

    @Override
    public String getMasterTokenHeader(final HttpServletRequest request) {
        return CsrfGuard.getInstance().getTokenName() + ':' + getMasterToken(request);
    }

    @Override
    public String getMasterToken(final HttpServletRequest request) {
        final String tokenKey = extractTokenKey(request, getCsrfGuard());
        final TokenHolder tokenHolder = getCsrfGuard().getTokenHolder();

        return getMasterToken(tokenHolder, tokenKey);
    }

    @Override
    public Map<String, String> getPageTokens(final HttpServletRequest request) {
        final String tokenKey = extractTokenKey(request, getCsrfGuard());
        final TokenHolder tokenHolder = getCsrfGuard().getTokenHolder();

        return new HashMap<>(tokenHolder.getPageTokens(tokenKey));
    }

    @Override
    public void generateTokensIfNotExists(final HttpServletRequest request) {
        final String requestURI = request.getRequestURI();
        final String tokenKey = extractTokenKey(request, getCsrfGuard());
        final TokenHolder tokenHolder = getCsrfGuard().getTokenHolder();
        final Token token = tokenHolder.getToken(tokenKey);

        if (Objects.isNull(token)) {
            generateNewMasterToken(tokenHolder, tokenKey);

            if (getCsrfGuard().isTokenPerPageEnabled()) {
                tokenHolder.setPageToken(tokenKey, requestURI, TokenUtils.generateRandomToken());
            }
        } else {
            if (Objects.isNull(token.getMasterToken())) {
                generateNewMasterToken(tokenHolder, tokenKey);
            }

            if (getCsrfGuard().isTokenPerPageEnabled()) {
                if (Objects.isNull(token.getPageToken(requestURI))) {
                    tokenHolder.setPageToken(tokenKey, requestURI, TokenUtils.generateRandomToken());
                }
            }
        }
    }

    @Override
    public void createMasterTokenIfNotExists(final HttpSession session) {
        /* do nothing, as we are not bound to an HTTP session */
    }

    @Override
    public String verifyPageToken(final HttpServletRequest request, final String masterToken, final String tokenFromRequest) throws CsrfGuardException {
        final TokenHolder tokenHolder = getCsrfGuard().getTokenHolder();
        final String tokenKey = extractTokenKey(request, getCsrfGuard());

        final String requestURI = request.getRequestURI();
        final Token token = tokenHolder.getToken(tokenKey);
        final String pageToken = token.getPageToken(requestURI);

        final String usedValidToken;

        if (pageToken == null) {
            /* if there is no token for the current resource, create it and the rely on the master token for validation */
            tokenHolder.setPageToken(tokenKey, requestURI, TokenUtils.generateRandomToken()); // TODO how this token will get back to the client?

            usedValidToken = verifyMasterToken(request, masterToken, tokenFromRequest);
        } else {
            if (pageToken.equals(tokenFromRequest)) {
                usedValidToken = tokenFromRequest;
            } else {
                /* TODO Is this necessary? If the Rotate action is registered, the exception handler will call it and re-generate the tokens */
                if (masterToken.equals(pageToken)) {
                    generateNewMasterToken(tokenHolder, tokenKey);
                }

                tokenHolder.regenerateUsedPageToken(tokenKey, tokenFromRequest);

                throw new CsrfGuardException(MessageConstants.MISMATCH_PAGE_TOKEN_MSG);
            }
        }

        return usedValidToken;
    }

    @Override
    public void generateNewMasterToken(final HttpServletRequest request) {
        final String tokenKey = extractTokenKey(request, getCsrfGuard());
        final TokenHolder tokenHolder = getCsrfGuard().getTokenHolder();

        generateNewMasterToken(tokenHolder, tokenKey);
    }

    @Override
    public void generateProtectedPageTokens(final HttpSession session) {
        /* do nothing, as we are not bound to an HTTP session */
    }

    @Override
    public void rotateUsedToken(final HttpServletRequest request, final String usedValidToken) {
        final TokenHolder tokenHolder = getCsrfGuard().getTokenHolder();
        final String tokenKey = extractTokenKey(request, getCsrfGuard());

        final String requestURI = request.getRequestURI();
        final String masterToken = getMasterToken(tokenHolder, tokenKey);

        if (masterToken.equals(usedValidToken)) {
            generateNewMasterToken(tokenHolder, tokenKey);
        } else {
            if (getCsrfGuard().isTokenPerPageEnabled()) {
                if (tokenHolder.getPageToken(tokenKey, requestURI).equals(usedValidToken)) {
                    tokenHolder.setPageToken(tokenKey, requestURI, TokenUtils.generateRandomToken());
                } else {
                    throw new IllegalStateException("The verified token was not associated to the current resource.");
                }
            } else {
                throw new IllegalStateException("Token-per-page is not enabled and the verified token is not the master token.");
            }
        }
    }

    @Override
    public void rotateAllTokens(final HttpServletRequest request) {
        final TokenHolder tokenHolder = getCsrfGuard().getTokenHolder();
        final TokenKeyExtractor tokenKeyExtractor = getCsrfGuard().getTokenKeyExtractor();
        final String tokenKey = tokenKeyExtractor.extract(request);

        generateNewMasterToken(tokenHolder, tokenKey);

        tokenHolder.rotateAllPageTokens(tokenKey);
    }

    @Override
    public String getTokenValue(final HttpServletRequest request, final String requestURI) {
        final String tokenValue;

        final TokenHolder tokenHolder = getCsrfGuard().getTokenHolder();
        final String tokenKey = extractTokenKey(request, getCsrfGuard());

        if (getCsrfGuard().isTokenPerPageEnabled()) {
            final String pageToken = tokenHolder.getPageToken(tokenKey, requestURI);

            if (Objects.isNull(pageToken)) {
                final String generateRandomToken = TokenUtils.generateRandomToken();
                tokenHolder.setPageToken(tokenKey, requestURI, generateRandomToken);
                tokenValue = generateRandomToken;
            } else {
                tokenValue = pageToken;
            }
        } else {
            final Token token = tokenHolder.getToken(tokenKey);
            final String masterToken = token.getMasterToken();

            // TODO can/should this happen?
            tokenValue = Objects.isNull(masterToken) ? generateNewMasterToken(tokenHolder, tokenKey)
                                                     : masterToken;
        }
        return tokenValue;
    }

    public String getMasterToken(final TokenHolder tokenHolder, final String tokenKey) {
        return tokenHolder.getToken(tokenKey).getMasterToken();
    }

    private static String generateNewMasterToken(final TokenHolder tokenHolder, final String tokenKey) {
        final String newTokenValue = TokenUtils.generateRandomToken();
        tokenHolder.setMasterToken(tokenKey, newTokenValue);
        return newTokenValue;
    }

    private static String extractTokenKey(final HttpServletRequest request, final CsrfGuard csrfGuard) {
        final TokenKeyExtractor tokenKeyExtractor = csrfGuard.getTokenKeyExtractor();
        return tokenKeyExtractor.extract(request);
    }
}
