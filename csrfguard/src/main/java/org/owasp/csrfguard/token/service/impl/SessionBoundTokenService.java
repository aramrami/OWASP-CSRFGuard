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
import org.owasp.csrfguard.util.MessageConstants;
import org.owasp.csrfguard.util.SessionUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

public class SessionBoundTokenService extends TokenService {

    public SessionBoundTokenService(final CsrfGuard csrfGuard) {
        super(csrfGuard);
    }

    @Override
    public void invalidate(final HttpServletRequest request) {
        final HttpSession session = request.getSession(false);

        if (session != null) {
            session.invalidate();
        }
    }

    @Override
    public String getMasterTokenHeader(final HttpServletRequest request) {
        return CsrfGuard.getInstance().getTokenName() + ':' + getMasterToken(request);
    }

    @Override
    public String getMasterToken(final HttpServletRequest request) {
        final HttpSession session = request.getSession(true);
        return SessionUtils.getMasterToken(session);
    }

    @Override
    public Map<String, String> getPageTokens(final HttpServletRequest request) {
        final HttpSession session = request.getSession(true);
        return new HashMap<>(SessionUtils.getPageTokens(session));
    }

    @Override
    public void generateTokensIfNotExists(final HttpServletRequest request) {
        final String requestURI = request.getRequestURI();

        /* cannot create sessions if response already committed */
        final HttpSession session = request.getSession(false);

        if (session != null) {
            createMasterTokenIfNotExists(session);

            if (getCsrfGuard().isTokenPerPageEnabled()) {
                if (getCsrfGuard().isProtectedPageAndMethod(request)) {
                    SessionUtils.generatePageTokenIfNotExists(session, requestURI);
                }
            }
        }
    }

    @Override
    public void createMasterTokenIfNotExists(final HttpSession session) {
        final String tokenValue = SessionUtils.getMasterToken(session);

        /* Generate a new token and store it in the session. */
        if (tokenValue == null) {
            SessionUtils.generateNewMasterToken(session, getCsrfGuard().getSessionKey());
        }
    }

    @Override
    public String verifyPageToken(final HttpServletRequest request, final String masterToken, final String tokenFromRequest) throws CsrfGuardException {
        final HttpSession session = request.getSession(true);
        final String requestURI = request.getRequestURI();
        final String pageToken = SessionUtils.getPageToken(session, requestURI);

        if (pageToken == null) {
            SessionUtils.generatePageTokenIfNotExists(session, requestURI); // FIXME who and when is going to send this back to the UI?

            verifyMasterToken(request, masterToken, tokenFromRequest);
        } else {
            if (!pageToken.equals(tokenFromRequest)) {
                /* TODO Is this necessary? If the Rotate action is registered, the exception handler will call it and re-generate the tokens */
                SessionUtils.invalidateTokenForResource(session, tokenFromRequest); // FIXME who and when is going to send this back to the UI?
                throw new CsrfGuardException(MessageConstants.MISMATCH_PAGE_TOKEN_MSG);
            }
        }
        return tokenFromRequest;
    }

    @Override
    public void generateNewMasterToken(final HttpServletRequest request) {
        final HttpSession session = request.getSession(true);
        SessionUtils.generateNewMasterToken(session, CsrfGuard.getInstance().getSessionKey());
    }

    @Override
    public void generateProtectedPageTokens(final HttpSession session) {
        final CsrfGuard csrfGuard = CsrfGuard.getInstance();
        final HashMap<String, String> protectedPagesNewTokenMap = csrfGuard.getProtectedPages().stream()
                                                                           .collect(Collectors.toMap(Function.identity(),
                                                                                                     k -> TokenUtils.generateRandomToken(),
                                                                                                     (a, b) -> b,
                                                                                                     HashMap::new));
        SessionUtils.setPageTokens(session, protectedPagesNewTokenMap);
    }

    @Override
    public void rotateUsedToken(final HttpServletRequest request, final String usedValidToken) {
        final String requestURI = request.getRequestURI();
        final HttpSession session = request.getSession(true);

        final String masterToken = SessionUtils.getMasterToken(session);
        if (masterToken.equals(usedValidToken)) {
            SessionUtils.generateNewMasterToken(session, getCsrfGuard().getSessionKey());
        } else {
            if (getCsrfGuard().isTokenPerPageEnabled()) {
                final String pageToken = SessionUtils.getPageToken(session, requestURI);

                if (Objects.nonNull(pageToken) && pageToken.equals(usedValidToken)) {
                    SessionUtils.generateNewPageToken(session, requestURI);
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
        final HttpSession session = request.getSession(false);

        if (Objects.nonNull(session)) {
            SessionUtils.generateNewMasterToken(session, getCsrfGuard().getSessionKey());

            if (getCsrfGuard().isTokenPerPageEnabled()) {
                SessionUtils.rotateAllPageTokens(session);
            }
        }
    }

    @Override
    public String getTokenValue(final HttpServletRequest request, final String uri) {
        final String result;
        final HttpSession session = request.getSession(false);

        if (session != null) {
            if (getCsrfGuard().isTokenPerPageEnabled()) {

                if (getCsrfGuard().isTokenPerPagePrecreate()) {
                    SessionUtils.generatePageTokenIfNotExists(session, uri); // TODO who sends this back to the client?
                }

                result = SessionUtils.getPageToken(session, uri);
            } else {
                result = SessionUtils.getMasterToken(session);
            }
        } else {
            result = null;
        }

        return result;
    }
}
