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
package org.owasp.csrfguard;

import org.apache.commons.lang3.StringUtils;
import org.owasp.csrfguard.action.IAction;
import org.owasp.csrfguard.log.ILogger;
import org.owasp.csrfguard.log.LogLevel;
import org.owasp.csrfguard.servlet.JavaScriptServlet;
import org.owasp.csrfguard.session.LogicalSession;
import org.owasp.csrfguard.token.businessobject.TokenBO;
import org.owasp.csrfguard.token.mapper.TokenMapper;
import org.owasp.csrfguard.token.service.TokenService;
import org.owasp.csrfguard.token.transferobject.TokenTO;
import org.owasp.csrfguard.util.CsrfGuardUtils;
import org.owasp.csrfguard.util.MessageConstants;
import org.owasp.csrfguard.util.RegexValidationUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Objects;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;

public final class CsrfValidator {

    private final CsrfGuard csrfGuard;

    public CsrfValidator() {
        this.csrfGuard = CsrfGuard.getInstance();
    }

    public boolean isValid(final HttpServletRequest request, final HttpServletResponse response) {
        final boolean isValid;

        final ILogger logger = this.csrfGuard.getLogger();
        final String normalizedResourceURI = CsrfGuardUtils.normalizeResourceURI(request);
        final ProtectionResult protectionResult = isProtectedPageAndMethod(request);
        if (protectionResult.isProtected()) {
            logger.log(LogLevel.Debug, String.format("CSRFGuard analyzing protected resource: '%s'", normalizedResourceURI));
            isValid = isTokenValidInRequest(request, response, protectionResult.getResourceIdentifier());
        } else {
            logger.log(LogLevel.Debug, String.format("Unprotected page: %s", normalizedResourceURI));
            isValid = true;
        }

        return isValid;
    }

    public ProtectionResult isProtectedPageAndMethod(final String page, final String method) {
        final String normalizedResourceUri = CsrfGuardUtils.normalizeResourceURI(page);
        final ProtectionResult protectionResult = isProtectedPage(normalizedResourceUri);

        return (protectionResult.isProtected() && isProtectedMethod(method)) ? protectionResult
                                                                             : new ProtectionResult(false, normalizedResourceUri);
    }

    public ProtectionResult isProtectedPage(final String normalizedResourceUri) {
        final ProtectionResult protectionResult;

        if (JavaScriptServlet.getJavascriptUris().contains(normalizedResourceUri)) {
            /* if this is a javascript page, let it go through */
            protectionResult = new ProtectionResult(false, normalizedResourceUri);
        } else if (this.csrfGuard.isProtectEnabled()) {
            /* all links are unprotected, except the ones that were explicitly specified */
            protectionResult = isUriMatch(normalizedResourceUri, this.csrfGuard.getProtectedPages(), v -> v, false);
        } else {
            /* all links are protected, except the ones were explicitly excluded */
            protectionResult = isUriMatch(normalizedResourceUri, this.csrfGuard.getUnprotectedPages(), v -> new ProtectionResult(false, v.getResourceIdentifier()), true);
        }
        return protectionResult;
    }

    private static boolean isUriPathMatch(final String configuredPageUri, final String requestUri) {
        return configuredPageUri.equals("/*") || (configuredPageUri.endsWith("/*") && (configuredPageUri.regionMatches(0, requestUri, 0, configuredPageUri.length() - 2)
                                                                                   && ((requestUri.length() == (configuredPageUri.length() - 2)) || ('/' == requestUri.charAt(configuredPageUri.length() - 2)))));
    }

    /**
     * FIXME: taken from Tomcat - <a href="https://github.com/apache/tomcat/blob/master/java/org/apache/catalina/core/ApplicationFilterFactory.java">ApplicationFilterFactory#matchFiltersURL</a>
     */
    private static boolean isExtensionMatch(final String testPath, final String requestPath) {
        final boolean result;
        if (StringUtils.startsWith(testPath, "*.")) {
            final int slash = requestPath.lastIndexOf('/');
            final int period = requestPath.lastIndexOf('.');

            if ((slash >= 0)
                && (period > slash)
                && (period != requestPath.length() - 1)
                && ((requestPath.length() - period) == (testPath.length() - 1))) {
                result = testPath.regionMatches(2, requestPath, period + 1, testPath.length() - 2);
            } else {
                result = false;
            }
        } else {
            result = false;
        }

        return result;
    }

    private ProtectionResult isUriMatch(final String normalizedResourceUri, final Set<String> pages, final UnaryOperator<ProtectionResult> operator, final boolean isProtected) {
        for (final String page : pages) {
            final ProtectionResult protectionResult = isUriMatch(page, normalizedResourceUri);
            if (protectionResult.isProtected()) {
                return operator.apply(protectionResult);
            }
        }
        return new ProtectionResult(isProtected, normalizedResourceUri);
    }

    private TokenService getTokenService() {
        return new TokenService(this.csrfGuard);
    }

    private ProtectionResult isProtectedPageAndMethod(final HttpServletRequest request) {
        return isProtectedPageAndMethod(request.getRequestURI(), request.getMethod());
    }

    /**
     * Whether or not the HTTP method is protected, i.e. should be checked for token.
     *
     * @param method The method to check for protection status
     * @return true when the given method name is in the protected methods set and not in the unprotected methods set
     */
    private boolean isProtectedMethod(final String method) {
        boolean isProtected = true;

        final Set<String> protectedMethods = this.csrfGuard.getProtectedMethods();
        if (!protectedMethods.isEmpty() && !protectedMethods.contains(method)) {
            isProtected = false;
        }

        final Set<String> unprotectedMethods = this.csrfGuard.getUnprotectedMethods();
        if (!unprotectedMethods.isEmpty() && unprotectedMethods.contains(method)) {
            isProtected = false;
        }

        return isProtected;
    }

    /**
     * @param configuredPageUri the pattern to match.
     * @param requestUri        the current request path.
     * @return {@code true} if {@code requestUri} matches {@code configuredPageUri}.
     */
    private ProtectionResult isUriMatch(final String configuredPageUri, final String requestUri) {
        if (Objects.nonNull(configuredPageUri)) {
            if (configuredPageUri.equals(requestUri) || isUriPathMatch(configuredPageUri, requestUri) || isExtensionMatch(configuredPageUri, requestUri)) {
                return new ProtectionResult(true, requestUri);
            } else if (isUriRegexMatch(configuredPageUri, requestUri)) {
                return new ProtectionResult(true, configuredPageUri);
            } else {
                return new ProtectionResult(false, requestUri);
            }
        } else {
            return new ProtectionResult(false, requestUri);
        }
    }

    private boolean isUriRegexMatch(final String configuredPageUri, final String requestUri) {
        return RegexValidationUtil.isTestPathRegex(configuredPageUri) && this.csrfGuard.getRegexPatternCache().computeIfAbsent(configuredPageUri, k -> Pattern.compile(configuredPageUri))
                                                                                       .matcher(requestUri)
                                                                                       .matches();
    }

    private boolean isTokenValidInRequest(final HttpServletRequest request, final HttpServletResponse response, final String resourceIdentifier) {
        boolean isValid = false;

        final CsrfGuard csrfGuard = CsrfGuard.getInstance();
        final LogicalSession logicalSession = csrfGuard.getLogicalSessionExtractor().extract(request);

        if (Objects.nonNull(logicalSession)) {
            final TokenService tokenService = getTokenService();
            final String logicalSessionKey = logicalSession.getKey();
            final String masterToken = tokenService.getMasterToken(logicalSessionKey);

            if (Objects.nonNull(masterToken)) {
                try {
                    final TokenBO tokenBO = tokenService.verifyToken(request, resourceIdentifier, logicalSessionKey, masterToken);

                    final TokenTO tokenTO = csrfGuard.isRotateEnabled(request) ? tokenService.rotateUsedToken(logicalSessionKey, resourceIdentifier, tokenBO)
                                                                               : TokenMapper.toTransferObject(tokenBO);

                    CsrfGuardUtils.addResponseTokenHeader(csrfGuard, request, response, tokenTO);

                    isValid = true;
                } catch (final CsrfGuardException e) {
                    callActionsOnError(request, response, e);
                }
            } else {
                callActionsOnError(request, response, new CsrfGuardException(MessageConstants.TOKEN_MISSING_FROM_STORAGE_MSG));
            }
        } else {
            callActionsOnError(request, response, new CsrfGuardException(MessageConstants.TOKEN_MISSING_FROM_STORAGE_MSG));
        }

        return isValid;
    }

    /**
     * Invoked when there was a CsrfGuardException such as a token mismatch error.
     * Calls the configured actions.
     *
     * @param request            The HttpServletRequest
     * @param response           The HttpServletResponse
     * @param csrfGuardException The exception that triggered the actions call. Passed to the action.
     * @see IAction#execute(HttpServletRequest, HttpServletResponse, CsrfGuardException, CsrfGuard)
     */
    private void callActionsOnError(final HttpServletRequest request, final HttpServletResponse response, final CsrfGuardException csrfGuardException) {
        for (final IAction action : this.csrfGuard.getActions()) {
            try {
                action.execute(request, response, csrfGuardException, this.csrfGuard);
            } catch (final CsrfGuardException exception) {
                this.csrfGuard.getLogger().log(LogLevel.Error, exception);
            }
        }
    }
}
