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

package org.owasp.csrfguard.http;

import org.owasp.csrfguard.CsrfGuard;
import org.owasp.csrfguard.CsrfValidator;
import org.owasp.csrfguard.ProtectionResult;
import org.owasp.csrfguard.session.LogicalSession;
import org.owasp.csrfguard.token.service.TokenService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;
import java.util.Objects;

public class InterceptRedirectResponse extends HttpServletResponseWrapper {

    private final HttpServletResponse response;

    private final CsrfGuard csrfGuard;

    private final HttpServletRequest request;

    public InterceptRedirectResponse(final HttpServletResponse response, final HttpServletRequest request, final CsrfGuard csrfGuard) {
        super(response);
        this.response = response;
        this.request = request;
        this.csrfGuard = csrfGuard;
    }

    @Override
    public void sendRedirect(final String location) throws IOException {
        // Remove CR and LF characters to prevent CRLF injection
        final String sanitizedLocation = location.replaceAll("(\\r|\\n|%0D|%0A|%0a|%0d)", "");

        /* ensure token included in redirects */
        final ProtectionResult protectionResult = new CsrfValidator().isProtectedPageAndMethod(sanitizedLocation, "GET");
        if (!sanitizedLocation.contains("://") && protectionResult.isProtected()) {
            // Separate URL fragment from path, e.g. /myPath#myFragment becomes [0]: /myPath [1]: myFragment
            final String[] splitOnFragment = location.split("#", 2);

            final StringBuilder stringBuilder = new StringBuilder();

            if (sanitizedLocation.startsWith("/")) {
                stringBuilder.append(sanitizedLocation);
            } else {
                stringBuilder.append(this.request.getContextPath()).append('/').append(sanitizedLocation);
            }

            if (sanitizedLocation.contains("?")) {
                stringBuilder.append('&');
            } else {
                stringBuilder.append('?');
            }

            // remove any query parameters from the sanitizedLocation
            final String locationUri = sanitizedLocation.split("\\?", 2)[0];

            stringBuilder.append(this.csrfGuard.getTokenName())
                         .append('=')
                         .append(computeTokenValue(locationUri));

            // Add back fragment, if one exists
            if (splitOnFragment.length > 1) {
                stringBuilder.append('#').append(splitOnFragment[1]);
            }

            this.response.sendRedirect(stringBuilder.toString());
        } else {
            this.response.sendRedirect(sanitizedLocation);
        }
    }

    private String computeTokenValue(final String locationUri) {
        final TokenService tokenService = CsrfGuard.getInstance().getTokenService();

        final LogicalSession logicalSession = this.csrfGuard.getLogicalSessionExtractor().extract(this.request);

        return Objects.nonNull(logicalSession) ? tokenService.generateTokensIfAbsent(logicalSession.getKey(), "GET", locationUri) : null;
    }
}
