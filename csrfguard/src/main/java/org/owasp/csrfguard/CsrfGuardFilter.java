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

import org.owasp.csrfguard.http.InterceptRedirectResponse;
import org.owasp.csrfguard.log.LogLevel;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public final class CsrfGuardFilter implements Filter {

    private FilterConfig filterConfig = null;

    @Override
    public void destroy() {
        this.filterConfig = null;
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain filterChain) throws IOException, ServletException {
        final CsrfGuard csrfGuard = CsrfGuard.getInstance();

        if (!csrfGuard.isEnabled()) {
            filterChain.doFilter(request, response);
            return;
        }

        if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
            final HttpServletRequest httpRequest = (HttpServletRequest) request;
            final InterceptRedirectResponse httpResponse = new InterceptRedirectResponse((HttpServletResponse) response, httpRequest, csrfGuard);

            if (csrfGuard.isStateless()) {
                filterStateless(filterChain, csrfGuard, httpRequest, httpResponse);
            } else {
                final HttpSession session = httpRequest.getSession(false);

                // if there is no session and we aren't validating when no session exists
                if (session == null && !csrfGuard.isValidateWhenNoSessionExists()) {
                    // If there is no session, no harm can be done
                    filterChain.doFilter(httpRequest, response);
                    return;
                }

                /*if (MultipartHttpServletRequest.isMultipartRequest(httpRequest)) {
				     httpRequest = new MultipartHttpServletRequest(httpRequest);
			    }*/

                if (session != null && (session.isNew() && csrfGuard.isUseNewTokenLandingPage())) {
                    csrfGuard.writeLandingPage(httpRequest, httpResponse);
                } else if (csrfGuard.isValidRequest(httpRequest, httpResponse)) {
                    filterChain.doFilter(httpRequest, httpResponse);
                } else {
                    logInvalidRequest(csrfGuard, httpRequest);
                }
            }

            // FIXME who and when is going to send this back to the UI?
            csrfGuard.getTokenService().generateTokensIfNotExists(httpRequest);
        } else {
            handleNonHttpServletMessages(request, response, filterChain, csrfGuard);
        }
    }

    private void filterStateless(final FilterChain filterChain, final CsrfGuard csrfGuard, final HttpServletRequest httpRequest, final InterceptRedirectResponse httpResponse) throws IOException, ServletException {
        if (csrfGuard.isUseNewTokenLandingPage()) {
            csrfGuard.writeLandingPage(httpRequest, httpResponse);
        } else if (csrfGuard.isValidRequest(httpRequest, httpResponse)) {
            filterChain.doFilter(httpRequest, httpResponse);
        } else {
            logInvalidRequest(csrfGuard, httpRequest);
        }
    }

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        this.filterConfig = filterConfig;
    }

    private void handleNonHttpServletMessages(final ServletRequest request, final ServletResponse response, final FilterChain filterChain, final CsrfGuard csrfGuard) throws IOException, ServletException {
        final String message = String.format("CSRFGuard does not know how to work with requests of class %s ", request.getClass().getName());
        csrfGuard.getLogger().log(LogLevel.Warning, message);
        this.filterConfig.getServletContext().log("[WARNING]" + message);

        filterChain.doFilter(request, response);
    }

    private void logInvalidRequest(final CsrfGuard csrfGuard, final HttpServletRequest httpRequest) {
        final String requestURI = httpRequest.getRequestURI();
        final String remoteAddress = httpRequest.getRemoteAddr();

        csrfGuard.getLogger().log(LogLevel.Warning, String.format("Invalid request: \r\nURI:\r\n%s\r\nRemote Address:%s", requestURI, remoteAddress));
    }
}
