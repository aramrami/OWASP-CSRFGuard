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

package org.owasp.csrfguard.action;

import org.apache.commons.lang3.StringUtils;
import org.owasp.csrfguard.CsrfGuard;
import org.owasp.csrfguard.CsrfGuardException;
import org.owasp.csrfguard.log.LogLevel;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;

public final class Log extends AbstractAction {

    private static final long serialVersionUID = 8238761463376338707L;

    @Override
    public void execute(final HttpServletRequest request, final HttpServletResponse response, final CsrfGuardException csrfe, final CsrfGuard csrfGuard) throws CsrfGuardException {
        String logMessage = getParameter("Message");

        /* Exception Information */
        logMessage = logMessage.replace("%exception%", String.valueOf(csrfe))
                               .replace("%exception_message%", csrfe.getLocalizedMessage());

        /* Remote Network Information */
        logMessage = logMessage.replace("%remote_ip%", StringUtils.defaultString(request.getRemoteAddr()))
                               .replace("%remote_host%", StringUtils.defaultString(request.getRemoteHost()))
                               .replace("%remote_port%", String.valueOf(request.getRemotePort()));

        /* Local Network Information */
        logMessage = logMessage.replace("%local_ip%", StringUtils.defaultString(request.getLocalAddr()))
                               .replace("%local_host%", StringUtils.defaultString(request.getLocalName()))
                               .replace("%local_port%", String.valueOf(request.getLocalPort()));

        /* Requested Resource Information */
        logMessage = logMessage.replace("%request_method%", StringUtils.defaultString(request.getMethod()))
                               .replace("%request_uri%", StringUtils.defaultString(request.getRequestURI()))
                               .replace("%request_url%", request.getRequestURL().toString());

        logMessage = logMessage.replace("%user%", getUserName(request));

        csrfGuard.getLogger().log(LogLevel.Error, logMessage);
    }

    private String getUserName(final HttpServletRequest request) {
        // JavaEE Principal Information
        String user = request.getRemoteUser();

        if (StringUtils.isBlank(user)) {
            user = (String) request.getAttribute("REMOTE_USER");
        }

        if (StringUtils.isBlank(user)) {
            final Principal userPrincipal = request.getUserPrincipal();
            if (userPrincipal != null) {
                user = userPrincipal.getName();
            }
        }

        if (StringUtils.isBlank(user)) {
            user = "<anonymous>";
        }

        return user;
    }
}
