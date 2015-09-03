/**
 * The OWASP CSRFGuard Project, BSD License
 * Eric Sheridan (eric@infraredsecurity.com), Copyright (c) 2011 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of OWASP nor the names of its contributors may be used
 *       to endorse or promote products derived from this software without specific
 *       prior written permission.
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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.csrfguard.CsrfGuard;
import org.owasp.csrfguard.CsrfGuardException;
import org.owasp.csrfguard.log.LogLevel;
import org.owasp.csrfguard.util.CsrfGuardUtils;

public final class Log extends AbstractAction {

	private static final long serialVersionUID = 8238761463376338707L;

	@Override
	public void execute(HttpServletRequest request, HttpServletResponse response, CsrfGuardException csrfe, CsrfGuard csrfGuard) throws CsrfGuardException {
		String logMessage = getParameter("Message");

		/** Exception Information **/
		logMessage = logMessage.replace("%exception%", String.valueOf(csrfe));
		logMessage = logMessage.replace("%exception_message%", csrfe.getLocalizedMessage());

		/** Remote Network Information **/
		logMessage = logMessage.replace("%remote_ip%", CsrfGuardUtils.defaultString(request.getRemoteAddr()));
		logMessage = logMessage.replace("%remote_host%", CsrfGuardUtils.defaultString(request.getRemoteHost()));
		logMessage = logMessage.replace("%remote_port%", String.valueOf(request.getRemotePort()));

		/** Local Network Information **/
		logMessage = logMessage.replace("%local_ip%", CsrfGuardUtils.defaultString(request.getLocalAddr()));
		logMessage = logMessage.replace("%local_host%", CsrfGuardUtils.defaultString(request.getLocalName()));
		logMessage = logMessage.replace("%local_port%", String.valueOf(request.getLocalPort()));

		/** Requested Resource Information **/
		logMessage = logMessage.replace("%request_method%", CsrfGuardUtils.defaultString(request.getMethod()));
		logMessage = logMessage.replace("%request_uri%", CsrfGuardUtils.defaultString(request.getRequestURI()));
		logMessage = logMessage.replace("%request_url%", request.getRequestURL().toString());

		// JavaEE Principal Information
		String user = request.getRemoteUser();
		if (user == null || "".equals(user.trim())) {
	        user = (String)request.getAttribute("REMOTE_USER");
		}
		if (user == null || "".equals(user.trim())) {
			if (request.getUserPrincipal() != null) {
				user = request.getUserPrincipal().getName();
			}
		}
		if (user != null && !"".equals(user.trim())) {
			logMessage = logMessage.replace("%user%", user);
		} else {
			logMessage = logMessage.replace("%user%", "<anonymous>");
		}

		csrfGuard.getLogger().log(LogLevel.Error, logMessage);
	}
	
}
