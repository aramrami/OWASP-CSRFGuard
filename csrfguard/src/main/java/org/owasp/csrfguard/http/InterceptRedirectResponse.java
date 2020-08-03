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

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.owasp.csrfguard.CsrfGuard;

public class InterceptRedirectResponse extends HttpServletResponseWrapper {

	private HttpServletResponse response = null;

	private CsrfGuard csrfGuard;

	private HttpServletRequest request;

	public InterceptRedirectResponse(HttpServletResponse response, HttpServletRequest request, CsrfGuard csrfGuard) {
		super(response);
		this.response = response;
		this.request = request;
		this.csrfGuard = csrfGuard;
	}

	@Override
	public void sendRedirect(String location) throws IOException {
		// Remove CR and LF characters to prevent CRLF injection
		String sanitizedLocation = location.replaceAll("(\\r|\\n|%0D|%0A|%0a|%0d)", "");
		
		/** ensure token included in redirects **/
		if (!sanitizedLocation.contains("://") && csrfGuard.isProtectedPageAndMethod(sanitizedLocation, "GET")) {
			/** update tokens **/
			csrfGuard.updateTokens(request);
			
			// Separate URL fragment from path, e.g. /myPath#myFragment becomes 
			//[0]: /myPath [1]: myFragment
			String[] splitOnFragement = location.split("#", 2);
			location = splitOnFragement[0];

			StringBuilder sb = new StringBuilder();

			if (!sanitizedLocation.startsWith("/")) {
				sb.append(request.getContextPath() + "/" + sanitizedLocation);
			} else {
				sb.append(sanitizedLocation);
			}
			
			if (sanitizedLocation.contains("?")) {
				sb.append('&');
			} else {
				sb.append('?');
			}

			// remove any query parameters from the sanitizedLocation
			String locationUri = sanitizedLocation.split("\\?", 2)[0];

			sb.append(csrfGuard.getTokenName());
			sb.append('=');
			sb.append(csrfGuard.getTokenValue(request, locationUri));
			
			// Add back fragment, if one exists
			if(splitOnFragement.length > 1) {
				sb.append('#').append(splitOnFragement[1]);
			}

			response.sendRedirect(sb.toString());
		} else {
			response.sendRedirect(sanitizedLocation);
		}
	}
}
