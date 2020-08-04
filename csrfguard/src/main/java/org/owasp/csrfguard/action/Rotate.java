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

import org.owasp.csrfguard.CsrfGuard;
import org.owasp.csrfguard.CsrfGuardException;
import org.owasp.csrfguard.util.RandomGenerator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class Rotate extends AbstractAction {

	private static final long serialVersionUID = -3164557586544451406L;

	@Override
	public void execute(HttpServletRequest request, HttpServletResponse response, CsrfGuardException csrfe, CsrfGuard csrfGuard) throws CsrfGuardException {
		final HttpSession session = request.getSession(false);

		if (session != null) {
			updateSessionToken(session, csrfGuard);

			if (csrfGuard.isTokenPerPageEnabled()) {
				updatePageTokens(session, csrfGuard);
			}
		}
	}

	private void updateSessionToken(final HttpSession session, final CsrfGuard csrfGuard) throws CsrfGuardException {
		final String token;

		try {
			token = RandomGenerator.generateRandomId(csrfGuard.getPrng(), csrfGuard.getTokenLength());
		} catch (final Exception e) {
			throw new CsrfGuardException(String.format("unable to generate the random token - %s", e.getLocalizedMessage()), e);
		}

		session.setAttribute(csrfGuard.getSessionKey(), token);
	}

	private void updatePageTokens(final HttpSession session, final CsrfGuard csrfGuard) throws CsrfGuardException {
		@SuppressWarnings("unchecked")
		final Map<String, String> pageTokens = (Map<String, String>) session.getAttribute(CsrfGuard.PAGE_TOKENS_KEY);
		final List<String> pages = new ArrayList<>();

		if (pageTokens != null) {
			pages.addAll(pageTokens.keySet());
		}

		for (final String page : pages) {
 			final String token;

			try {
				token = RandomGenerator.generateRandomId(csrfGuard.getPrng(), csrfGuard.getTokenLength());
			} catch (final Exception e) {
				throw new CsrfGuardException(String.format("unable to generate the random token - %s", e.getLocalizedMessage()), e);
			}

			pageTokens.put(page, token);
		}
	}
}
