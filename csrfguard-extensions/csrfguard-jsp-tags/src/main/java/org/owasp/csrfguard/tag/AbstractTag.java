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

package org.owasp.csrfguard.tag;

import org.owasp.csrfguard.CsrfValidator;
import org.owasp.csrfguard.ProtectionResult;

import javax.servlet.jsp.tagext.TagSupport;

public abstract class AbstractTag extends TagSupport {

	private final static long serialVersionUID = 0xadede854;

	public String buildUri(final String uri) {
		return calculateExtendedPageDescriptorUri(normalizeUri(uri));
	}

	/**
	 * @param normalizedUri the current normalizedUri
	 * @return if the protected/un-protected page descriptors were defined using wildcards or regexes, this method
	 * will return the extended page descriptor definition of the normalizedUri, otherwise returns itself
	 */
	private String calculateExtendedPageDescriptorUri(final String normalizedUri) {
		final ProtectionResult protectionResult = new CsrfValidator().isProtectedPage(normalizedUri);

		return protectionResult.isProtected() ? protectionResult.getResourceIdentifier()
											  : normalizedUri;
	}

	private String normalizeUri(final String uri) {
		return uri.startsWith("/") ? uri
								   : this.pageContext.getServletContext().getContextPath() + '/' + uri;
	}
}
