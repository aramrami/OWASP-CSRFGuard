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

import org.owasp.csrfguard.CsrfGuard;
import org.owasp.csrfguard.session.LogicalSession;
import org.owasp.csrfguard.util.BrowserEncoder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.DynamicAttributes;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public final class FormTag extends AbstractUriTag implements DynamicAttributes {

	private final static long serialVersionUID = 0xbefee742;
	
	private final Map<String, String> attributes = new HashMap<>();

	@Override
	public int doStartTag() {
		final CsrfGuard csrfGuard = CsrfGuard.getInstance();
		final String tokenName = csrfGuard.getTokenName();

		final LogicalSession logicalSession = csrfGuard.getLogicalSessionExtractor().extract((HttpServletRequest) this.pageContext.getRequest());
		final String tokenValue = Objects.nonNull(logicalSession) ? csrfGuard.getTokenService().getTokenValue(logicalSession.getKey(), buildUri(this.attributes.get("action"))) : null;

		try {
			this.pageContext.getOut().write(buildStartHtml(tokenName, tokenValue));
		} catch (final IOException e) {
			this.pageContext.getServletContext().log(e.getLocalizedMessage(), e);
		}

		return EVAL_BODY_INCLUDE;
	}

	@Override
	public int doEndTag() {
		try {
			this.pageContext.getOut().write("</form>");
		} catch (final IOException e) {
			this.pageContext.getServletContext().log(e.getLocalizedMessage(), e);
		}

		return EVAL_PAGE;
	}

	@Override
	public void setDynamicAttribute(final String arg0, final String arg1, final Object arg2) throws JspException {
		this.attributes.put(arg1.toLowerCase(), String.valueOf(arg2));
	}

	private String buildStartHtml(final String tokenName, final String tokenValue) {
		final StringBuilder sb = new StringBuilder();

		sb.append("<form ");

		for (final String name : this.attributes.keySet()) {
			final String value = this.attributes.get(name);

			sb.append(BrowserEncoder.encodeForAttribute(name));
			sb.append('=');
			sb.append('"');
			sb.append(BrowserEncoder.encodeForAttribute(value));

			sb.append('"');
			sb.append(' ');
		}

		sb.append('>');
		sb.append("<input type=\"hidden\" name=\"");
		sb.append(tokenName);
		sb.append("\" value=\"");
		sb.append(tokenValue);
		sb.append("\"");
		sb.append("/>");

		return sb.toString();
	}
}
