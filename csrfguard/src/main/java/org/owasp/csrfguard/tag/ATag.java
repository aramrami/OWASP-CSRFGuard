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
package org.owasp.csrfguard.tag;

import java.io.*;
import java.util.*;

import javax.servlet.http.*;
import javax.servlet.jsp.*;
import javax.servlet.jsp.tagext.*;

import org.owasp.csrfguard.*;
import org.owasp.csrfguard.util.BrowserEncoder;

public final class ATag extends AbstractUriTag implements DynamicAttributes {

	private final static long serialVersionUID = 0x00202937;
	
	private Map<String, String> attributes = new HashMap<String, String>();

	@Override
	public int doStartTag() {
		CsrfGuard csrfGuard = CsrfGuard.getInstance();
		String tokenValue = csrfGuard.getTokenValue((HttpServletRequest) pageContext.getRequest(), buildUri(attributes.get("href")));
		String tokenName = csrfGuard.getTokenName();

		try {
			pageContext.getOut().write(buildStartHtml(tokenName, tokenValue));
		} catch (IOException e) {
			pageContext.getServletContext().log(e.getLocalizedMessage(), e);
		}

		return EVAL_BODY_INCLUDE;
	}

	@Override
	public int doEndTag() {
		try {
			pageContext.getOut().write("</a>");
		} catch (IOException e) {
			pageContext.getServletContext().log(e.getLocalizedMessage(), e);
		}

		return EVAL_PAGE;
	}

	@Override
	public void setDynamicAttribute(String arg0, String arg1, Object arg2) throws JspException {
		attributes.put(arg1.toLowerCase(), String.valueOf(arg2));
	}

	private String buildStartHtml(String tokenName, String tokenValue) {
		StringBuilder sb = new StringBuilder();

		sb.append("<a ");

		for (String name : attributes.keySet()) {
			String value = attributes.get(name);

			sb.append(BrowserEncoder.encodeForAttribute(name));
			sb.append('=');
			sb.append('"');
			sb.append(BrowserEncoder.encodeForAttribute(value));

			if ("href".equalsIgnoreCase(name)) {
				if (value.indexOf('?') != -1) {
					sb.append('&');
				} else {
					sb.append('?');
				}

				sb.append(tokenName);
				sb.append('=');
				sb.append(tokenValue);
			}

			sb.append('"');
			sb.append(' ');
		}

		sb.append(">");

		return sb.toString();
	}
}
