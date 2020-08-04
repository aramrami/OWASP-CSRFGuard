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

package org.owasp.csrfguard.util;

public final class BrowserEncoder {

	private BrowserEncoder() {
		/* enforce use of static methods */
	}

	@Override
	public Object clone() throws CloneNotSupportedException {
		throw new CloneNotSupportedException();
	}

	public static String encodeForHtml(final String s) {
		final StringBuilder stringBuilder = new StringBuilder();
		final int length = (s == null ? -1 : s.length());

		for (int i = 0; i < length; i++) {
			final char c = s.charAt(i);

			switch (c) {
				case '&':
					stringBuilder.append("&amp;");
					break;
				case '<':
					stringBuilder.append("&lt;");
					break;
				case '>':
					stringBuilder.append("&gt;");
					break;
				case '"':
					stringBuilder.append("&quot;");
					break;
				case '\'':
					stringBuilder.append("&#x27;");
					break;
				case '/':
					stringBuilder.append("&#x2F;");
					break;
				default:
					stringBuilder.append(c);
					break;
			}
		}

		return stringBuilder.toString();
	}

	public static String encodeForAttribute(final String s) {
		final StringBuilder sb = new StringBuilder();
		final int len = (s == null ? -1 : s.length());

		for (int i = 0; i < len; i++) {
			final char c = s.charAt(i);

			if (c < 256 && !Character.isLetterOrDigit((int) c)) {
				sb.append("&#");
				sb.append((int) c);
				sb.append(';');
			} else {
				sb.append(c);
			}
		}

		return sb.toString();
	}
}
