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
package org.owasp.csrfguard.util;

public final class BrowserEncoder {

	private BrowserEncoder() {
		/** enforce use of static methods **/
	}

	@Override
	public Object clone() throws CloneNotSupportedException {
		throw new CloneNotSupportedException();
	}
	
	public static String encodeForHtml(String s) {
		StringBuilder sb = new StringBuilder();
		int len = (s == null ? -1 : s.length());
		
		for(int i=0; i<len; i++) {
			char c = s.charAt(i);
			
			if(c == '&') {
				sb.append("&amp;");
			} else if(c == '<') {
				sb.append("&lt;");
			} else if(c == '>') {
				sb.append("&gt;");
			} else if(c == '"') {
				sb.append("&quot;");
			} else if(c == '\'') {
				sb.append("&#x27;");
			} else if(c == '/') {
				sb.append("&#x2F;");
			} else {
				sb.append(c);
			}
		}
		
		return sb.toString();
	}
	
	public static String encodeForAttribute(String s) {
		StringBuilder sb = new StringBuilder();
		int len = (s == null ? -1 : s.length());
		
		for(int i=0; i<len; i++) {
			char c = s.charAt(i);
			
			if(c < 256 && !Character.isLetterOrDigit((int)c)) {
				sb.append("&#");
				sb.append((int)c);
				sb.append(';');
			} else {
				sb.append(c);
			}
		}
		
		return sb.toString();
	}
	
}
