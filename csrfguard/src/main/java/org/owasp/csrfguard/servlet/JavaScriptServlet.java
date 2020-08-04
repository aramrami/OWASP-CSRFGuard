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

package org.owasp.csrfguard.servlet;

import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.owasp.csrfguard.CsrfGuard;
import org.owasp.csrfguard.CsrfGuardServletContextListener;
import org.owasp.csrfguard.log.LogLevel;
import org.owasp.csrfguard.util.CsrfGuardUtils;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public final class JavaScriptServlet extends HttpServlet {

	private static final long serialVersionUID = -1459584282530150483L;
	
	private static final String TOKEN_NAME_IDENTIFIER = "%TOKEN_NAME%";
	
	private static final String TOKEN_VALUE_IDENTIFIER = "%TOKEN_VALUE%";
	
	private static final String DOMAIN_ORIGIN_IDENTIFIER = "%DOMAIN_ORIGIN%";
	
	private static final String DOMAIN_STRICT_IDENTIFIER = "%DOMAIN_STRICT%";
	
	private static final String INJECT_INTO_XHR_IDENTIFIER = "%INJECT_XHR%";
	
	private static final String INJECT_INTO_FORMS_IDENTIFIER = "%INJECT_FORMS%";

	private static final String INJECT_GET_FORMS_IDENTIFIER = "%INJECT_GET_FORMS%";
	
	private static final String INJECT_FORM_ATTRIBUTES_IDENTIFIER = "%INJECT_FORM_ATTRIBUTES%";
	
	private static final String INJECT_INTO_ATTRIBUTES_IDENTIFIER = "%INJECT_ATTRIBUTES%";
	
	private static final String CONTEXT_PATH_IDENTIFIER = "%CONTEXT_PATH%";
	
	private static final String SERVLET_PATH_IDENTIFIER = "%SERVLET_PATH%";
	
	private static final String X_REQUESTED_WITH_IDENTIFIER = "%X_REQUESTED_WITH%";
	
	private static final String TOKENS_PER_PAGE_IDENTIFIER = "%TOKENS_PER_PAGE%";
	
	private static final String UNPROTECTED_EXTENSIONS_IDENTIFIER = "%UNPROTECTED_EXTENSIONS%";
	
	private static ServletConfig servletConfig = null;

	/**
	 *  whitelist the javascript servlet from csrf errors
	 */
	private static final Set<String> javascriptUris = new HashSet<>();

	public static ServletConfig getStaticServletConfig() {
		return servletConfig;
	}

	@Override
	public void init(final ServletConfig theServletConfig) {
		servletConfig = theServletConfig;
		// print again since it might change based on servlet config of javascript servlet
		CsrfGuardServletContextListener.printConfigIfConfigured(servletConfig.getServletContext(),
																"Printing properties after JavaScript servlet, note, the javascript properties have now been initialized: ");
	}

	@Override
	public void doGet(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
		final String refererHeader = request.getHeader("referer");
		boolean hasError = false;
		final Pattern javascriptRefererPattern = CsrfGuard.getInstance().getJavascriptRefererPattern();
		if (refererHeader != null && !javascriptRefererPattern.matcher(refererHeader).matches()) {
			CsrfGuard.getInstance().getLogger().log(LogLevel.Error, String.format("Referer domain %s does not match regex: %s", refererHeader, javascriptRefererPattern.pattern()));
			response.sendError(404);
			hasError = true;
		}
			
		if (refererHeader != null && CsrfGuard.getInstance().isJavascriptRefererMatchDomain()) {
			final boolean isJavascriptRefererMatchProtocol = CsrfGuard.getInstance().isJavascriptRefererMatchProtocol();
			// this is something like http://something.com/path or https://something.com/path
			final String url = request.getRequestURL().toString();
			final String requestProtocolAndDomain = CsrfGuardUtils.httpProtocolAndDomain(url, isJavascriptRefererMatchProtocol);
			final String refererProtocolAndDomain = CsrfGuardUtils.httpProtocolAndDomain(refererHeader, isJavascriptRefererMatchProtocol);
			if (!refererProtocolAndDomain.equals(requestProtocolAndDomain)) {
				CsrfGuard.getInstance().getLogger().log(LogLevel.Error, String.format("Referer domain %s does not match request domain: %s", refererHeader, url));
				hasError = true;
				response.sendError(404);
			}
		}

		if (!hasError) {
			
			// save this path so javascript is whitelisted
			final String javascriptPath = request.getContextPath() + request.getServletPath();
			
			// don't know why there would be more than one... hmmm
			if (javascriptUris.size() < 100) {
				javascriptUris.add(javascriptPath);
			}
			
			writeJavaScript(request, response);
		}
	}

	/**
	 * whitelist the javascript servlet from csrf errors
	 * @return the javascriptUris
	 */
	public static Set<String> getJavascriptUris() {
		return javascriptUris;
	}

	@Override
	public void doPost(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
		final CsrfGuard csrfGuard = CsrfGuard.getInstance();
		final String isFetchCsrfToken = request.getHeader("FETCH-CSRF-TOKEN");
		
		if (csrfGuard != null && isFetchCsrfToken != null){
			fetchCsrfToken(request, response);
		} else {
			if (csrfGuard != null && csrfGuard.isTokenPerPageEnabled()) {
				writePageTokens(request, response);
			} else {
				response.sendError(404);
			}
		}
	}

	private void fetchCsrfToken(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
		final HttpSession session = request.getSession(true);
		final CsrfGuard csrfGuard = CsrfGuard.getInstance();
		final String token_name = csrfGuard.getTokenName();
		final String token_value = (String) session.getAttribute(csrfGuard.getSessionKey());
		final String token_pair = token_name + ":" + token_value;

		/* setup headers */
		response.setContentType("text/plain");

		/* write dynamic javascript */
		response.getWriter().write(token_pair);
	}

	private void writePageTokens(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
		final HttpSession session = request.getSession(true);
		@SuppressWarnings("unchecked")
		final Map<String, String> pageTokens = (Map<String, String>) session.getAttribute(CsrfGuard.PAGE_TOKENS_KEY);
		final String pageTokensString = (pageTokens != null ? parsePageTokens(pageTokens) : StringUtils.EMPTY);

		/* setup headers */
		response.setContentType("text/plain");
		response.setContentLength(pageTokensString.length());

		/* write dynamic javascript */
		response.getWriter().write(pageTokensString);
	}

	private void writeJavaScript(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
		final HttpSession session = request.getSession(true);
		final CsrfGuard csrfGuard = CsrfGuard.getInstance();

		/* cannot cache if rotate or token-per-page is enabled */
		if (csrfGuard.isRotateEnabled() || csrfGuard.isTokenPerPageEnabled()) {
			response.setHeader("Cache-Control", "no-cache, no-store");
			response.setHeader("Pragma", "no-cache");
			response.setHeader("Expires", "0");
		} else {
			response.setHeader("Cache-Control", CsrfGuard.getInstance().getJavascriptCacheControl());
		}

		response.setContentType("text/javascript");

		/* build dynamic javascript */
		String code = CsrfGuard.getInstance().getJavascriptTemplateCode();

		code = code.replace(TOKEN_NAME_IDENTIFIER, StringUtils.defaultString(csrfGuard.getTokenName()))
				   .replace(TOKEN_VALUE_IDENTIFIER, StringUtils.defaultString((String) session.getAttribute(csrfGuard.getSessionKey())))
				   .replace(INJECT_INTO_FORMS_IDENTIFIER, Boolean.toString(csrfGuard.isJavascriptInjectIntoForms()))
				   .replace(INJECT_GET_FORMS_IDENTIFIER, Boolean.toString(csrfGuard.isJavascriptInjectGetForms()))
				   .replace(INJECT_FORM_ATTRIBUTES_IDENTIFIER, Boolean.toString(csrfGuard.isJavascriptInjectFormAttributes()))
				   .replace(INJECT_INTO_ATTRIBUTES_IDENTIFIER, Boolean.toString(csrfGuard.isJavascriptInjectIntoAttributes()))
				   .replace(INJECT_INTO_XHR_IDENTIFIER, String.valueOf(csrfGuard.isAjaxEnabled()))
				   .replace(TOKENS_PER_PAGE_IDENTIFIER, String.valueOf(csrfGuard.isTokenPerPageEnabled()))
				   .replace(UNPROTECTED_EXTENSIONS_IDENTIFIER, String.valueOf(csrfGuard.getJavascriptUnprotectedExtensions()))
				   .replace(DOMAIN_ORIGIN_IDENTIFIER, ObjectUtils.defaultIfNull(csrfGuard.getDomainOrigin(), StringUtils.defaultString(parseDomain(request.getRequestURL()))))
				   .replace(DOMAIN_STRICT_IDENTIFIER, Boolean.toString(csrfGuard.isJavascriptDomainStrict()))
				   .replace(CONTEXT_PATH_IDENTIFIER, StringUtils.defaultString(request.getContextPath()))
				   .replace(SERVLET_PATH_IDENTIFIER, StringUtils.defaultString(request.getContextPath() + request.getServletPath()))
				   .replace(X_REQUESTED_WITH_IDENTIFIER, StringUtils.defaultString(csrfGuard.getJavascriptXrequestedWith()));

		/* write dynamic javascript */
		response.getWriter().write(code);
	}

	private String parsePageTokens(final Map<String, String> pageTokens) {
		return pageTokens.entrySet().stream().map(e -> e.getKey() + ':' + e.getValue()).collect(Collectors.joining(","));
	}

	private String parseDomain(final StringBuffer url) {
		try {
			return new URL(url.toString()).getHost();
		} catch (final MalformedURLException e) {
			// Should not occur. javax.servlet.http.HttpServletRequest.getRequestURL should only returns valid URLs.
			return "INVALID_URL: " + url.toString();
		}
	}
}
