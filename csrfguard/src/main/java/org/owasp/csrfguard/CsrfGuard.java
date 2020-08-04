/*
 * The OWASP CSRFGuard Project, BSD License
 * Copyright (c) 2011, Eric Sheridan (eric@infraredsecurity.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3. Neither the name of OWASP nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without specific
 *     prior written permission.
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

package org.owasp.csrfguard;

import org.owasp.csrfguard.action.IAction;
import org.owasp.csrfguard.config.*;
import org.owasp.csrfguard.config.overlay.ExpirableCache;
import org.owasp.csrfguard.config.properties.ConfigParameters;
import org.owasp.csrfguard.exception.CSRFGuardTokenException;
import org.owasp.csrfguard.log.ILogger;
import org.owasp.csrfguard.log.LogLevel;
import org.owasp.csrfguard.servlet.JavaScriptServlet;
import org.owasp.csrfguard.util.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public final class CsrfGuard {

	public static final String PAGE_TOKENS_KEY = "Owasp_CsrfGuard_Pages_Tokens_Key";

	private static final String NEW_LINE = "\r\n";

	private Properties properties = null;

	/**
	 * cache the configuration for a minute
	 */
	private static final ExpirableCache<Boolean, ConfigurationProvider> configurationProviderExpirableCache = new ExpirableCache<>(1);

	public CsrfGuard() {}

	private ConfigurationProvider config() {
		if (this.properties == null) {
			return new NullConfigurationProvider();
		}

		ConfigurationProvider configurationProvider = configurationProviderExpirableCache.get(Boolean.TRUE);

		if (configurationProvider == null) {

			synchronized (CsrfGuard.class) {
				configurationProvider = retrieveNewConfig();
			}
		} else if ( !configurationProvider.isCacheable()) {
			/* don't synchronize if not cacheable */
			configurationProvider = retrieveNewConfig();
		}


		return configurationProvider;
	}

	void generatePageTokensForSession(final HttpSession session) {
		final Map<String, String> pageTokens = SessionUtils.extractPageTokensFromSession(session);
		final Set<String> protectedPages = getProtectedPages();

		for (final String protectedResource : protectedPages) {
			pageTokens.put(protectedResource, TokenUtils.getRandomToken());
		}

		SessionUtils.updatePageTokensOnSession(session, pageTokens);
	}

	/**
	 * @return new provider
	 */
	private ConfigurationProvider retrieveNewConfig() {
		final ConfigurationProvider configurationProvider;
		/* lets see what provider we are using */
		final String configurationProviderFactoryClassName = this.properties.getProperty(ConfigParameters.CONFIG_PROVIDER_FACTORY_PROPERTY_NAME, PropertiesConfigurationProviderFactory.class.getName());

		final Class<ConfigurationProviderFactory> configurationProviderFactoryClass = CsrfGuardUtils.forName(configurationProviderFactoryClassName);

		final ConfigurationProviderFactory configurationProviderFactory = CsrfGuardUtils.newInstance(configurationProviderFactoryClass);

		configurationProvider = configurationProviderFactory.retrieveConfiguration(this.properties);
		configurationProviderExpirableCache.put(Boolean.TRUE, configurationProvider);
		return configurationProvider;
	}

	private static class SingletonHolder {
	  public static final CsrfGuard instance = new CsrfGuard();
	}

	public static CsrfGuard getInstance() {
		return SingletonHolder.instance;
	}

	public static void load(final Properties theProperties) {
		getInstance().properties = theProperties;
		configurationProviderExpirableCache.clear();
	}

	public ILogger getLogger() {
		return config().getLogger();
	}

	public String getTokenName() {
		return config().getTokenName();
	}

	public int getTokenLength() {
		return config().getTokenLength();
	}

	public boolean isRotateEnabled() {
		return config().isRotateEnabled();
	}

	public boolean isTokenPerPageEnabled() {
		return config().isTokenPerPageEnabled();
	}

	public boolean isTokenPerPagePrecreate() {
		return config().isTokenPerPagePrecreateEnabled();
	}

	/**
	 * If csrf guard filter should check even if there is no session for the user
	 * Note: this changed in 2014/04/20, the default behavior used to be to
	 * not check if there is no session.  If you want the legacy behavior (if your app
	 * is not susceptible to CSRF if the user has no session), set this to false
	 * @return if true
	 */
	public boolean isValidateWhenNoSessionExists() {
		return config().isValidateWhenNoSessionExists();
	}

	public SecureRandom getPrng() {
		return config().getPrng();
	}

	public String getNewTokenLandingPage() {
		return config().getNewTokenLandingPage();
	}

	public boolean isUseNewTokenLandingPage() {
		return config().isUseNewTokenLandingPage();
	}

	public boolean isAjaxEnabled() {
		return config().isAjaxEnabled();
	}

	public boolean isProtectEnabled() {
		return config().isProtectEnabled();
	}

	/**
	 * @see ConfigurationProvider#isEnabled()
	 * @return if enabled
	 */
	public boolean isEnabled() {
		return config().isEnabled();
	}

	public String getSessionKey() {
		return config().getSessionKey();
	}

	public Set<String> getProtectedPages() {
		return config().getProtectedPages();
	}

	public Set<String> getUnprotectedPages() {
		return config().getUnprotectedPages();
	}

	/**
	 * cache regex patterns here
	 */
	private final Map<String, Pattern> regexPatternCache = new HashMap<>();

	public Set<String> getProtectedMethods () {
		return config().getProtectedMethods();
	}

	public List<IAction> getActions() {
		return config().getActions();
	}

	public String getJavascriptSourceFile() {
		return config().getJavascriptSourceFile();
	}

	/**
	 * @see ConfigurationProvider#isJavascriptInjectFormAttributes()
	 * @return if inject
	 */
	public boolean isJavascriptInjectFormAttributes() {
		return config().isJavascriptInjectFormAttributes();
	}

	/**
	 * @see ConfigurationProvider#isJavascriptInjectGetForms()
	 * @return if inject
	 */
	public boolean isJavascriptInjectGetForms() {
		return config().isJavascriptInjectGetForms();
	}

	public boolean isJavascriptDomainStrict() {
		return config().isJavascriptDomainStrict();
	}

	public boolean isJavascriptRefererMatchProtocol() {
		return config().isJavascriptRefererMatchProtocol();
	}

	public boolean isJavascriptRefererMatchDomain() {
		return config().isJavascriptRefererMatchDomain();
	}

	public String getJavascriptCacheControl() {
		return config().getJavascriptCacheControl();
	}

	public Pattern getJavascriptRefererPattern() {
		return config().getJavascriptRefererPattern();
	}

	public boolean isJavascriptInjectIntoForms() {
		return config().isJavascriptInjectIntoForms();
	}

	public boolean isJavascriptInjectIntoAttributes() {
		return config().isJavascriptInjectIntoAttributes();
	}

	public String getJavascriptXrequestedWith() {
		return config().getJavascriptXrequestedWith();
	}

	public String getJavascriptTemplateCode() {
		return config().getJavascriptTemplateCode();
	}

	public String getJavascriptUnprotectedExtensions() {
		return config().getJavascriptUnprotectedExtensions();
	}

	public String getTokenValue(final HttpServletRequest request) {
		return getTokenValue(request, request.getRequestURI());
	}

	public String getTokenValue(final HttpServletRequest request, final String uri) {
		String tokenValue = null;
		final HttpSession session = request.getSession(false);

		if (session != null) {
			if (isTokenPerPageEnabled()) {

				final Map<String, String> pageTokens = SessionUtils.extractPageTokensFromSession(session);

				if (isTokenPerPagePrecreate()) {
					createPageToken(pageTokens, uri);
				}

				tokenValue = pageTokens.get(uri);
			}

			if (tokenValue == null) {
				tokenValue = (String) session.getAttribute(getSessionKey());
			}
		}

		return tokenValue;
	}

	public boolean isValidRequest(final HttpServletRequest request, final HttpServletResponse response) {
		boolean valid = !isProtectedPageAndMethod(request);
		final HttpSession session = request.getSession(true);
		final String tokenFromSession = (String) session.getAttribute(getSessionKey());

		if (!valid){
			/* print log message - page and method are protected */
		    getLogger().log(String.format("CSRFGuard analyzing request %s", request.getRequestURI()));
		}

		/* sending request to protected resource - verify token */
		if (tokenFromSession != null && !valid) {
			try {
				verifyToken(request);
				valid = true;
			} catch (final CsrfGuardException csrfe) {
				callActionsOnError(request, response, csrfe);
			}

			/* rotate session and page tokens */
			if (!isAjaxRequest(request) && isRotateEnabled()) {
				rotateTokens(request);
			}
			/* expected token in session - bad state and not valid */
		} else if (tokenFromSession == null && !valid) {
			try {
				throw new CsrfGuardException(MessageConstants.SESSION_TOKEN_MSG);
			} catch (final CsrfGuardException csrfe) {
				callActionsOnError(request, response, csrfe);
			}
		} else {
			/* unprotected page - nothing to do */
		}
		return valid;
	}

	/**
	 * Verify the token based on the type - ex: page, session or ajax
	 *
	 * @param request - HttpRequest
	 * @throws CsrfGuardException - Exception
	 */
	private void verifyToken(final HttpServletRequest request) throws CsrfGuardException {
		if (isAjaxEnabled() && isAjaxRequest(request)) {
			verifyAjaxToken(request);
		} else if (isTokenPerPageEnabled()) {
			verifyPageToken(request);
		} else {
			verifySessionToken(request);
		}
	}

	/**
	 * Invoked when there was a CsrfGuardException such as a token mismatch error.
	 * Calls the configured actions.
	 *
	 * @see IAction#execute(HttpServletRequest, HttpServletResponse, CsrfGuardException, CsrfGuard)
     *
	 * @param request The HttpServletRequest
	 * @param response The HttpServletResponse
	 * @param csrfe The exception that triggered the actions call. Passed to the action.
	 */
	private void callActionsOnError(final HttpServletRequest request, final HttpServletResponse response, final CsrfGuardException csrfe) {
		for (final IAction action : getActions()) {
			try {
				action.execute(request, response, csrfe, this);
			} catch (final CsrfGuardException exception) {
				getLogger().log(LogLevel.Error, exception);
			}
		}
	}

	public void updateToken(final HttpSession session) {
		final String tokenValue = (String) session.getAttribute(getSessionKey());

		/* Generate a new token and store it in the session. */
		if (tokenValue == null) {
			session.setAttribute(getSessionKey(), generateRandomId());
		}
	}

	public void updateTokens(final HttpServletRequest request) {
		/* cannot create sessions if response already committed */
		final HttpSession session = request.getSession(false);

		if (session != null) {
			/* create master token if it does not exist */
			updateToken(session);

			/* create page specific token */
			if (isTokenPerPageEnabled()) {

				final Map<String, String> pageTokens = SessionUtils.extractPageTokensFromSession(session);

				/* create token if it does not exist */
				if (isProtectedPageAndMethod(request)) {
					createPageToken(pageTokens, request.getRequestURI());
				}
			}
		}
	}

	/**
	 * Create page token if it doesn't exist.
	 * @param pageTokens A map of tokens. If token doesn't exist it will be added.
	 * @param uri The key for the tokens.
	 */
	private void createPageToken(final Map<String, String> pageTokens, final String uri) {

		if (pageTokens == null)
			return;

		/* create token if it does not exist */
		if (pageTokens.containsKey(uri))
			return;
		try {
			pageTokens.put(uri, RandomGenerator.generateRandomId(getPrng(), getTokenLength()));
		} catch (final Exception e) {
			final String errorLiteral = MessageConstants.RANDOM_TOKEN_FAILURE_MSG + " - " + "%s";
			throw new CSRFGuardTokenException(String.format(errorLiteral, e.getLocalizedMessage()), e);
		}
	}

	public void writeLandingPage(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
		String landingPage = getNewTokenLandingPage();

		/* default to current page */
		if (landingPage == null) {
			landingPage = request.getContextPath() + request.getServletPath();
		}

		// create auto posting form
		final StringBuilder sb = new StringBuilder();

		// TODO this HTML template should rather be extracted to a separate file
		sb.append("<html>").append(NEW_LINE)
		  .append("<head>").append(NEW_LINE)
		  .append("<title>OWASP CSRFGuard Project - New Token Landing Page</title>").append(NEW_LINE)
		  .append("</head>").append(NEW_LINE)
		  .append("<body>").append(NEW_LINE)
		  .append("<script type=\"text/javascript\">").append(NEW_LINE)
		  .append("var form = document.createElement(\"form\");").append(NEW_LINE)
		  .append("form.setAttribute(\"method\", \"post\");").append(NEW_LINE)
		  .append("form.setAttribute(\"action\", \"")
		  .append(landingPage)
		  .append("\");").append(NEW_LINE);

		/* only include token if needed */
		if (isProtectedPage(landingPage)) {
			sb.append("var hiddenField = document.createElement(\"input\");").append(NEW_LINE)
			  .append("hiddenField.setAttribute(\"type\", \"hidden\");").append(NEW_LINE)
			  .append("hiddenField.setAttribute(\"name\", \"")
			  .append(getTokenName())
			  .append("\");").append(NEW_LINE)
			  .append("hiddenField.setAttribute(\"value\", \"")
			  .append(getTokenValue(request, landingPage))
			  .append("\");").append(NEW_LINE)
			  .append("form.appendChild(hiddenField);").append(NEW_LINE);
		}

		sb.append("document.body.appendChild(form);").append(NEW_LINE)
		  .append("form.submit();").append(NEW_LINE)
		  .append("</script>").append(NEW_LINE)
		  .append("</body>").append(NEW_LINE)
		  .append("</html>").append(NEW_LINE);

		final String code = sb.toString();

		/* setup headers */
		response.setContentType("text/html");
		response.setContentLength(code.length());

		/* write auto posting form */
		response.getWriter().write(code);
	}

	@Override
	public String toString() {
		final String prefix = "*";
		final String delimiter = Stream.generate(() -> prefix).limit(53).collect(Collectors.joining());

		final StringBuilder sb = new StringBuilder();

		sb.append(NEW_LINE).append(delimiter).append(NEW_LINE)
		  .append(prefix).append(' ').append("Owasp.CsrfGuard Properties").append(NEW_LINE)
		  .append(prefix).append(NEW_LINE)
		  .append(getConfigurationsToDisplay(prefix)).append(NEW_LINE);

		for (final IAction action : getActions()) {
			sb.append(prefix).append(" Action: ").append(action.getClass().getName()).append(NEW_LINE);

			final String parameters = action.getParameterMap().entrySet().stream().map(e -> String.format("%s\tParameter: %s = %s", prefix, e.getKey(), e.getValue())).collect(Collectors.joining(NEW_LINE));
			sb.append(parameters).append(NEW_LINE);
		}

		sb.append(delimiter).append(NEW_LINE);

		return sb.toString();
	}

	private String getConfigurationsToDisplay(final String prefix) {
		final Map<Object, Object> configurations = new LinkedHashMap<>();

		configurations.put("Logger", getLogger().getClass().getName());
		configurations.put("NewTokenLandingPage", getNewTokenLandingPage());
		configurations.put("PRNG", getPrng().getAlgorithm());
		configurations.put("SessionKey", getSessionKey());
		configurations.put("TokenLength", getTokenLength());
		configurations.put("TokenName", getTokenName());
		configurations.put("Ajax", isAjaxEnabled());
		configurations.put("Rotate", isRotateEnabled());
		configurations.put("JavaScript cache control", getJavascriptCacheControl());
		configurations.put("JavaScript domain strict", isJavascriptDomainStrict());
		configurations.put("JavaScript inject attributes", isJavascriptInjectIntoAttributes());
		configurations.put("JavaScript inject forms", isJavascriptInjectIntoForms());
		configurations.put("JavaScript referer pattern", getJavascriptRefererPattern());
		configurations.put("JavaScript referer match protocol", isJavascriptRefererMatchProtocol());
		configurations.put("JavaScript referer match domain", isJavascriptRefererMatchDomain());
		configurations.put("JavaScript unprotected extensions", getJavascriptUnprotectedExtensions());
		configurations.put("JavaScript source file", getJavascriptSourceFile());
		configurations.put("JavaScript X requested with", getJavascriptXrequestedWith());
		configurations.put("Protected methods", String.join(",", getProtectedMethods()));
		configurations.put("Protected pages size", getProtectedPages().size());
		configurations.put("Unprotected methods", String.join(",", getUnprotectedMethods()));
		configurations.put("Unprotected pages size", getUnprotectedPages().size());
		configurations.put("TokenPerPage", isTokenPerPageEnabled());
		configurations.put("Enabled", isEnabled());
		configurations.put("ValidateWhenNoSessionExists", isValidateWhenNoSessionExists());

		return configurations.entrySet().stream().map(e -> String.format("%s %s: %s", prefix, e.getKey(), e.getValue())).collect(Collectors.joining(NEW_LINE));
	}

	private boolean isAjaxRequest(final HttpServletRequest request) {
		final String header = request.getHeader("X-Requested-With");
		if (header == null) {
			return false;
		}
		final String[] headers = header.split(",");
		for (final String requestedWithHeader: headers) {
			if ("XMLHttpRequest".equals(requestedWithHeader.trim())) {
				return true;
			}
		}
		return false;
	}

	private void verifyAjaxToken(final HttpServletRequest request) throws CsrfGuardException {
		final HttpSession session = request.getSession(true);
		final String tokenFromSession = (String) session.getAttribute(getSessionKey());
		String tokenFromRequest = request.getHeader(getTokenName());

		if (tokenFromRequest == null) {
			/* FAIL: token is missing from the request */
			throw new CsrfGuardException(MessageConstants.MISSING_TOKEN_MSG);
		} else {
			/* if there are two headers, then the result is comma separated */
			if (!tokenFromSession.equals(tokenFromRequest)) {
				if (tokenFromRequest.contains(",")) {
					tokenFromRequest = tokenFromRequest.substring(0, tokenFromRequest.indexOf(',')).trim();
				}
				if (!tokenFromSession.equals(tokenFromRequest)) {
					/* FAIL: the request token does not match the session token */
					throw new CsrfGuardException(MessageConstants.MISSING_TOKEN_MSG);
				}
			}
		}
	}

	private void verifyPageToken(final HttpServletRequest request) throws CsrfGuardException {

		final HttpSession session = request.getSession(true);
		final Map<String, String> pageTokens = SessionUtils.extractPageTokensFromSession(session);

		final String tokenFromPages = pageTokens.get(request.getRequestURI());
		final String tokenFromSession = (String) session.getAttribute(getSessionKey());
		final String tokenFromRequest = request.getParameter(getTokenName());

		if (tokenFromRequest == null) {
			/* FAIL: token is missing from the request */
			throw new CsrfGuardException(MessageConstants.MISSING_TOKEN_MSG);
		} else if (tokenFromPages != null) {
			if (!tokenFromPages.equals(tokenFromRequest)) {
				/* FAIL: request does not match page token */
				SessionUtils.invalidateTokenForResource(session, tokenFromPages, tokenFromRequest);
				throw new CsrfGuardException(MessageConstants.MISMATCH_PAGE_TOKEN_MSG);
			}
		} else if (!tokenFromSession.equals(tokenFromRequest)) {
			/* FAIL: the request token does not match the session token */
			SessionUtils.invalidateSessionToken(session);
			throw new CsrfGuardException(MessageConstants.MISMATCH_SESSION_TOKEN_MSG);
		}
	}

	private void verifySessionToken(final HttpServletRequest request) throws CsrfGuardException {
		final HttpSession session = request.getSession(true);
		final String tokenFromSession = (String) session.getAttribute(getSessionKey());
		final String tokenFromRequest = request.getParameter(getTokenName());

		if (tokenFromRequest == null) {
			/* FAIL: token is missing from the request */
			throw new CsrfGuardException(MessageConstants.MISSING_TOKEN_MSG);
		} else if (!tokenFromSession.equals(tokenFromRequest)) {
			/* FAIL: the request token does not match the session token */
			SessionUtils.invalidateSessionToken(session);
			throw new CsrfGuardException(MessageConstants.MISMATCH_SESSION_TOKEN_MSG);
		}
	}

	private void rotateTokens(final HttpServletRequest request) {
		final HttpSession session = request.getSession(true);

		/* rotate master token */
		session.setAttribute(getSessionKey(), generateRandomId());

		/* rotate page token */
		if (isTokenPerPageEnabled()) {

			final Map<String, String> pageTokens = SessionUtils.extractPageTokensFromSession(session);

			try {
				pageTokens.put(request.getRequestURI(), RandomGenerator.generateRandomId(getPrng(), getTokenLength()));
			} catch (final Exception e) {
				final String errorLiteral = MessageConstants.RANDOM_TOKEN_FAILURE_MSG + " - " + "%s";
				throw new CSRFGuardTokenException(String.format(errorLiteral, e.getLocalizedMessage()), e);
			}
		}
	}

	private String generateRandomId() {
		try {
			return RandomGenerator.generateRandomId(getPrng(), getTokenLength());
		} catch (final Exception e) {
			final String errorLiteral = MessageConstants.RANDOM_TOKEN_FAILURE_MSG + " - " + "%s";
			throw new CSRFGuardTokenException(String.format(errorLiteral, e.getLocalizedMessage()), e);
		}
	}

	public boolean isProtectedPage(final String uri) {

		/* if this is a javascript page, let it go through */
		if (JavaScriptServlet.getJavascriptUris().contains(uri)) {
			return false;
		}

		boolean retval = !isProtectEnabled();

		for (final String protectedPage : getProtectedPages()) {
			if (isUriExactMatch(protectedPage, uri)) {
				return true;
			} else if (isUriMatch(protectedPage, uri)) {
				retval = true;
			}
		}

		for (final String unprotectedPage : getUnprotectedPages()) {
			if (isUriExactMatch(unprotectedPage, uri)) {
				return false;
			} else if (isUriMatch(unprotectedPage, uri)) {
				retval = false;
			}
		}

		return retval;
	}

	/**
	 * Whether or not the HTTP method is protected, i.e. should be checked for token.
	 * @param method The method to check for protection status
	 * @return true when the given method name is in the protected methods set and not in the unprotected methods set
	 */
	public boolean isProtectedMethod(final String method) {
		boolean isProtected = true;

		{
			final Set<String> theProtectedMethods = getProtectedMethods();
			if (!theProtectedMethods.isEmpty() && !theProtectedMethods.contains(method)) {
					isProtected = false;
			}
		}

		{
			final Set<String> theUnprotectedMethods = getUnprotectedMethods();
			if (!theUnprotectedMethods.isEmpty() && theUnprotectedMethods.contains(method)) {
					isProtected = false;
			}
		}

		return isProtected;
	}

	public boolean isProtectedPageAndMethod(final String page, final String method) {
		return (isProtectedPage(page) && isProtectedMethod(method));
	}

	public boolean isProtectedPageAndMethod(final HttpServletRequest request) {
		return isProtectedPageAndMethod(request.getRequestURI(), request.getMethod());
	}

	public boolean isPrintConfig() {
		return config().isPrintConfig();
	}

	public String getDomainOrigin() {
		return config().getDomainOrigin();
	}

	/**
	 * FIXME: taken from Tomcat - ApplicationFilterFactory
	 *
	 * @param testPath the pattern to match.
	 * @param requestPath the current request path.
	 * @return {@code true} if {@code requestPath} matches {@code testPath}.
	 */
	private boolean isUriMatch(final String testPath, final String requestPath) {

		/* case 4, if it is a regex */
		if (RegexValidationUtil.isTestPathRegex(testPath)) {

			Pattern pattern = this.regexPatternCache.get(testPath);
			if (pattern == null) {
				pattern = Pattern.compile(testPath);
				this.regexPatternCache.put(testPath, pattern);
			}

			return pattern.matcher(requestPath).matches();
		}

		boolean retval = false;

		/* Case 1: Exact Match
		   MCH 140419: ??? isn't this checked in isUriExactMatch() ???  */
		if (testPath.equals(requestPath)) {
			retval = true;
		}

		/* Case 2 - Path Match ("/.../*") */
		if (testPath.equals("/*")) {
			retval = true;
		}

		if (testPath.endsWith("/*") &&
				(testPath.regionMatches(0, requestPath, 0, testPath.length() - 2)
						&& (requestPath.length() == (testPath.length() - 2)
						|| '/' == requestPath.charAt(testPath.length() - 2)))) {
			retval = true;
		}

		/* Case 3 - Extension Match */
		retval = validateExtensionMatch(testPath, requestPath, retval);

		return retval;
	}

	private boolean validateExtensionMatch(final String testPath, final String requestPath, boolean retval) {
		if (testPath != null && testPath.startsWith("*.")) {
			final int slash = requestPath.lastIndexOf('/');
			final int period = requestPath.lastIndexOf('.');

			if ((slash >= 0) && (period > slash) && (period != requestPath.length() - 1)
					&& ((requestPath.length() - period) == (testPath.length() - 1))) {
				retval = testPath.regionMatches(2, requestPath, period + 1,
						testPath.length() - 2);
			}
		}
		return retval;
	}

	private boolean isUriExactMatch(final String testPath, final String requestPath) {

		/* can't be an exact match if this is a regex */
		if (RegexValidationUtil.isTestPathRegex(testPath)) {
			return false;
		}

		boolean retval = false;

		/* Case 1: Exact Match */
		if (testPath.equals(requestPath)) {
			retval = true;
		}

		return retval;
	}

	/**
	 * if there are methods specified, then they (e.g. GET) are unprotected, and all others are protected
	 * @return the unprotected HTTP methods
	 */
	public Set<String> getUnprotectedMethods () {
		return config().getUnprotectedMethods();
	}
}
