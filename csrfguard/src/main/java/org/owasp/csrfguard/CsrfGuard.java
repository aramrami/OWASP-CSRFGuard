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
import org.owasp.csrfguard.config.ConfigurationProvider;
import org.owasp.csrfguard.config.ConfigurationProviderFactory;
import org.owasp.csrfguard.config.NullConfigurationProvider;
import org.owasp.csrfguard.config.PropertiesConfigurationProviderFactory;
import org.owasp.csrfguard.config.overlay.ExpirableCache;
import org.owasp.csrfguard.config.properties.ConfigParameters;
import org.owasp.csrfguard.log.ILogger;
import org.owasp.csrfguard.log.LogLevel;
import org.owasp.csrfguard.servlet.JavaScriptServlet;
import org.owasp.csrfguard.session.LogicalSession;
import org.owasp.csrfguard.token.businessobject.TokenBO;
import org.owasp.csrfguard.token.mapper.TokenMapper;
import org.owasp.csrfguard.token.service.TokenService;
import org.owasp.csrfguard.token.storage.LogicalSessionExtractor;
import org.owasp.csrfguard.token.storage.TokenHolder;
import org.owasp.csrfguard.token.transferobject.TokenTO;
import org.owasp.csrfguard.util.CsrfGuardPropertiesToStringBuilder;
import org.owasp.csrfguard.util.CsrfGuardUtils;
import org.owasp.csrfguard.util.MessageConstants;
import org.owasp.csrfguard.util.RegexValidationUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;
import java.util.function.Predicate;
import java.util.regex.Pattern;

public final class CsrfGuard {

    /**
     * cache the configuration for a minute
     */
    private static final ExpirableCache<Boolean, ConfigurationProvider> configurationProviderExpirableCache = new ExpirableCache<>(1);

    /**
     * cache regex patterns here
     */
    private final Map<String, Pattern> regexPatternCache = new HashMap<>();

    private Properties properties = null;

    public CsrfGuard() {}

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
     *
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

    /**
     * @see ConfigurationProvider#isProtectEnabled()
     */
    public boolean isProtectEnabled() {
        return config().isProtectEnabled();
    }

    /**
     * @return if enabled
     * @see ConfigurationProvider#isEnabled()
     */
    public boolean isEnabled() {
        return config().isEnabled();
    }

    public Set<String> getProtectedPages() {
        return config().getProtectedPages();
    }

    public Set<String> getUnprotectedPages() {
        return config().getUnprotectedPages();
    }

    public TokenHolder getTokenHolder() {
        return config().getTokenHolder();
    }

    public LogicalSessionExtractor getLogicalSessionExtractor() {
        return config().getLogicalSessionExtractor();
    }

    public Set<String> getProtectedMethods() {
        return config().getProtectedMethods();
    }

    public List<IAction> getActions() {
        return config().getActions();
    }

    public String getJavascriptSourceFile() {
        return config().getJavascriptSourceFile();
    }

    /**
     * @return if inject
     * @see ConfigurationProvider#isJavascriptInjectFormAttributes()
     */
    public boolean isJavascriptInjectFormAttributes() {
        return config().isJavascriptInjectFormAttributes();
    }

    /**
     * @return if inject
     * @see ConfigurationProvider#isJavascriptInjectGetForms()
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

    public boolean isJavascriptInjectIntoDynamicallyCreatedNodes() {
        return config().isJavascriptInjectIntoDynamicallyCreatedNodes();
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

    public TokenService getTokenService() {
        return new TokenService(this);
    }

    public boolean isValidRequest(final HttpServletRequest request, final HttpServletResponse response) {
        final boolean isValid;

        final ILogger logger = getLogger();
        final String normalizedResourceURI = CsrfGuardUtils.normalizeResourceURI(request);
        if (isProtectedPageAndMethod(request)) {
            logger.log(LogLevel.Debug, String.format("CSRFGuard analyzing protected resource: '%s'", normalizedResourceURI));
            isValid = isTokenValidInRequest(request, response);
        } else {
            logger.log(LogLevel.Debug, String.format("Unprotected page: %s", normalizedResourceURI));
            isValid = true;
        }

        return isValid;
    }

    /**
     * Method to be called by a logical session implementation when a new session is created. <br>
     * <p>
     * Example: {@link javax.servlet.http.HttpSessionListener#sessionCreated(javax.servlet.http.HttpSessionEvent)}
     *
     * @param logicalSession a logical session implementation
     */
    public void onSessionCreated(final LogicalSession logicalSession) {
        if (isEnabled()) {
            final String logicalSessionKey = logicalSession.getKey();

            final TokenService tokenService = getTokenService();
            tokenService.createMasterTokenIfAbsent(logicalSessionKey);

            if (isTokenPerPageEnabled()
                && isTokenPerPagePrecreate()
                && !logicalSession.areTokensGenerated()) {

                tokenService.generateProtectedPageTokens(logicalSessionKey);
                logicalSession.setTokensGenerated(true);
            }
        }
    }

    /**
     * Method to be called by a logical session implementation when a session is destroyed. <br>
     * <p>
     * Example: {@link javax.servlet.http.HttpSessionListener#sessionDestroyed(javax.servlet.http.HttpSessionEvent)}
     *
     * @param logicalSession a logical session implementation
     */
    public void onSessionDestroyed(final LogicalSession logicalSession) {
        final TokenHolder tokenHolder = getTokenHolder();
        if (Objects.nonNull(tokenHolder)) {
            tokenHolder.remove(logicalSession.getKey());
        }
    }

    public void writeLandingPage(final HttpServletRequest request, final HttpServletResponse response, final String logicalSessionKey) throws IOException {
        String landingPage = getNewTokenLandingPage();

        /* default to current page */
        if (landingPage == null) {
            landingPage = request.getContextPath() + request.getServletPath();
        }

        /* create auto posting form */
        final StringBuilder stringBuilder = new StringBuilder();

        // TODO this HTML template should rather be extracted to a separate file
        stringBuilder.append("<html>")
                     .append("<head>")
                     .append("<title>OWASP CSRFGuard Project - New Token Landing Page</title>")
                     .append("</head>")
                     .append("<body>")
                     .append("<script type=\"text/javascript\">")
                     .append("var form = document.createElement(\"form\");")
                     .append("form.setAttribute(\"method\", \"post\");")
                     .append("form.setAttribute(\"action\", \"")
                     .append(landingPage)
                     .append("\");");

        /* only include token if needed */
        if (isProtectedPage(landingPage)) {
            stringBuilder.append("var hiddenField = document.createElement(\"input\");")
                         .append("hiddenField.setAttribute(\"type\", \"hidden\");")
                         .append("hiddenField.setAttribute(\"name\", \"")
                         .append(getTokenName())
                         .append("\");")
                         .append("hiddenField.setAttribute(\"value\", \"")
                         .append(getTokenService().getTokenValue(logicalSessionKey, landingPage))
                         .append("\");")
                         .append("form.appendChild(hiddenField);");
        }

        stringBuilder.append("document.body.appendChild(form);")
                     .append("form.submit();")
                     .append("</script>")
                     .append("</body>")
                     .append("</html>");

        final String code = stringBuilder.toString();

        /* setup headers */
        response.setContentType("text/html");
        response.setContentLength(code.length());

        /* write auto posting form */
        response.getWriter().write(code);
    }

    public boolean isProtectedPageAndMethod(final String page, final String method) {
        return (isProtectedPage(CsrfGuardUtils.normalizeResourceURI(page)) && isProtectedMethod(method));
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

    public Duration getPageTokenSynchronizationTolerance() {
        return config().getPageTokenSynchronizationTolerance();
    }

    /**
     * if there are methods specified, then they (e.g. GET) are unprotected, and all others are protected
     *
     * @return the unprotected HTTP methods
     */
    public Set<String> getUnprotectedMethods() {
        return config().getUnprotectedMethods();
    }

    @Override
    public String toString() {
        return isEnabled() ? new CsrfGuardPropertiesToStringBuilder(config()).toString()
                           : "OWASP CSRFGuard is disabled.";
    }

    private static boolean isUriPathMatch(final String testPath, final String requestPath) {
        return testPath.equals("/*") || (testPath.endsWith("/*")
                                         && (testPath.regionMatches(0, requestPath, 0, testPath.length() - 2)
                                             && (requestPath.length() == (testPath.length() - 2) || '/' == requestPath.charAt(testPath.length() - 2))));
    }

    private boolean isTokenValidInRequest(final HttpServletRequest request, final HttpServletResponse response) {
        boolean isValid = false;

        final CsrfGuard csrfGuard = CsrfGuard.getInstance();
        final LogicalSession logicalSession = csrfGuard.getLogicalSessionExtractor().extract(request);

        if (Objects.nonNull(logicalSession)) {
            final TokenService tokenService = getTokenService();
            final String logicalSessionKey = logicalSession.getKey();
            final String masterToken = tokenService.getMasterToken(logicalSessionKey);

            if (Objects.nonNull(masterToken)) {
                try {
                    final TokenBO tokenBO = tokenService.verifyToken(request, logicalSessionKey, masterToken);

                    final TokenTO tokenTO = isRotateEnabled(request) ? tokenService.rotateUsedToken(logicalSessionKey, request.getRequestURI(), tokenBO)
                                                                     : TokenMapper.toTransferObject(tokenBO);

                    CsrfGuardUtils.addResponseTokenHeader(csrfGuard, request, response, tokenTO);

                    isValid = true;
                } catch (final CsrfGuardException csrfe) {
                    callActionsOnError(request, response, csrfe);
                }
            } else {
                callActionsOnError(request, response, new CsrfGuardException(MessageConstants.TOKEN_MISSING_FROM_STORAGE_MSG));
            }
        } else {
            callActionsOnError(request, response, new CsrfGuardException(MessageConstants.TOKEN_MISSING_FROM_STORAGE_MSG));
        }

        return isValid;
    }

    /**
     * Rotation in case of AJAX requests is not currently not supported because of the possible race conditions.
     * <p>
     * A Single Page Application can fire multiple simultaneous requests.
     * If rotation is enabled, the first request might trigger a token change before the validation of the second request with the same token, causing
     * false-positive CSRF intrusion exceptions.
     *
     * @param request the current request
     * @return True if rotation is enabled and possible
     */
    private boolean isRotateEnabled(final HttpServletRequest request) {
        return isRotateEnabled() && !CsrfGuardUtils.isAjaxRequest(request);
    }

    private boolean isProtectedPage(final String normalizedResourceUri) {
        /* if this is a javascript page, let it go through */
        if (JavaScriptServlet.getJavascriptUris().contains(normalizedResourceUri)) {
            return false;
        }

        final Predicate<String> predicate = page -> isUriMatch(page, normalizedResourceUri);
        return isProtectEnabled() ? getProtectedPages().stream().anyMatch(predicate)     /* all links are unprotected, except the ones that were explicitly specified */
                                  : getUnprotectedPages().stream().noneMatch(predicate); /* all links are protected, except the ones were explicitly excluded */
    }

    /**
     * Whether or not the HTTP method is protected, i.e. should be checked for token.
     *
     * @param method The method to check for protection status
     * @return true when the given method name is in the protected methods set and not in the unprotected methods set
     */
    private boolean isProtectedMethod(final String method) {
        boolean isProtected = true;

        final Set<String> protectedMethods = getProtectedMethods();
        if (!protectedMethods.isEmpty() && !protectedMethods.contains(method)) {
            isProtected = false;
        }

        final Set<String> unprotectedMethods = getUnprotectedMethods();
        if (!unprotectedMethods.isEmpty() && unprotectedMethods.contains(method)) {
            isProtected = false;
        }

        return isProtected;
    }

    /**
     * FIXME: partially taken from Tomcat - <a href="https://github.com/apache/tomcat/blob/master/java/org/apache/catalina/core/ApplicationFilterFactory.java">ApplicationFilterFactory#matchFiltersURL</a>
     *
     * @param testPath    the pattern to match.
     * @param requestPath the current request path.
     * @return {@code true} if {@code requestPath} matches {@code testPath}.
     */
    private boolean isUriMatch(final String testPath, final String requestPath) {
        return Objects.nonNull(testPath) && (testPath.equals(requestPath)
                                             || isUriPathMatch(testPath, requestPath)
                                             || CsrfGuardUtils.isExtensionMatch(testPath, requestPath)
                                             || isUriRegexMatch(testPath, requestPath));
    }

    private boolean isUriRegexMatch(final String testPath, final String requestPath) {
        return RegexValidationUtil.isTestPathRegex(testPath) && this.regexPatternCache.computeIfAbsent(testPath, k -> Pattern.compile(testPath))
                                                                                      .matcher(requestPath)
                                                                                      .matches();
    }

    private ConfigurationProvider config() {
        if (this.properties == null) {
            return new NullConfigurationProvider();
        }

        ConfigurationProvider configurationProvider = configurationProviderExpirableCache.get(Boolean.TRUE);

        if (configurationProvider == null) {

            synchronized (CsrfGuard.class) {
                configurationProvider = retrieveNewConfig();
            }
        } else if (!configurationProvider.isCacheable()) {
            /* don't synchronize if not cacheable */
            configurationProvider = retrieveNewConfig();
        }

        return configurationProvider;
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

    /**
     * Invoked when there was a CsrfGuardException such as a token mismatch error.
     * Calls the configured actions.
     *
     * @param request  The HttpServletRequest
     * @param response The HttpServletResponse
     * @param csrfe    The exception that triggered the actions call. Passed to the action.
     * @see IAction#execute(HttpServletRequest, HttpServletResponse, CsrfGuardException, CsrfGuard)
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

    private static final class SingletonHolder {
        public static final CsrfGuard instance = new CsrfGuard();
    }
}
