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
import org.owasp.csrfguard.session.LogicalSession;
import org.owasp.csrfguard.token.service.TokenService;
import org.owasp.csrfguard.token.storage.LogicalSessionExtractor;
import org.owasp.csrfguard.token.storage.TokenHolder;
import org.owasp.csrfguard.util.CsrfGuardPropertiesToStringBuilder;
import org.owasp.csrfguard.util.CsrfGuardUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;
import java.util.regex.Pattern;

public class CsrfGuard {

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

    public Map<String, Pattern> getRegexPatternCache() {
        return this.regexPatternCache;
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

    public String getJavascriptDynamicNodeCreationEventName() {
        return config().getJavascriptDynamicNodeCreationEventName();
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
    public boolean isRotateEnabled(final HttpServletRequest request) {
        return isRotateEnabled() && !CsrfGuardUtils.isAjaxRequest(request);
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
                && isProtectEnabled()
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
        if (new CsrfValidator().isProtectedPage(landingPage).isProtected()) {
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

    private static final class SingletonHolder {
        public static final CsrfGuard instance = new CsrfGuard();
    }
}
