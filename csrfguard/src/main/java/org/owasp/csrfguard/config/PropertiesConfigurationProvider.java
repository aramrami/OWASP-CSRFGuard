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

package org.owasp.csrfguard.config;

import org.apache.commons.lang3.StringUtils;
import org.owasp.csrfguard.action.IAction;
import org.owasp.csrfguard.config.properties.ConfigParameters;
import org.owasp.csrfguard.config.properties.PropertyUtils;
import org.owasp.csrfguard.config.properties.javascript.JavaScriptConfigParameters;
import org.owasp.csrfguard.config.properties.javascript.JsConfigParameter;
import org.owasp.csrfguard.log.ILogger;
import org.owasp.csrfguard.servlet.JavaScriptServlet;
import org.owasp.csrfguard.token.storage.TokenHolder;
import org.owasp.csrfguard.token.storage.TokenKeyExtractor;
import org.owasp.csrfguard.util.CsrfGuardUtils;

import javax.servlet.ServletConfig;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.*;
import java.util.regex.Pattern;

/**
 * {@link ConfigurationProvider} based on a {@link java.util.Properties} object.
 */
public class PropertiesConfigurationProvider implements ConfigurationProvider {

	private final ILogger logger;

	private final String tokenName;

	private final int tokenLength;

	private final boolean rotate;

	private final boolean enabled;

	private final boolean tokenPerPage;

	private final boolean tokenPerPagePrecreate;

	private final boolean printConfig;

	private final SecureRandom prng;

	private final String newTokenLandingPage;

	private final boolean useNewTokenLandingPage;

	private final boolean ajax;

	private final boolean protect;

	private final String sessionKey;

	private final Set<String> protectedPages;

	private final Set<String> unprotectedPages;

	private final Set<String> protectedMethods;

	private final Set<String> unprotectedMethods;

	private final List<IAction> actions;

	private final Properties propertiesCache;

	private final String domainOrigin;

	private boolean javascriptParamsInitialized = false;

	private final boolean validationWhenNoSessionExists;

	private String javascriptTemplateCode;

	private String javascriptSourceFile;

	private boolean javascriptDomainStrict;

	private String javascriptCacheControl;

	private Pattern javascriptRefererPattern;

	private boolean javascriptInjectIntoForms;

	private boolean javascriptRefererMatchProtocol;

	private boolean javascriptInjectIntoAttributes;

	private String javascriptXrequestedWith;

	private boolean javascriptInjectGetForms;

	private boolean javascriptRefererMatchDomain;

	private boolean javascriptInjectFormAttributes;

	private String javascriptUnprotectedExtensions;

	private TokenKeyExtractor tokenKeyExtractor;

	private TokenHolder tokenHolder;

	public PropertiesConfigurationProvider(final Properties properties) {
		try {
			this.propertiesCache = properties;
			this.actions = new ArrayList<>();
			this.protectedPages = new HashSet<>();
			this.unprotectedPages = new HashSet<>();
			this.protectedMethods = new HashSet<>();
			this.unprotectedMethods = new HashSet<>();

			/* load simple properties */
			this.logger = (ILogger) Class.forName(PropertyUtils.getProperty(properties, ConfigParameters.LOGGER)).newInstance();
			this.tokenName = PropertyUtils.getProperty(properties, ConfigParameters.TOKEN_NAME);
			this.tokenLength = PropertyUtils.getProperty(properties, ConfigParameters.TOKEN_LENGTH);
			this.rotate = PropertyUtils.getProperty(properties, ConfigParameters.ROTATE);
			this.tokenPerPage = PropertyUtils.getProperty(properties, ConfigParameters.TOKEN_PER_PAGE);

			this.validationWhenNoSessionExists = PropertyUtils.getProperty(properties, ConfigParameters.VALIDATE_WHEN_NO_SESSION_EXISTS);
			this.domainOrigin = PropertyUtils.getProperty(properties, ConfigParameters.DOMAIN_ORIGIN);
			this.tokenPerPagePrecreate = PropertyUtils.getProperty(properties, ConfigParameters.TOKEN_PER_PAGE_PRECREATE);

			this.prng = SecureRandom.getInstance(PropertyUtils.getProperty(properties, ConfigParameters.PRNG),
												 PropertyUtils.getProperty(properties, ConfigParameters.PRNG_PROVIDER));

			this.printConfig = PropertyUtils.getProperty(properties, ConfigParameters.PRINT_ENABLED);

			// TODO does it worth checking all this if it's not enabled?
			this.enabled = PropertyUtils.getProperty(properties, ConfigParameters.CSRFGUARD_ENABLED);
			this.protect = PropertyUtils.getProperty(properties, ConfigParameters.CSRFGUARD_PROTECT);

			this.newTokenLandingPage = PropertyUtils.getProperty(properties, ConfigParameters.NEW_TOKEN_LANDING_PAGE);
			this.useNewTokenLandingPage = PropertyUtils.getProperty(properties, ConfigParameters.getUseNewTokenLandingPage(this.newTokenLandingPage));

			this.sessionKey = PropertyUtils.getProperty(properties, ConfigParameters.SESSION_KEY);
			this.ajax = PropertyUtils.getProperty(properties, ConfigParameters.AJAX_ENABLED);

			initializeStatelessParameters(properties);

			initializeActionParameters(properties, instantiateActions(properties));

			initializePageProtection(properties);

			initializeMethodProtection(properties);
		} catch (final Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public ILogger getLogger() {
		return this.logger;
	}

	@Override
	public String getTokenName() {
		return this.tokenName;
	}

	@Override
	public int getTokenLength() {
		return this.tokenLength;
	}

	@Override
	public boolean isRotateEnabled() {
		return this.rotate;
	}

	@Override
	public boolean isValidateWhenNoSessionExists() {
		return this.validationWhenNoSessionExists;
	}

	@Override
	public boolean isTokenPerPageEnabled() {
		return this.tokenPerPage;
	}

	@Override
	public boolean isTokenPerPagePrecreateEnabled() {
		return this.tokenPerPagePrecreate;
	}

	@Override
	public SecureRandom getPrng() {
		return this.prng;
	}

	@Override
	public String getNewTokenLandingPage() {
		return this.newTokenLandingPage;
	}

	@Override
	public boolean isUseNewTokenLandingPage() {
		return this.useNewTokenLandingPage;
	}

	@Override
	public boolean isAjaxEnabled() {
		return this.ajax;
	}

	@Override
	public boolean isProtectEnabled() {
		return this.protect;
	}

	@Override
	public String getSessionKey() {
		return this.sessionKey;
	}

	@Override
	public Set<String> getProtectedPages() {
		return this.protectedPages;
	}

	@Override
	public Set<String> getUnprotectedPages() {
		return this.unprotectedPages;
	}

	@Override
	public Set<String> getProtectedMethods () {
		return this.protectedMethods;
	}

	@Override
	public Set<String> getUnprotectedMethods () {
		return this.unprotectedMethods;
	}

	@Override
	public List<IAction> getActions() {
		return this.actions;
	}

	@Override
	public boolean isPrintConfig() {
		return this.printConfig;
	}

	@Override
	public String getJavascriptSourceFile() {
		this.javascriptInitParamsIfNeeded();
		return this.javascriptSourceFile;
	}

	@Override
	public boolean isJavascriptDomainStrict() {
		this.javascriptInitParamsIfNeeded();
		return this.javascriptDomainStrict;
	}

	@Override
	public String getJavascriptCacheControl() {
		this.javascriptInitParamsIfNeeded();
		return this.javascriptCacheControl;
	}

	@Override
	public Pattern getJavascriptRefererPattern() {
		this.javascriptInitParamsIfNeeded();
		return this.javascriptRefererPattern;
	}

	@Override
	public boolean isJavascriptRefererMatchProtocol() {
		this.javascriptInitParamsIfNeeded();
		return this.javascriptRefererMatchProtocol;
	}

	@Override
	public boolean isJavascriptRefererMatchDomain() {
		this.javascriptInitParamsIfNeeded();
		return this.javascriptRefererMatchDomain;
	}

	@Override
	public boolean isJavascriptInjectIntoForms() {
		this.javascriptInitParamsIfNeeded();
		return this.javascriptInjectIntoForms;
	}

	@Override
	public boolean isJavascriptInjectIntoAttributes() {
		this.javascriptInitParamsIfNeeded();
		return this.javascriptInjectIntoAttributes;
	}

	@Override
	public String getJavascriptXrequestedWith() {
		this.javascriptInitParamsIfNeeded();
		return this.javascriptXrequestedWith;
	}

	@Override
	public String getJavascriptTemplateCode() {
		this.javascriptInitParamsIfNeeded();
		return this.javascriptTemplateCode;
	}

	public boolean isCacheable() {
		/* don't cache this until the javascript params are all set i.e. the javascript servlet is */
		return this.javascriptParamsInitialized;
	}

	@Override
	public boolean isEnabled() {
		return this.enabled;
	}

	@Override
	public boolean isJavascriptInjectGetForms() {
		this.javascriptInitParamsIfNeeded();
		return this.javascriptInjectGetForms;
	}

	@Override
	public boolean isJavascriptInjectFormAttributes() {
		this.javascriptInitParamsIfNeeded();
		return this.javascriptInjectFormAttributes;
	}

	@Override
	public String getDomainOrigin() {
		return this.domainOrigin;
	}

	@Override
	public String getJavascriptUnprotectedExtensions() {
		this.javascriptInitParamsIfNeeded();
		return this.javascriptUnprotectedExtensions;
	}

	@Override
	public TokenHolder getTokenHolder() {
		return this.tokenHolder;
	}

	@Override
	public TokenKeyExtractor getTokenKeyExtractor() {
		return this.tokenKeyExtractor;
	}

	@Override
	public boolean isStateless() {
		return Objects.nonNull(this.tokenKeyExtractor);
	}

	private Map<String, IAction> instantiateActions(final Properties properties) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
		final Map<String, IAction> actionsMap = new HashMap<>();

		for (final Object obj : properties.keySet()) {
			final String key = (String) obj;

			if (key.startsWith(ConfigParameters.ACTION_PREFIX)) {
				final String directive = key.substring(ConfigParameters.ACTION_PREFIX.length());
				final int index = directive.indexOf('.');

				/* action name/class */
				if (index < 0) {
					final String actionClass = PropertyUtils.getProperty(properties, key);
					final IAction action = (IAction) Class.forName(actionClass).newInstance();

					action.setName(directive);
					actionsMap.put(action.getName(), action);
					this.actions.add(action);
				}
			}
		}
		return actionsMap;
	}

	private void initializeMethodProtection(final Properties properties) {
		initializeMethodProtection(properties, ConfigParameters.PROTECTED_METHODS, this.protectedMethods);
		initializeMethodProtection(properties, ConfigParameters.UNPROTECTED_METHODS, this.unprotectedMethods);

		final HashSet<String> intersection = new HashSet<>(this.protectedMethods);
		intersection.retainAll(this.unprotectedMethods);

		if (!intersection.isEmpty()) {
			throw new IllegalArgumentException(String.format("The %s HTTP method(s) cannot be both protected and unprotected.", intersection.toString()));
		}
	}

	private static void initializeMethodProtection(final Properties properties, final String protectedMethods, final Set<String> protectedMethods2) {
		final String protectedMethodList = PropertyUtils.getProperty(properties, protectedMethods);
		if (StringUtils.isNotBlank(protectedMethodList)) {
			for (final String method : protectedMethodList.split(",")) {
				protectedMethods2.add(method.trim());
			}
		}
	}

	private void initializePageProtection(final Properties properties) {
		for (final Object obj : properties.keySet()) {
			final String key = (String) obj;

			if (key.startsWith(ConfigParameters.PROTECTED_PAGE_PREFIX)) {
				final String directive = key.substring(ConfigParameters.PROTECTED_PAGE_PREFIX.length());
				final int index = directive.indexOf('.');

				/* page name/class */
				if (index < 0) {
					final String pageUri = PropertyUtils.getProperty(properties, key);

					this.protectedPages.add(pageUri);
				}
			}

			if (key.startsWith(ConfigParameters.UNPROTECTED_PAGE_PREFIX)) {
				final String directive = key.substring(ConfigParameters.UNPROTECTED_PAGE_PREFIX.length());
				final int index = directive.indexOf('.');

				/* page name/class */
				if (index < 0) {
					final String pageUri = PropertyUtils.getProperty(properties, key);

					this.unprotectedPages.add(pageUri);
				}
			}
		}
	}

	private void initializeActionParameters(final Properties properties, final Map<String, IAction> actionsMap) throws IOException {
		for (final Object obj : properties.keySet()) {
			final String key = (String) obj;

			if (key.startsWith(ConfigParameters.ACTION_PREFIX)) {
				final String directive = key.substring(ConfigParameters.ACTION_PREFIX.length());
				final int index = directive.indexOf('.');

				/* action name/class */
				if (index >= 0) {
					final String actionName = directive.substring(0, index);
					final IAction action = actionsMap.get(actionName);

					if (action == null) {
						throw new IOException(String.format("action class %s has not yet been specified", actionName));
					}

					final String parameterName = directive.substring(index + 1);
					final String parameterValue = PropertyUtils.getProperty(properties, key);

					action.setParameter(parameterName, parameterValue);
				}
			}
		}

		/* ensure at least one action was defined */
		if (this.actions.size() <= 0) {
			throw new IOException("failure to define at least one action");
		}
	}

	private void javascriptInitParamsIfNeeded() {
		if (!this.javascriptParamsInitialized) {
			final ServletConfig servletConfig = JavaScriptServlet.getStaticServletConfig();

			if (servletConfig != null) {

				this.javascriptCacheControl = getProperty(JavaScriptConfigParameters.CACHE_CONTROL, servletConfig);
				this.javascriptDomainStrict = getProperty(JavaScriptConfigParameters.DOMAIN_STRICT, servletConfig);
				this.javascriptInjectIntoAttributes = getProperty(JavaScriptConfigParameters.INJECT_INTO_ATTRIBUTES, servletConfig);
				this.javascriptInjectGetForms = getProperty(JavaScriptConfigParameters.INJECT_GET_FORMS, servletConfig);
				this.javascriptInjectFormAttributes = getProperty(JavaScriptConfigParameters.INJECT_FORM_ATTRIBUTES, servletConfig);
				this.javascriptInjectIntoForms = getProperty(JavaScriptConfigParameters.INJECT_INTO_FORMS, servletConfig);
				this.javascriptRefererPattern = Pattern.compile(getProperty(JavaScriptConfigParameters.REFERER_PATTERN, servletConfig));
				this.javascriptRefererMatchProtocol = getProperty(JavaScriptConfigParameters.REFERER_MATCH_PROTOCOL, servletConfig);
				this.javascriptRefererMatchDomain = getProperty(JavaScriptConfigParameters.REFERER_MATCH_DOMAIN, servletConfig);
				this.javascriptUnprotectedExtensions = getProperty(JavaScriptConfigParameters.UNPROTECTED_EXTENSIONS, servletConfig);
				this.javascriptSourceFile = getProperty(JavaScriptConfigParameters.SOURCE_FILE, servletConfig);
				this.javascriptXrequestedWith = getProperty(JavaScriptConfigParameters.X_REQUESTED_WITH, servletConfig);

				if (this.javascriptSourceFile == null) {
					this.javascriptTemplateCode = CsrfGuardUtils.readResourceFileContent("META-INF/csrfguard.js");
				} else if (this.javascriptSourceFile.startsWith("META-INF/")) {
					this.javascriptTemplateCode = CsrfGuardUtils.readResourceFileContent(this.javascriptSourceFile);
				} else if (this.javascriptSourceFile.startsWith("classpath:")) {
					final String location = this.javascriptSourceFile.substring("classpath:".length()).trim();
					this.javascriptTemplateCode = CsrfGuardUtils.readResourceFileContent(location);
				} else if (this.javascriptSourceFile.startsWith("file:")) {
					final String location = this.javascriptSourceFile.substring("file:".length()).trim();
					this.javascriptTemplateCode = CsrfGuardUtils.readFileContent(location);
				} else if (servletConfig.getServletContext().getRealPath(this.javascriptSourceFile) != null) {
					this.javascriptTemplateCode = CsrfGuardUtils.readFileContent(servletConfig.getServletContext().getRealPath(this.javascriptSourceFile));
				} else {
					throw new IllegalStateException("getRealPath failed for file " + this.javascriptSourceFile);
				}

				this.javascriptParamsInitialized = true;
			}
		}
	}

	private <T> T getProperty(final JsConfigParameter<T> jsConfigParameter, final ServletConfig servletConfig) {
		return jsConfigParameter.getProperty(servletConfig, this.propertiesCache);
	}

	// TODO give a better name maybe
	private void initializeStatelessParameters(final Properties properties) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
		final String tokenKeyExtractorName = PropertyUtils.getProperty(properties, ConfigParameters.TOKEN_KEY_EXTRACTOR_NAME);
		if (StringUtils.isNoneBlank(tokenKeyExtractorName)) {
			this.tokenKeyExtractor = instantiate(TokenKeyExtractor.class);

			final String tokenHolderClassName = PropertyUtils.getProperty(properties, ConfigParameters.TOKEN_HOLDER);

			if (StringUtils.isNoneBlank(tokenHolderClassName)) {
				this.tokenHolder = (TokenHolder) Class.forName(PropertyUtils.getProperty(properties, ConfigParameters.TOKEN_HOLDER)).newInstance();
			} else {
				this.tokenHolder = instantiate(TokenHolder.class);
			}
		}
	}

	private static <T> T instantiate(final Class<T> clazz) {
		final ServiceLoader<T> serviceLoader = ServiceLoader.load(clazz);
		final Iterator<T> iterator = serviceLoader.iterator();

		if (iterator.hasNext()) {
			final T instance = iterator.next();

			 if (iterator.hasNext()) {
				throw new IllegalStateException(String.format("There should be only one %s implementation on the classpath!", clazz.getSimpleName()));
			} else {
				return instance;
			}
		} else {
			throw new IllegalStateException(String.format("Implementation for class '%s' is missing from classpath!", clazz.getSimpleName()));
		}
	}
}
