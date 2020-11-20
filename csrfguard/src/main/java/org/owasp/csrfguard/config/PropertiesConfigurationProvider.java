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
import org.apache.commons.lang3.tuple.Pair;
import org.owasp.csrfguard.action.IAction;
import org.owasp.csrfguard.config.properties.ConfigParameters;
import org.owasp.csrfguard.config.properties.HttpMethod;
import org.owasp.csrfguard.config.properties.PropertyUtils;
import org.owasp.csrfguard.config.properties.javascript.JavaScriptConfigParameters;
import org.owasp.csrfguard.config.properties.javascript.JsConfigParameter;
import org.owasp.csrfguard.log.ILogger;
import org.owasp.csrfguard.log.LogLevel;
import org.owasp.csrfguard.servlet.JavaScriptServlet;
import org.owasp.csrfguard.token.storage.LogicalSessionExtractor;
import org.owasp.csrfguard.token.storage.TokenHolder;
import org.owasp.csrfguard.util.CsrfGuardUtils;
import org.owasp.csrfguard.util.RegexValidationUtil;

import javax.servlet.ServletConfig;
import java.io.IOException;
import java.security.*;
import java.time.Duration;
import java.util.*;
import java.util.function.IntPredicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * {@link ConfigurationProvider} based on a {@link java.util.Properties} object.
 */
public class PropertiesConfigurationProvider implements ConfigurationProvider {

	private final ILogger logger;

	private final Set<String> protectedPages;

	private final Set<String> unprotectedPages;

	private final Set<String> protectedMethods;

	private final Set<String> unprotectedMethods;

	private final List<IAction> actions;

	private final Properties propertiesCache;

	private final boolean enabled;

	private String tokenName;

	private int tokenLength;

	private boolean rotate;

	private boolean tokenPerPage;

	private boolean tokenPerPagePrecreate;

	private boolean printConfig;

	private SecureRandom prng;

	private String newTokenLandingPage;

	private boolean useNewTokenLandingPage;

	private boolean ajax;

	private boolean protect;

	private String domainOrigin;

	private Duration pageTokenSynchronizationTolerance;

	private boolean validationWhenNoSessionExists;

	private boolean javascriptParamsInitialized = false;

	private String javascriptTemplateCode;

	private String javascriptSourceFile;

	private boolean javascriptDomainStrict;

	private String javascriptCacheControl;

	private Pattern javascriptRefererPattern;

	private boolean javascriptInjectIntoForms;

	private boolean javascriptRefererMatchProtocol;

	private boolean javascriptInjectIntoAttributes;

	private boolean isJavascriptInjectIntoDynamicallyCreatedNodes;

	private String javascriptDynamicNodeCreationEventName;

	private String javascriptXrequestedWith;

	private boolean javascriptInjectGetForms;

	private boolean javascriptRefererMatchDomain;

	private boolean javascriptInjectFormAttributes;

	private String javascriptUnprotectedExtensions;

	private LogicalSessionExtractor logicalSessionExtractor;

	private TokenHolder tokenHolder;

	public PropertiesConfigurationProvider(final Properties properties) {
		try {
			this.propertiesCache = properties;
			this.actions = new ArrayList<>();
			this.protectedPages = new HashSet<>();
			this.unprotectedPages = new HashSet<>();
			this.protectedMethods = new HashSet<>();
			this.unprotectedMethods = new HashSet<>();

			this.logger = CsrfGuardUtils.<ILogger>forName(PropertyUtils.getProperty(properties, ConfigParameters.LOGGER)).newInstance();

            this.enabled = PropertyUtils.getProperty(properties, ConfigParameters.CSRFGUARD_ENABLED);

            if (this.enabled) {
				this.tokenName = PropertyUtils.getProperty(properties, ConfigParameters.TOKEN_NAME);
				this.tokenLength = getTokenLength(properties);
				this.rotate = PropertyUtils.getProperty(properties, ConfigParameters.ROTATE);
				this.tokenPerPage = PropertyUtils.getProperty(properties, ConfigParameters.TOKEN_PER_PAGE);

				this.validationWhenNoSessionExists = PropertyUtils.getProperty(properties, ConfigParameters.VALIDATE_WHEN_NO_SESSION_EXISTS);
				this.domainOrigin = PropertyUtils.getProperty(properties, ConfigParameters.DOMAIN_ORIGIN);
				this.tokenPerPagePrecreate = PropertyUtils.getProperty(properties, ConfigParameters.TOKEN_PER_PAGE_PRECREATE);

				this.prng = getSecureRandomInstance(properties);

				this.printConfig = PropertyUtils.getProperty(properties, ConfigParameters.PRINT_ENABLED);

				this.protect = PropertyUtils.getProperty(properties, ConfigParameters.CSRFGUARD_PROTECT);

				this.newTokenLandingPage = PropertyUtils.getProperty(properties, ConfigParameters.NEW_TOKEN_LANDING_PAGE);
				this.useNewTokenLandingPage = PropertyUtils.getProperty(properties, ConfigParameters.getUseNewTokenLandingPage(this.newTokenLandingPage));

				this.ajax = PropertyUtils.getProperty(properties, ConfigParameters.AJAX_ENABLED);

				this.pageTokenSynchronizationTolerance = PropertyUtils.getProperty(properties, ConfigParameters.PAGE_TOKEN_SYNCHRONIZATION_TOLERANCE);

				initializeTokenPersistenceConfigurations(properties);

				initializeActionParameters(properties, instantiateActions(properties));

				initializePageProtection(properties);

				initializeMethodProtection(properties);
			}
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
    public boolean isJavascriptInjectIntoDynamicallyCreatedNodes() {
		this.javascriptInitParamsIfNeeded();
		return this.isJavascriptInjectIntoDynamicallyCreatedNodes;
    }

    @Override
    public String getJavascriptDynamicNodeCreationEventName() {
		this.javascriptInitParamsIfNeeded();
		return this.javascriptDynamicNodeCreationEventName;
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
	public LogicalSessionExtractor getLogicalSessionExtractor() {
		return this.logicalSessionExtractor;
	}

    @Override
    public Duration getPageTokenSynchronizationTolerance() {
        return this.pageTokenSynchronizationTolerance;
    }

    private Map<String, IAction> instantiateActions(final Properties properties) throws InstantiationException, IllegalAccessException {
		final Map<String, IAction> actionsMap = new HashMap<>();

		for (final Object obj : properties.keySet()) {
			final String propertyKey = (String) obj;

			final String actionProperty = getPrimaryPropertyDirective(propertyKey, ConfigParameters.ACTION_PREFIX);

			if (Objects.nonNull(actionProperty)) {
				final String actionClass = PropertyUtils.getProperty(properties, propertyKey);
				final IAction action = CsrfGuardUtils.<IAction>forName(actionClass).newInstance();

				action.setName(actionProperty);
				actionsMap.put(action.getName(), action);
				this.actions.add(action);
			}
		}
		return actionsMap;
	}

	private void initializeMethodProtection(final Properties properties) {
		this.protectedMethods.addAll(initializeMethodProtection(properties, ConfigParameters.PROTECTED_METHODS));
		this.unprotectedMethods.addAll(initializeMethodProtection(properties, ConfigParameters.UNPROTECTED_METHODS));

		final HashSet<String> intersection = new HashSet<>(this.protectedMethods);
		intersection.retainAll(this.unprotectedMethods);

		if (!intersection.isEmpty()) {
			throw new IllegalArgumentException(String.format("The %s HTTP method(s) cannot be both protected and unprotected.", intersection.toString()));
		}
	}

	private static Set<String> initializeMethodProtection(final Properties properties, final String configParameterName) {
		final String methodProtectionValue = PropertyUtils.getProperty(properties, configParameterName);
		if (StringUtils.isNotBlank(methodProtectionValue)) {
			final Set<String> httpMethods = Arrays.stream(methodProtectionValue.split(",")).map(String::trim).collect(Collectors.toSet());
			HttpMethod.validate(httpMethods);
			return httpMethods;
		}
		return Collections.emptySet();
	}

	private void initializePageProtection(final Properties properties) {
		for (final Object obj : properties.keySet()) {
			final String propertyKey = (String) obj;

			final String protectedPage = getPageProperty(properties, propertyKey, ConfigParameters.PROTECTED_PAGE_PREFIX);

			if (Objects.nonNull(protectedPage)) {
				this.protectedPages.add(protectedPage);
			} else {
				final String unProtectedPage = getPageProperty(properties, propertyKey, ConfigParameters.UNPROTECTED_PAGE_PREFIX);
				if (Objects.nonNull(unProtectedPage)) {
					this.unprotectedPages.add(unProtectedPage);
				}
			}
		}
	}

	private void initializeActionParameters(final Properties properties, final Map<String, IAction> actionsMap) throws IOException {
		for (final Object obj : properties.keySet()) {
			final String propertyKey = (String) obj;

			final Pair<String, Integer> actionParameterProperty = getParameterPropertyDirective(propertyKey, ConfigParameters.ACTION_PREFIX);

			if (Objects.nonNull(actionParameterProperty)) {
				final String directive = actionParameterProperty.getKey();
				final int index = actionParameterProperty.getValue();

				final String actionName = directive.substring(0, index);
				final IAction action = actionsMap.get(actionName);

				final String parameterName = directive.substring(index + 1);
				final String parameterValue = PropertyUtils.getProperty(properties, propertyKey);

				action.setParameter(parameterName, parameterValue);
			}
		}

		/* ensure at least one action was defined */
		if (this.actions.isEmpty()) {
			throw new IOException("At least one action that will be called in case of CSRF attacks must be defined!");
		}
	}

	private static Pair<String, Integer> getParameterPropertyDirective(final String propertyKey, final String propertyKeyPrefix) {
		return getPropertyDirective(propertyKey, propertyKeyPrefix, i -> i >= 0);
	}

	private static String getPrimaryPropertyDirective(final String propertyKey, final String propertyKeyPrefix) {
		final Pair<String, Integer> propertyDirective = getPropertyDirective(propertyKey, propertyKeyPrefix, i -> i < 0);

		return Objects.isNull(propertyDirective) ? null : propertyDirective.getKey();
	}

	private static Pair<String, Integer> getPropertyDirective(final String propertyKey, final String propertyKeyPrefix, final IntPredicate directivePredicate) {
		Pair<String, Integer> result = null;
		if (propertyKey.startsWith(propertyKeyPrefix)) {
			final String directive = propertyKey.substring(propertyKeyPrefix.length());
			final int index = directive.indexOf('.');

			if (directivePredicate.test(index)) {
				result = Pair.of(directive, index);
			}
		}

		return result;
	}

	private String getPageProperty(final Properties properties, final String propertyKey, final String propertyKeyPrefix) {
		String result = null;
		final String pageProperty = getPrimaryPropertyDirective(propertyKey, propertyKeyPrefix);

		if (Objects.nonNull(pageProperty)) {
			final String pageUri = PropertyUtils.getProperty(properties, propertyKey);

			result = isSpecialUriDescriptor(pageUri) ? pageUri
													 : CsrfGuardUtils.normalizeResourceURI(pageUri);
		}

		return result;
	}

	/**
	 * Decides whether the given resourceUri is a static descriptor or a matching rule
	 * Has to be in sync with org.owasp.csrfguard.CsrfValidator.isUriMatch(java.lang.String, java.lang.String) and calculatePageTokenForUri in the JS logic
	 */
	private boolean isSpecialUriDescriptor(final String resourceUri) {
		if (this.tokenPerPage && (resourceUri.endsWith("/*") || resourceUri.startsWith("*."))) {
			// FIXME implement in the JS logic (calculatePageTokenForUri)
			this.logger.log(LogLevel.Warning, "'Extension' and 'partial path wildcard' matching for page tokens is not supported properly yet! " +
											  "Every resource will be assigned a new unique token instead of using the defined resource matcher token. " +
											  "Although this is not a security issue, in case of a large REST application it can have an impact on performance." +
											  "Consider using regular expressions instead.");
		}

		return RegexValidationUtil.isTestPathRegex(resourceUri) || resourceUri.startsWith("/*") || resourceUri.endsWith("/*") || resourceUri.startsWith("*.");
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
				this.isJavascriptInjectIntoDynamicallyCreatedNodes = getProperty(JavaScriptConfigParameters.INJECT_INTO_DYNAMICALLY_CREATED_NODES, servletConfig);
				this.javascriptDynamicNodeCreationEventName = getProperty(JavaScriptConfigParameters.DYNAMIC_NODE_CREATION_EVENT_NAME, servletConfig);
				this.javascriptRefererPattern = Pattern.compile(getProperty(JavaScriptConfigParameters.REFERER_PATTERN, servletConfig));
				this.javascriptRefererMatchProtocol = getProperty(JavaScriptConfigParameters.REFERER_MATCH_PROTOCOL, servletConfig);
				this.javascriptRefererMatchDomain = getProperty(JavaScriptConfigParameters.REFERER_MATCH_DOMAIN, servletConfig);
				this.javascriptUnprotectedExtensions = getProperty(JavaScriptConfigParameters.UNPROTECTED_EXTENSIONS, servletConfig);
				this.javascriptSourceFile = getProperty(JavaScriptConfigParameters.SOURCE_FILE, servletConfig);
				this.javascriptXrequestedWith = getProperty(JavaScriptConfigParameters.X_REQUESTED_WITH, servletConfig);

				if (StringUtils.isBlank(this.javascriptSourceFile)) {
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

	private void initializeTokenPersistenceConfigurations(final Properties properties) throws InstantiationException, IllegalAccessException {
		final String logicalSessionExtractorName = PropertyUtils.getProperty(properties, ConfigParameters.LOGICAL_SESSION_EXTRACTOR_NAME);
		if (StringUtils.isNoneBlank(logicalSessionExtractorName)) {
			this.logicalSessionExtractor = CsrfGuardUtils.<LogicalSessionExtractor>forName(logicalSessionExtractorName).newInstance();

			final String tokenHolderClassName = StringUtils.defaultIfBlank(PropertyUtils.getProperty(properties, ConfigParameters.TOKEN_HOLDER), ConfigParameters.TOKEN_HOLDER.getValue());
			this.tokenHolder = CsrfGuardUtils.<TokenHolder>forName(tokenHolderClassName).newInstance();
		} else {
			throw new IllegalArgumentException(String.format("Mandatory parameter [%s] is missing from the configuration!", ConfigParameters.LOGICAL_SESSION_EXTRACTOR_NAME));
		}
	}

	private int getTokenLength(final Properties properties) {
		final int tokenLength = PropertyUtils.getProperty(properties, ConfigParameters.TOKEN_LENGTH);

		if (tokenLength < 4) {
			throw new IllegalArgumentException("The token length cannot be less than 4 characters. The recommended default value is: " + ConfigParameters.TOKEN_LENGTH.getDefaultValue());
		}

		return tokenLength;
	}

    private SecureRandom getSecureRandomInstance(final Properties properties) {
        final String algorithm = PropertyUtils.getProperty(properties, ConfigParameters.PRNG);
        final String provider = PropertyUtils.getProperty(properties, ConfigParameters.PRNG_PROVIDER);

        return getSecureRandomInstance(algorithm, provider);
    }

    private SecureRandom getSecureRandomInstance(final String algorithm, final String provider) {
		SecureRandom secureRandom;
		try {
			if (Objects.nonNull(provider)) {
				secureRandom = Objects.nonNull(algorithm) ? SecureRandom.getInstance(algorithm, provider) : getDefaultSecureRandom();
			} else {
				secureRandom = Objects.nonNull(algorithm) ? SecureRandom.getInstance(algorithm) : getDefaultSecureRandom();
			}
		} catch (final NoSuchProviderException e) {
			this.logger.log(LogLevel.Warning, String.format("The configured Secure Random Provider '%s' was not found, trying default providers.", provider));
			this.logger.log(LogLevel.Info, getAvailableSecureRandomProvidersAndAlgorithms());

			secureRandom = getSecureRandomInstance(algorithm, null);
			logDefaultPrngProviderAndAlgorithm(secureRandom);
		} catch (final NoSuchAlgorithmException nse) {
			this.logger.log(LogLevel.Warning, String.format("The configured Secure Random Algorithm '%s' was not found, reverting to system defaults.", algorithm));
			this.logger.log(LogLevel.Info, getAvailableSecureRandomProvidersAndAlgorithms());

			secureRandom = getSecureRandomInstance(null, null);
		}
		return secureRandom;
	}

	private SecureRandom getDefaultSecureRandom() {
		final SecureRandom defaultSecureRandom = new SecureRandom();
		logDefaultPrngProviderAndAlgorithm(defaultSecureRandom);
		return defaultSecureRandom;
	}

	private void logDefaultPrngProviderAndAlgorithm(final SecureRandom defaultSecureRandom) {
		this.logger.log(LogLevel.Info, String.format("Using default Secure Random Provider '%s' and '%s' Algorithm.", defaultSecureRandom.getProvider().getName(), defaultSecureRandom.getAlgorithm()));
	}

	private static String getAvailableSecureRandomProvidersAndAlgorithms() {
		final String prefix = "Available Secure Random providers and algorithms:" + System.lineSeparator();
		return Stream.of(Security.getProviders())
					 .map(Provider::getServices)
					 .flatMap(Collection::stream)
					 .filter(service -> SecureRandom.class.getSimpleName().equals(service.getType()))
					 .map(service -> String.format("\tProvider: %s | Algorithm: %s", service.getProvider().getName(), service.getAlgorithm()))
					 .collect(Collectors.joining(System.lineSeparator(), prefix, StringUtils.EMPTY));
	}
}
