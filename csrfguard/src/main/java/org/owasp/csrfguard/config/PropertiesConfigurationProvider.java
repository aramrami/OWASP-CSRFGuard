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
package org.owasp.csrfguard.config;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;

import javax.servlet.ServletConfig;

import org.owasp.csrfguard.CsrfGuardServletContextListener;
import org.owasp.csrfguard.action.IAction;
import org.owasp.csrfguard.log.ILogger;
import org.owasp.csrfguard.servlet.JavaScriptServlet;
import org.owasp.csrfguard.util.CsrfGuardUtils;

/**
 * ConfifgurationProvider based on a java.util.Properties object.
 *
 */
public class PropertiesConfigurationProvider implements ConfigurationProvider {

	private final static String ACTION_PREFIX = "org.owasp.csrfguard.action.";

	private final static String PROTECTED_PAGE_PREFIX = "org.owasp.csrfguard.protected.";
	
	private final static String UNPROTECTED_PAGE_PREFIX = "org.owasp.csrfguard.unprotected.";

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
	
	private Properties propertiesCache;
	
	private String domainOrigin;
	
	public PropertiesConfigurationProvider(Properties properties) {
		try {
			this.propertiesCache = properties;
			actions = new ArrayList<IAction>();
			protectedPages = new HashSet<String>();
			unprotectedPages = new HashSet<String>();
			protectedMethods = new HashSet<String>();
			unprotectedMethods = new HashSet<String>();
			/** load simple properties **/
			logger = (ILogger) Class.forName(propertyString(properties, "org.owasp.csrfguard.Logger", "org.owasp.csrfguard.log.ConsoleLogger")).newInstance();
			tokenName = propertyString(properties, "org.owasp.csrfguard.TokenName", "OWASP-CSRFGUARD");
			tokenLength = Integer.parseInt(propertyString(properties, "org.owasp.csrfguard.TokenLength", "32"));
			rotate = Boolean.valueOf(propertyString(properties, "org.owasp.csrfguard.Rotate", "false"));
			tokenPerPage = Boolean.valueOf(propertyString(properties, "org.owasp.csrfguard.TokenPerPage", "false"));

			this.validationWhenNoSessionExists = Boolean.valueOf(propertyString(properties, "org.owasp.csrfguard.ValidateWhenNoSessionExists", "true"));
			this.domainOrigin = propertyString(properties, "org.owasp.csrfguard.domainOrigin", null);
			tokenPerPagePrecreate = Boolean.valueOf(propertyString(properties, "org.owasp.csrfguard.TokenPerPagePrecreate", "false"));
			prng = SecureRandom.getInstance(propertyString(properties, "org.owasp.csrfguard.PRNG", "SHA1PRNG"), propertyString(properties, "org.owasp.csrfguard.PRNG.Provider", "SUN"));
			newTokenLandingPage = propertyString(properties, "org.owasp.csrfguard.NewTokenLandingPage");
	
			printConfig = Boolean.valueOf(propertyString(properties, "org.owasp.csrfguard.Config.Print", "false"));

			this.enabled = Boolean.valueOf(propertyString(properties, "org.owasp.csrfguard.Enabled", "true"));
			
			//default to false if newTokenLandingPage is not set; default to true if set.
			if (newTokenLandingPage == null) {
				useNewTokenLandingPage = Boolean.valueOf(propertyString(properties, "org.owasp.csrfguard.UseNewTokenLandingPage", "false"));
			} else {
				useNewTokenLandingPage = Boolean.valueOf(propertyString(properties, "org.owasp.csrfguard.UseNewTokenLandingPage", "true"));
			}
			sessionKey = propertyString(properties, "org.owasp.csrfguard.SessionKey", "OWASP_CSRFGUARD_KEY");
			ajax = Boolean.valueOf(propertyString(properties, "org.owasp.csrfguard.Ajax", "false"));
			protect = Boolean.valueOf(propertyString(properties, "org.owasp.csrfguard.Protect", "false"));
	
			/** first pass: instantiate actions **/
			Map<String, IAction> actionsMap = new HashMap<String, IAction>();
	
			for (Object obj : properties.keySet()) {
				String key = (String) obj;
	
				if (key.startsWith(ACTION_PREFIX)) {
					String directive = key.substring(ACTION_PREFIX.length());
					int index = directive.indexOf('.');
	
					/** action name/class **/
					if (index < 0) {
						String actionClass = propertyString(properties, key);
						IAction action = (IAction) Class.forName(actionClass).newInstance();
	
						action.setName(directive);
						actionsMap.put(action.getName(), action);
						actions.add(action);
					}
				}
			}
	
			/** second pass: initialize action parameters **/
			for (Object obj : properties.keySet()) {
				String key = (String) obj;
	
				if (key.startsWith(ACTION_PREFIX)) {
					String directive = key.substring(ACTION_PREFIX.length());
					int index = directive.indexOf('.');
	
					/** action name/class **/
					if (index >= 0) {
						String actionName = directive.substring(0, index);
						IAction action = actionsMap.get(actionName);
	
						if (action == null) {
							throw new IOException(String.format("action class %s has not yet been specified", actionName));
						}
	
						String parameterName = directive.substring(index + 1);
						String parameterValue = propertyString(properties, key);
	
						action.setParameter(parameterName, parameterValue);
					}
				}
			}
	
			/** ensure at least one action was defined **/
			if (actions.size() <= 0) {
				throw new IOException("failure to define at least one action");
			}
	
			/** initialize protected, unprotected pages **/
			for (Object obj : properties.keySet()) {
				String key = (String) obj;
				
				if (key.startsWith(PROTECTED_PAGE_PREFIX)) {
					String directive = key.substring(PROTECTED_PAGE_PREFIX.length());
					int index = directive.indexOf('.');
	
					/** page name/class **/
					if (index < 0) {
						String pageUri = propertyString(properties, key);
						
						protectedPages.add(pageUri);
					}
				}
	
				if (key.startsWith(UNPROTECTED_PAGE_PREFIX)) {
					String directive = key.substring(UNPROTECTED_PAGE_PREFIX.length());
					int index = directive.indexOf('.');
	
					/** page name/class **/
					if (index < 0) {
						String pageUri = propertyString(properties, key);
						
						unprotectedPages.add(pageUri);
					}
				}
			}
	
			/** initialize protected methods **/
			String methodList = propertyString(properties, "org.owasp.csrfguard.ProtectedMethods");
			if (methodList != null && methodList.trim().length() != 0) {
				for (String method : methodList.split(",")) {
					protectedMethods.add(method.trim());
				}
			}
			/** initialize unprotected methods **/
			methodList = propertyString(properties, "org.owasp.csrfguard.UnprotectedMethods");
			if (methodList != null && methodList.trim().length() != 0) {
				for (String method : methodList.split(",")) {
					unprotectedMethods.add(method.trim());
				}
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	private boolean javascriptParamsInitted = false;
	
	private void javascriptInitParamsIfNeeded() {
		if (!this.javascriptParamsInitted) {
			ServletConfig servletConfig = JavaScriptServlet.getStaticServletConfig();
			
			if (servletConfig != null) {
				
				this.javascriptCacheControl = CsrfGuardUtils.getInitParameter(servletConfig, "cache-control",  
						propertyString(this.propertiesCache, "org.owasp.csrfguard.JavascriptServlet.cacheControl"), "private, maxage=28800");
				this.javascriptDomainStrict = Boolean.valueOf(CsrfGuardUtils.getInitParameter(servletConfig, "domain-strict",  
						propertyString(this.propertiesCache, "org.owasp.csrfguard.JavascriptServlet.domainStrict"), "true"));
				this.javascriptInjectIntoAttributes = Boolean.valueOf(CsrfGuardUtils.getInitParameter(servletConfig, "inject-into-attributes",  
						propertyString(this.propertiesCache, "org.owasp.csrfguard.JavascriptServlet.injectIntoAttributes"), "true"));

				this.javascriptInjectGetForms = Boolean.valueOf(CsrfGuardUtils.getInitParameter(servletConfig, "inject-get-forms",  
						propertyString(this.propertiesCache, "org.owasp.csrfguard.JavascriptServlet.injectGetForms"), "true"));

				this.javascriptInjectFormAttributes = Boolean.valueOf(CsrfGuardUtils.getInitParameter(servletConfig, "inject-form-attributes",  
						propertyString(this.propertiesCache, "org.owasp.csrfguard.JavascriptServlet.injectFormAttributes"), "true"));

				this.javascriptInjectIntoForms = Boolean.valueOf(CsrfGuardUtils.getInitParameter(servletConfig, "inject-into-forms",  
						propertyString(this.propertiesCache, "org.owasp.csrfguard.JavascriptServlet.injectIntoForms"), "true"));
				
				this.javascriptRefererPattern = Pattern.compile(CsrfGuardUtils.getInitParameter(servletConfig, "referer-pattern",  
						propertyString(this.propertiesCache, "org.owasp.csrfguard.JavascriptServlet.refererPattern"), ".*"));

				this.javascriptRefererMatchProtocol = Boolean.valueOf(CsrfGuardUtils.getInitParameter(servletConfig, "referer-match-protocol",
						propertyString(this.propertiesCache, "org.owasp.csrfguard.JavascriptServlet.refererMatchProtocol"), "true"));

				this.javascriptRefererMatchDomain = Boolean.valueOf(CsrfGuardUtils.getInitParameter(servletConfig, "referer-match-domain",  
						propertyString(this.propertiesCache, "org.owasp.csrfguard.JavascriptServlet.refererMatchDomain"), "true"));
				
				/* unprotectedExtensions - default to none unless specified */
				this.javascriptUnprotectedExtensions = CsrfGuardUtils.getInitParameter(servletConfig, "unprotected-extensions",  
						propertyString(this.propertiesCache, "org.owasp.csrfguard.JavascriptServlet.UnprotectedExtensions"), "");

				this.javascriptSourceFile = CsrfGuardUtils.getInitParameter(servletConfig, "source-file",
						propertyString(this.propertiesCache, "org.owasp.csrfguard.JavascriptServlet.sourceFile"), null);
				this.javascriptXrequestedWith = CsrfGuardUtils.getInitParameter(servletConfig, "x-requested-with",  
						propertyString(this.propertiesCache, "org.owasp.csrfguard.JavascriptServlet.xRequestedWith"), "OWASP CSRFGuard Project");
	            if(this.javascriptSourceFile == null) {
	                this.javascriptTemplateCode = CsrfGuardUtils.readResourceFileContent("META-INF/csrfguard.js", true);
	            } else if (this.javascriptSourceFile.startsWith("META-INF/")) {
	                this.javascriptTemplateCode = CsrfGuardUtils.readResourceFileContent(this.javascriptSourceFile, true);
	            } else if (this.javascriptSourceFile.startsWith("classpath:")) {
	                final String location = this.javascriptSourceFile.substring("classpath:".length()).trim();
	                this.javascriptTemplateCode = CsrfGuardUtils.readResourceFileContent(location, true);
	            } else if (this.javascriptSourceFile.startsWith("file:")) {
	                final String location = this.javascriptSourceFile.substring("file:".length()).trim();
	                this.javascriptTemplateCode = CsrfGuardUtils.readFileContent(location);
	            } else if (servletConfig.getServletContext().getRealPath(this.javascriptSourceFile) != null) {
	            	this.javascriptTemplateCode = CsrfGuardUtils.readFileContent(
	            			servletConfig.getServletContext().getRealPath(this.javascriptSourceFile));
	            } else {
                    throw new IllegalStateException("getRealPath failed for file " + this.javascriptSourceFile);
                }
										
	    		this.javascriptParamsInitted = true;
			}
		}
	}

	/**
	 * property string and substitutions
	 * @param properties The properties from which to fetch a value
	 * @param propertyName The name of the desired property
	 * @return the value, with common substitutions performed
	 * @see #commonSubstitutions(String)
	 */
	public static String propertyString(Properties properties, String propertyName) {
		String value = properties.getProperty(propertyName);
		value = commonSubstitutions(value);
		return value;
	}

	/**
	 * property string and substitutions
	 * @param properties The properties from which to fetch a value
	 * @param propertyName The name of the desired property
	 * @param defaultValue The value to use when the propertyName does not exist
	 * @return the value, with common substitutions performed
	 * @see #commonSubstitutions(String)
	 */
	public static String propertyString(Properties properties, String propertyName, String defaultValue) {
		String value = properties.getProperty(propertyName, defaultValue);
		value = commonSubstitutions(value);
		return value;
	}
	
	public ILogger getLogger() {
		return logger;
	}

	public String getTokenName() {
		return tokenName;
	}

	public int getTokenLength() {
		return tokenLength;
	}

	public boolean isRotateEnabled() {
		return rotate;
	}

	/**
	 * @see ConfigurationProvider#isValidateWhenNoSessionExists()
	 */
	@Override
	public boolean isValidateWhenNoSessionExists() {
		return this.validationWhenNoSessionExists;
	}

	/**
	 * If csrf guard filter should check even if there is no session for the user
	 * Note: this changed in 2014/04, the default behavior used to be to 
	 * not check if there is no session.  If you want the legacy behavior (if your app
	 * is not susceptible to CSRF if the user has no session), set this to false
	 */
	private final boolean validationWhenNoSessionExists;
	
	public boolean isTokenPerPageEnabled() {
		return tokenPerPage;
	}

	public boolean isTokenPerPagePrecreateEnabled() {
		return tokenPerPagePrecreate;
	}

	public SecureRandom getPrng() {
		return prng;
	}

	public String getNewTokenLandingPage() {
		return newTokenLandingPage;
	}

	public boolean isUseNewTokenLandingPage() {
		return useNewTokenLandingPage;
	}

	public boolean isAjaxEnabled() {
		return ajax;
	}

	public boolean isProtectEnabled() {
		return protect;
	}

	public String getSessionKey() {
		return sessionKey;
	}

	public Set<String> getProtectedPages() {
		return protectedPages;
	}

	public Set<String> getUnprotectedPages() {
		return unprotectedPages;
	}

	public Set<String> getProtectedMethods () {
		return protectedMethods;
	}

	/**
	 * if there are methods here, they are unprotected (e.g. GET), and all others are protected
	 * @return the unprotected methods
	 */
	@Override
	public Set<String> getUnprotectedMethods () {
		return this.unprotectedMethods;
	}

	public List<IAction> getActions() {
		return actions;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#isPrintConfig()
	 */
	public boolean isPrintConfig() {
		return this.printConfig;
	}

	private String javascriptTemplateCode;

	private String javascriptSourceFile;
	
	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#getJavascriptSourceFile()
	 */
	@Override
	public String getJavascriptSourceFile() {
		this.javascriptInitParamsIfNeeded();
		return javascriptSourceFile;
	}

	private boolean javascriptDomainStrict;
	
	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#isJavascriptDomainStrict()
	 */
	@Override
	public boolean isJavascriptDomainStrict() {
		this.javascriptInitParamsIfNeeded();
		return javascriptDomainStrict;
	}

	private String javascriptCacheControl;
	
	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#getJavascriptCacheControl()
	 */
	@Override
	public String getJavascriptCacheControl() {
		this.javascriptInitParamsIfNeeded();
		return javascriptCacheControl;
	}

	private Pattern javascriptRefererPattern;
	
	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#getJavascriptRefererPattern()
	 */
	@Override
	public Pattern getJavascriptRefererPattern() {
		this.javascriptInitParamsIfNeeded();
		return javascriptRefererPattern;
	}

	private boolean javascriptInjectIntoForms;

	private boolean javascriptRefererMatchProtocol;

	/**
	 * if the referer must match domain
	 */
	private boolean javascriptRefererMatchDomain;

	/**
	 * if the referer protocol must match protocol on the domain
	 * @return the isJavascriptRefererMatchProtocol
	 */
	@Override
	public boolean isJavascriptRefererMatchProtocol() {
		this.javascriptInitParamsIfNeeded();
		return this.javascriptRefererMatchProtocol;
	}

	/**
	 * if the referer must match domain
	 * @return the javascriptRefererMatchDomain
	 */
	@Override
	public boolean isJavascriptRefererMatchDomain() {
		this.javascriptInitParamsIfNeeded();
		return this.javascriptRefererMatchDomain;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#isJavascriptInjectIntoForms()
	 */
	@Override
	public boolean isJavascriptInjectIntoForms() {
		this.javascriptInitParamsIfNeeded();
		return javascriptInjectIntoForms;
	}

	private boolean javascriptInjectIntoAttributes;
	
	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#isJavascriptInjectIntoAttributes()
	 */
	@Override
	public boolean isJavascriptInjectIntoAttributes() {
		this.javascriptInitParamsIfNeeded();
		return this.javascriptInjectIntoAttributes;
	}

	private String javascriptXrequestedWith;
	
	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#getJavascriptXrequestedWith()
	 */
	@Override
	public String getJavascriptXrequestedWith() {
		this.javascriptInitParamsIfNeeded();
		return javascriptXrequestedWith;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#getJavascriptTemplateCode()
	 */
	@Override
	public String getJavascriptTemplateCode() {
		this.javascriptInitParamsIfNeeded();
		return this.javascriptTemplateCode;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#isCacheable()
	 */
	public boolean isCacheable() {
		//dont cache this until the javascript params are all set
		//i.e. the javascript servlet is 
		return this.javascriptParamsInitted;
	}


	/**
	 * Replaces percent-bounded expressions such as "%servletContext%."
	 * common subsitutions in config values
	 * @param input A string with expressions that should be replaced
	 * @return new string with "common" expressions replaced by configuration values
	 */
	public static String commonSubstitutions(String input) {
		if (input == null || !input.contains("%")) {
			return input;
		}
		input = input.replace("%servletContext%", CsrfGuardUtils.defaultString(CsrfGuardServletContextListener.getServletContext()));
		return input;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#isEnabled()
	 */
	@Override
	public boolean isEnabled() {
		return this.enabled;
	}
	
	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#isJavascriptInjectGetForms()
	 */
	private boolean javascriptInjectGetForms;
	
	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#isJavascriptInjectGetForms()
	 */
	public boolean isJavascriptInjectGetForms() {
		this.javascriptInitParamsIfNeeded();
		return this.javascriptInjectGetForms;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#isJavascriptInjectFormAttributes()
	 */
	private boolean javascriptInjectFormAttributes;
	
	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#isJavascriptInjectFormAttributes()
	 */
	public boolean isJavascriptInjectFormAttributes() {
		this.javascriptInitParamsIfNeeded();
		return this.javascriptInjectFormAttributes;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#getDomainOrigin()
	 */
	@Override
	public String getDomainOrigin() {
		return domainOrigin;
	}
	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#getDomainOrigin()
	 */
	private String javascriptUnprotectedExtensions;
	
	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#getDomainOrigin()
	 */
	@Override
	public String getJavascriptUnprotectedExtensions() {
		this.javascriptInitParamsIfNeeded();
		return this.javascriptUnprotectedExtensions;
	}
}
