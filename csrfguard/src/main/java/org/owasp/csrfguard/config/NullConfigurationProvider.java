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

import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import org.owasp.csrfguard.action.IAction;
import org.owasp.csrfguard.log.ConsoleLogger;
import org.owasp.csrfguard.log.ILogger;

/**
 * ConfigurationProvider which returns all null or empty values (except for the logger).
 * Used before initialization has occurred.
 */
public final class NullConfigurationProvider implements ConfigurationProvider {

	private static final ILogger logger = new ConsoleLogger();
	
	public NullConfigurationProvider() {
	}

	@Override
	public ILogger getLogger() {
		return logger;
	}

	@Override
	public String getTokenName() {
		return null;
	}

	@Override
	public int getTokenLength() {
		return 0;
	}

	@Override
	public boolean isRotateEnabled() {
		return false;
	}

	@Override
	public boolean isTokenPerPageEnabled() {
		return false;
	}

	@Override
	public boolean isTokenPerPagePrecreateEnabled() {
		return false;
	}

	@Override
	public SecureRandom getPrng() {
		try {
			return SecureRandom.getInstance("SHA1PRNG", "SUN");
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public String getNewTokenLandingPage() {
		return null;
	}

	@Override
	public boolean isUseNewTokenLandingPage() {
		return false;
	}

	@Override
	public boolean isAjaxEnabled() {
		return false;
	}

	@Override
	public boolean isProtectEnabled() {
		return false;
	}

	@Override
	public String getSessionKey() {
		return null;
	}

	@Override
	public Set<String> getProtectedPages() {
		return Collections.emptySet();
	}

	@Override
	public Set<String> getUnprotectedPages() {
		return Collections.emptySet();
	}

	@Override
	public Set<String> getProtectedMethods() {
		return Collections.emptySet();
	}

	@Override
	public List<IAction> getActions() {
		return Collections.emptyList();
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#isPrintConfig()
	 */
	@Override
	public boolean isPrintConfig() {
		return false;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#getJavascriptSourceFile()
	 */
	@Override
	public String getJavascriptSourceFile() {
		return null;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#isJavascriptDomainStrict()
	 */
	@Override
	public boolean isJavascriptDomainStrict() {
		return false;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#getJavascriptCacheControl()
	 */
	@Override
	public String getJavascriptCacheControl() {
		return null;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#getJavascriptRefererPattern()
	 */
	@Override
	public Pattern getJavascriptRefererPattern() {
		return null;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#isJavascriptInjectIntoForms()
	 */
	@Override
	public boolean isJavascriptInjectIntoForms() {
		return false;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#isJavascriptInjectIntoAttributes()
	 */
	@Override
	public boolean isJavascriptInjectIntoAttributes() {
		return false;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#getJavascriptXrequestedWith()
	 */
	@Override
	public String getJavascriptXrequestedWith() {
		return null;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#getJavascriptTemplateCode()
	 */
	@Override
	public String getJavascriptTemplateCode() {
		return null;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#isCacheable()
	 */
	public boolean isCacheable() {
		return true;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#getUnprotectedMethods()
	 */
	public Set<String> getUnprotectedMethods() {
		return Collections.emptySet();
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#isJavascriptRefererMatchProtocol()
	 */
	@Override
	public boolean isJavascriptRefererMatchProtocol() {
		return false;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#isJavascriptRefererMatchDomain()
	 */
	@Override
	public boolean isJavascriptRefererMatchDomain() {
		return false;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#isEnabled()
	 */
	@Override
	public boolean isEnabled() {
		return false;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#isValidateWhenNoSessionExists()
	 */
	@Override
	public boolean isValidateWhenNoSessionExists() {
		return false;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#isJavascriptInjectGetForms()
	 */
	public boolean isJavascriptInjectGetForms() {
		return false;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#isJavascriptInjectFormAttributes()
	 */
	public boolean isJavascriptInjectFormAttributes() {
		return false;
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#getDomainOrigin()
	 */
	@Override
	public String getDomainOrigin() {
		return null;
	}
	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProvider#getJavascriptUnprotectedExtensions()
	 */
	@Override
	public String getJavascriptUnprotectedExtensions() {
		return null;
	}
}
