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

/*
 * @author mchyzer
 * $Id$
 */
package org.owasp.csrfguard.config.overlay;

import org.apache.commons.lang3.StringUtils;
import org.owasp.csrfguard.CsrfGuardServletContextListener;
import org.owasp.csrfguard.config.properties.ConfigParameters;

import java.io.InputStream;

/**
 * Use configuration overlays that use the base properties as a default, and then decorate with an overlay file
 */
public class ConfigurationOverlayProvider extends ConfigPropertiesCascadeBase {

	/**
	 * 
	 */
	public static final String META_INF_CSRFGUARD_PROPERTIES = "META-INF/csrfguard.properties";

	/**
	 * base properties file
	 */
	public static final String OWASP_CSRF_GUARD_PROPERTIES = "Owasp.CsrfGuard.properties";

	/**
	 * ovrlay properties file
	 */
	public static final String OWASP_CSRF_GUARD_OVERLAY_PROPERTIES = "Owasp.CsrfGuard.overlay.properties";

	/**
	 * retrieve a config from the config file or from cache
	 * @return the config object
	 */
	public static ConfigurationOverlayProvider retrieveConfig() {
		return retrieveConfig(ConfigurationOverlayProvider.class);
	}

	/**
	 * 
	 */
	public ConfigurationOverlayProvider() {
	}

	@Override
	protected String getSecondsToCheckConfigKey() {
		return ConfigParameters.CONFIG_OVERLAY_UPDATE_CHECK_PROPERTY_NAME;
	}

	@Override
	protected String getMainConfigClasspath() {
		return OWASP_CSRF_GUARD_OVERLAY_PROPERTIES;
	}

	@Override
	protected String getHierarchyConfigKey() {
		return ConfigParameters.CONFIG_OVERLAY_HIERARCHY_PROPERTY_NAME;
	}

	/**
	 * see which configs are available
	 */
	private static String mainExampleConfigClasspath = null;
	
	@Override
	protected String getMainExampleConfigClasspath() {

		//do not know the answer?
		if (mainExampleConfigClasspath == null) {

			//is the main config file there?
			InputStream inputStream = getClass().getClassLoader().getResourceAsStream(OWASP_CSRF_GUARD_PROPERTIES);
			if (inputStream != null) {
				mainExampleConfigClasspath = OWASP_CSRF_GUARD_PROPERTIES;
				ConfigPropertiesCascadeCommonUtils.closeQuietly(inputStream);
			} else {
				inputStream = getClass().getClassLoader().getResourceAsStream(META_INF_CSRFGUARD_PROPERTIES);
				if (inputStream != null) {
					mainExampleConfigClasspath = META_INF_CSRFGUARD_PROPERTIES;
					ConfigPropertiesCascadeCommonUtils.closeQuietly(inputStream);
				} else {
					//hmm, its not there, but use it anyways
					mainExampleConfigClasspath = OWASP_CSRF_GUARD_PROPERTIES;
				}
			}
		}
		
		//generally this is Owasp.CsrfGuard.properties
		return StringUtils.defaultIfBlank(CsrfGuardServletContextListener.getConfigFileName(), mainExampleConfigClasspath);
	}
}
