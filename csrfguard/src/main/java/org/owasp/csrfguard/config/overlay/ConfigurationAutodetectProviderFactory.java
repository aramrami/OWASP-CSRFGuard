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

package org.owasp.csrfguard.config.overlay;

import org.owasp.csrfguard.config.properties.ConfigParameters;
import org.owasp.csrfguard.config.ConfigurationProvider;
import org.owasp.csrfguard.config.ConfigurationProviderFactory;
import org.owasp.csrfguard.config.PropertiesConfigurationProviderFactory;
import org.owasp.csrfguard.util.CsrfGuardUtils;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * The default configuration provider is: {@link org.owasp.csrfguard.config.overlay.ConfigurationAutodetectProviderFactory}
 * which will look for an overlay file, it is there, and the factory inside that file is set it will use it, otherwise will be {@link PropertiesConfigurationProviderFactory}
 * it needs to implement {@link org.owasp.csrfguard.config.ConfigurationProviderFactory}
 *
 * @author mchyzer
 */
public class ConfigurationAutodetectProviderFactory implements ConfigurationProviderFactory {

	/**
	 * TODO document
	 */
	public ConfigurationAutodetectProviderFactory() {}

	/**
	 * configuration provider cached
	 */
	private static ExpirableCache<Boolean, ConfigurationProvider> configurationProviderCache = new ExpirableCache<Boolean, ConfigurationProvider>(2); // TODO does this really reload the configurations in every 2 minutes?!
	
	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProviderFactory#retrieveConfiguration(java.util.Properties)
	 */
	public ConfigurationProvider retrieveConfiguration(Properties defaultProperties) {
		
		ConfigurationProvider configurationProvider = configurationProviderCache.get(Boolean.TRUE);
		
		if (configurationProvider == null) {
			synchronized (ConfigurationAutodetectProviderFactory.class) {
				if (configurationProvider == null) {
					
					Class<? extends ConfigurationProviderFactory> factoryClass = null;
					
					//if there is an overlay, and that specifies the factory, use that
					InputStream inputStream = getClass().getClassLoader().getResourceAsStream(ConfigurationOverlayProvider.OWASP_CSRF_GUARD_OVERLAY_PROPERTIES);
					if (inputStream != null) {
						Properties theProperties = new Properties();
						try {
							theProperties.load(inputStream);
						} catch (IOException ioe) {
							throw new RuntimeException("Error reading config file: " + ConfigurationOverlayProvider.OWASP_CSRF_GUARD_OVERLAY_PROPERTIES, ioe);
						}
						ConfigPropertiesCascadeCommonUtils.closeQuietly(inputStream);
						
						String factoryClassName = theProperties.getProperty(ConfigParameters.CONFIG_PROVIDER_FACTORY_PROPERTY_NAME);
						if (factoryClassName != null && !"".equals(factoryClassName)) {
							if (ConfigurationAutodetectProviderFactory.class.getName().equals(factoryClassName)) {
								throw new RuntimeException("Cannot specify auto detect factory in override file (recursion), pick the actual factory: " + factoryClassName);
							}
							factoryClass = CsrfGuardUtils.forName(factoryClassName);
						}
					}
					
					if (factoryClass == null) {
						factoryClass = PropertiesConfigurationProviderFactory.class;
					}
					
					ConfigurationProviderFactory factory = CsrfGuardUtils.newInstance(factoryClass);
					configurationProvider = factory.retrieveConfiguration(defaultProperties);
					configurationProviderCache.put(Boolean.TRUE, configurationProvider);
					
				}
			}
		}
		
		return configurationProvider;
	}
}
