/**
 * @author mchyzer
 * $Id$
 */
package org.owasp.csrfguard.config;

import java.util.Properties;

/**
 *
 */
public class PropertiesConfigurationProviderFactory implements
		ConfigurationProviderFactory {

	/**
	 * 
	 */
	public PropertiesConfigurationProviderFactory() {
	}

	/**
	 * cache this since it doesnt change
	 */
	private static ConfigurationProvider configurationProvider = null;
	
	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProviderFactory#retrieveConfiguration(java.util.Properties)
	 */
	public ConfigurationProvider retrieveConfiguration(Properties properties) {
		if (configurationProvider == null) {
			try {
				configurationProvider = new PropertiesConfigurationProvider(properties);
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		}
		return configurationProvider;
	}

}
