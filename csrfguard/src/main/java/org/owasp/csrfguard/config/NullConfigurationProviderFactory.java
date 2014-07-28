/**
 * @author mchyzer
 * $Id$
 */
package org.owasp.csrfguard.config;

import java.util.Properties;

/**
 *
 */
public class NullConfigurationProviderFactory implements
		ConfigurationProviderFactory {

	/**
	 * 
	 */
	public NullConfigurationProviderFactory() {
	}

	/**
	 * cache this it doesnt change
	 */
	private static ConfigurationProvider configurationProvider = null;
	
	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProviderFactory#retrieveConfiguration(java.util.Properties)
	 */
	public ConfigurationProvider retrieveConfiguration(Properties properties) {
		if (configurationProvider == null) {
			configurationProvider = new NullConfigurationProvider();
		}
		return configurationProvider;
	}

}
