/**
 * @author mchyzer
 * $Id$
 */
package org.owasp.csrfguard.config.overlay;

import java.util.Properties;

import org.owasp.csrfguard.config.ConfigurationProvider;
import org.owasp.csrfguard.config.ConfigurationProviderFactory;
import org.owasp.csrfguard.config.PropertiesConfigurationProvider;

/**
 *
 */
public class ConfigurationOverlayProviderFactory implements
		ConfigurationProviderFactory {

	/**
	 * 
	 */
	public ConfigurationOverlayProviderFactory() {
	}

	/**
	 * @see org.owasp.csrfguard.config.ConfigurationProviderFactory#retrieveConfiguration(java.util.Properties)
	 */
	public ConfigurationProvider retrieveConfiguration(Properties originalProperties) {
		ConfigurationOverlayProvider configurationOverlayProvider = ConfigurationOverlayProvider.retrieveConfig();
		Properties properties = configurationOverlayProvider.properties();
		
		return new PropertiesConfigurationProvider(properties);
    }
	
}
