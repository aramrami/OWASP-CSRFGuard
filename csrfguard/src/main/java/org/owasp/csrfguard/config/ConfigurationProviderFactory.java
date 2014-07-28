/**
 * @author mchyzer
 * $Id$
 */
package org.owasp.csrfguard.config;

import java.util.Properties;

/**
 * implement this interface to provide the configuration
 */
public interface ConfigurationProviderFactory {

	/**
	 * called when retrieving the configuration
	 * @param properties
	 * @return the configuration
	 */
	public ConfigurationProvider retrieveConfiguration(Properties properties);

}
