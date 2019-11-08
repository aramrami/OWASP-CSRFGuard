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
     * Called when retrieving the configuration
     *
     * @param properties describing the configuration
     * @return the configuration
     */
    ConfigurationProvider retrieveConfiguration(Properties properties);

}
