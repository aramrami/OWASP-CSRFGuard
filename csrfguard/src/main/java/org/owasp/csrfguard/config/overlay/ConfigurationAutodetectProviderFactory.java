/**
 * @author mchyzer
 * $Id$
 */
package org.owasp.csrfguard.config.overlay;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.owasp.csrfguard.config.ConfigurationProvider;
import org.owasp.csrfguard.config.ConfigurationProviderFactory;
import org.owasp.csrfguard.config.PropertiesConfigurationProviderFactory;
import org.owasp.csrfguard.util.CsrfGuardUtils;

/**
 * The default configuration provider is: org.owasp.csrfguard.config.overlay.ConfigurationAutodetectProviderFactory
 * which will look for an overlay file, it is there, and the factory inside that file is set it will use it, otherwise will be PropertiesConfigurationProviderFactory
 * it needs to implement org.owasp.csrfguard.config.ConfigurationProviderFactory
 */
public class ConfigurationAutodetectProviderFactory implements
		ConfigurationProviderFactory {

	/**
	 * 
	 */
	public ConfigurationAutodetectProviderFactory() {
	}

	/**
	 * configuration provider cached
	 */
	private static ExpirableCache<Boolean, ConfigurationProvider> configurationProviderCache = new ExpirableCache<Boolean, ConfigurationProvider>(2);
	
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
						CsrfGuardUtils.closeQuietly(inputStream);
						
						String factoryClassName = theProperties.getProperty("org.owasp.csrfguard.configuration.provider.factory");
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
