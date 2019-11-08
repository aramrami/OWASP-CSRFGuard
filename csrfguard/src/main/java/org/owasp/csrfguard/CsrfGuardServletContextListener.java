package org.owasp.csrfguard;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.owasp.csrfguard.config.overlay.ConfigurationOverlayProvider;
import org.owasp.csrfguard.util.Streams;

public class CsrfGuardServletContextListener implements ServletContextListener {

	private static final String CONFIG_PARAM = "Owasp.CsrfGuard.Config";
	private static final String CONFIG_PRINT_PARAM = "Owasp.CsrfGuard.Config.Print";

	/**
	 * servlet context (will be the empty string if it is / )
	 */
	private static String servletContext = null;
	
	/**
	 * servlet context (will be the empty string if it is / )
	 * @return the servletContext
	 */
	public static String getServletContext() {
		return servletContext;
	}

	/**
	 * config file name if specified in the web.xml
	 */
	private static String configFileName = null;
	
	/**
	 * config file name if specified in the web.xml
	 * @return config file name
	 */
	public static String getConfigFileName() {
		return configFileName;
	}
	
	@Override
	public void contextInitialized(ServletContextEvent event) {
		ServletContext context = event.getServletContext();
		servletContext = context.getContextPath();
		//since this is just a prefix of a path, then if there is no servlet context, it is the empty string
		if (servletContext == null || "/".equals(servletContext)) {
			servletContext = "";
		}
		
		configFileName = context.getInitParameter(CONFIG_PARAM);

		if (configFileName == null) {
			configFileName = ConfigurationOverlayProvider.OWASP_CSRF_GUARD_PROPERTIES;
		}

		InputStream is = null;
		Properties properties = new Properties();

		try {
			is = getResourceStream(configFileName, context, false);
			
			if (is == null) {
				is = getResourceStream(ConfigurationOverlayProvider.META_INF_CSRFGUARD_PROPERTIES, context, false);
			}

			if (is == null) {
				throw new RuntimeException("Cant find default owasp csrfguard properties file: " + configFileName);
			}
			
			properties.load(is);
			CsrfGuard.load(properties);
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			Streams.close(is);
		}


		printConfigIfConfigured(context, "Printing properties before Javascript servlet, note, the javascript properties might not be initialized yet: ");
	}

	/**
	 * Prints the configuration to the ServletContext log file with the given prefix.
	 * Has no effect unless the CONFIG_PRINT_PARAM init parameter is "true."
	 * @param context The ServletContext
	 * @param prefix  The string used as a prefix when printing the configuration to the log
	 * @see javax.servlet.ServletContext#log(String)
	 */
	public static void printConfigIfConfigured(ServletContext context, String prefix) {
		String printConfig = context.getInitParameter(CONFIG_PRINT_PARAM);

		if (printConfig == null || "".equals(printConfig.trim())) {
			printConfig = CsrfGuard.getInstance().isPrintConfig() ? "true" : null;
		}
		
		if (printConfig != null && Boolean.parseBoolean(printConfig)) {
			context.log(prefix 
					+ CsrfGuard.getInstance().toString());
		}
	}

	@Override
	public void contextDestroyed(ServletContextEvent event) {
		/** nothing to do **/
	}

	private InputStream getResourceStream(String resourceName, ServletContext context, boolean failIfNotFound) throws IOException {
		InputStream is = null;

		/** try classpath **/
		is = getClass().getClassLoader().getResourceAsStream(resourceName);

		/** try web context **/
		if (is == null) {
			String fileName = context.getRealPath(resourceName);
            if (fileName != null) {
                File file = new File(fileName);

                if (file.exists()) {
                    is = new FileInputStream(fileName);
                }
            }
		}

		/** try current directory **/
		if (is == null) {
			File file = new File(resourceName);

			if (file.exists()) {
				is = new FileInputStream(resourceName);
			}
		}

		/** fail if still empty **/
		if (is == null && failIfNotFound) {
			throw new IOException(String.format("unable to locate resource - %s", resourceName));
		}

		return is;
	}

}
