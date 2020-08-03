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
