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

import org.apache.commons.lang3.StringUtils;
import org.owasp.csrfguard.config.overlay.ConfigurationOverlayProvider;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import java.util.Properties;

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
	public void contextInitialized(final ServletContextEvent event) {
		final ServletContext context = event.getServletContext();
		servletContext = context.getContextPath();
		// since this is just a prefix of a path, then if there is no servlet context, it is the empty string
		if (StringUtils.equals(servletContext, "/")) {
			servletContext = "";
		}

		configFileName = context.getInitParameter(CONFIG_PARAM);

		if (configFileName == null) {
			configFileName = ConfigurationOverlayProvider.OWASP_CSRF_GUARD_PROPERTIES;
		}

		try (final InputStream configFileInputStream = getResourceStream(configFileName, context, false)) {
			if (Objects.isNull(configFileInputStream)) {
				try (final InputStream metaInfInputStream = getResourceStream(ConfigurationOverlayProvider.META_INF_CSRFGUARD_PROPERTIES, context, false)) {
					if (Objects.isNull(metaInfInputStream)) {
						throw new RuntimeException("Can't find default OWASP CSRFGuard properties file: " + configFileName);
					}

					loadProperties(metaInfInputStream);
				}
			}

			loadProperties(configFileInputStream);
		} catch (final Exception e) {
			throw new RuntimeException(e);
		}

		printConfigIfConfigured(context, "Printing properties before JavaScript servlet, note, the JavaScript properties might not be initialized yet: ");
	}

	private void loadProperties(final InputStream resourceStream) throws IOException {
		final Properties properties = new Properties();
		properties.load(resourceStream);
		CsrfGuard.load(properties);
	}

	/**
	 * Prints the configuration to the ServletContext log file with the given prefix.
	 * Has no effect unless the CONFIG_PRINT_PARAM init parameter is "true."
	 * @param context The ServletContext
	 * @param prefix  The string used as a prefix when printing the configuration to the log
	 * @see javax.servlet.ServletContext#log(String)
	 */
	public static void printConfigIfConfigured(final ServletContext context, final String prefix) {
		final CsrfGuard csrfGuard = CsrfGuard.getInstance();

		if (csrfGuard.isEnabled()) {
			String printConfig = context.getInitParameter(CONFIG_PRINT_PARAM);

			if (StringUtils.isBlank(printConfig)) {
				printConfig = csrfGuard.isPrintConfig() ? "true" : null;
			}

			if (Boolean.parseBoolean(printConfig)) {
				context.log(prefix + csrfGuard.toString());
			}
		} else {
			context.log("OWASP CSRFGuard is disabled.");
		}
	}

	@Override
	public void contextDestroyed(final ServletContextEvent event) {
		/* nothing to do */
	}

	private InputStream getResourceStream(final String resourceName, final ServletContext context, final boolean failIfNotFound) throws IOException {
		InputStream inputStream;

		/* try classpath */
		inputStream = getClass().getClassLoader().getResourceAsStream(resourceName);

		/* try web context */
		if (inputStream == null) {
			final String fileName = context.getRealPath(resourceName);
            if (fileName != null) {
                final File file = new File(fileName);

                if (file.exists()) {
                    inputStream = new FileInputStream(fileName);
                }
            }
		}

		/* try current directory */
		if (inputStream == null) {
			final File file = new File(resourceName);

			if (file.exists()) {
				inputStream = new FileInputStream(resourceName);
			}
		}

		/* fail if still empty */
		if (inputStream == null && failIfNotFound) {
			throw new IOException(String.format("unable to locate resource - %s", resourceName));
		}

		return inputStream;
	}
}
