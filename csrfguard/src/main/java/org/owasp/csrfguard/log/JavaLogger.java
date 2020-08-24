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

package org.owasp.csrfguard.log;

import java.util.logging.Level;
import java.util.logging.Logger;

public class JavaLogger implements ILogger {

	private static final long serialVersionUID = -4857601483759096197L;
	
	private final static Logger LOGGER = Logger.getLogger("Owasp.CsrfGuard");

	@Override
	public void log(final String msg) {
		LOGGER.info(msg.replaceAll("(\\r|\\n)", ""));
	}

	@Override
	public void log(final LogLevel level, final String msg) {
		// Remove CR and LF characters to prevent CRLF injection
		final String sanitizedMsg = msg.replaceAll("(\\r|\\n)", "");
		
		switch(level) {
			case Trace:
				LOGGER.finest(sanitizedMsg);
				break;
			case Debug:
				LOGGER.fine(sanitizedMsg);
				break;
			case Info:
				LOGGER.info(sanitizedMsg);
				break;
			case Warning:
				LOGGER.warning(sanitizedMsg);
				break;
			case Error:
				LOGGER.warning(sanitizedMsg);
				break;
			case Fatal:
				LOGGER.severe(sanitizedMsg);
				break;
			default:
				throw new RuntimeException("unsupported log level " + level);
		}
	}

	@Override
	public void log(final Exception exception) {
		LOGGER.log(Level.WARNING, exception.getLocalizedMessage(), exception);
	}

	@Override
	public void log(final LogLevel level, final Exception exception) {
			switch(level) {
			case Trace:
				LOGGER.log(Level.FINEST, exception.getLocalizedMessage(), exception);
				break;
			case Debug:
				LOGGER.log(Level.FINE, exception.getLocalizedMessage(), exception);
				break;
			case Info:
				LOGGER.log(Level.INFO, exception.getLocalizedMessage(), exception);
				break;
			case Warning:
			case Error:
				LOGGER.log(Level.WARNING, exception.getLocalizedMessage(), exception);
				break;
			case Fatal:
				LOGGER.log(Level.SEVERE, exception.getLocalizedMessage(), exception);
				break;
			default:
				throw new RuntimeException("unsupported log level " + level);
		}
	}
}
