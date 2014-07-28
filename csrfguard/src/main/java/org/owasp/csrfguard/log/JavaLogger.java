package org.owasp.csrfguard.log;

import java.util.logging.Level;
import java.util.logging.Logger;

public class JavaLogger implements ILogger {

	private static final long serialVersionUID = -4857601483759096197L;
	
	private final static Logger LOGGER = Logger.getLogger("Owasp.CsrfGuard");

	@Override
	public void log(String msg) {
		LOGGER.info(msg.replaceAll("(\\r|\\n)", ""));
	}

	@Override
	public void log(LogLevel level, String msg) {
		// Remove CR and LF characters to prevent CRLF injection
		String sanitizedMsg = msg.replaceAll("(\\r|\\n)", "");
		
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
	public void log(Exception exception) {
		LOGGER.log(Level.WARNING, exception.getLocalizedMessage(), exception);
	}

	@Override
	public void log(LogLevel level, Exception exception) {
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
				LOGGER.log(Level.WARNING, exception.getLocalizedMessage(), exception);
				break;
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
