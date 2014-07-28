package org.owasp.csrfguard.util;

public final class Strings {

	public final static String EMPTY = "";
	
	private Strings() {
		/**
		 * Intentionally blank to force static usage
		 */
	}

	@Override
	public Object clone() throws CloneNotSupportedException {
		throw new CloneNotSupportedException();
	}
	
}
