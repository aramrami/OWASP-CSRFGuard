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

package org.owasp.csrfguard.util;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.owasp.csrfguard.CsrfGuard;
import org.owasp.csrfguard.config.overlay.ConfigPropertiesCascadeCommonUtils;
import org.owasp.csrfguard.token.transferobject.TokenTO;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Objects;

/**
 * Various utility methods/helpers.
 */
public final class CsrfGuardUtils {

    private CsrfGuardUtils() {}

    /**
     * for a url, get the protocol and domain, e.g. for url https://a.b/path, will return https://a.b
     *
     * @param url             a string representing a URL
     * @param includeProtocol whether to include the HTTP or HTTPS protocol in the result
     * @return the path with or without the protocol
     */
    public static String httpProtocolAndDomain(final String url, final boolean includeProtocol) {
        if (includeProtocol) {
            return httpProtocolAndDomain(url);
        }

        return httpProtocolAndDomain(url.replaceFirst("^(http[s]?)://", StringUtils.EMPTY));
    }

    /**
     * <pre>Returns the class object.</pre>
     *
     * @param origClassName is fully qualified
     * @return the class
     */
    public static <T> Class<T> forName(final String origClassName) {
        try {
            return (Class<T>) Class.forName(origClassName);
        } catch (final Throwable t) {
            throw new RuntimeException("Problem loading class: " + origClassName, t);
        }
    }

    public static String readResourceFileContent(final String resourceName) {
        try (final InputStream inputStream = CsrfGuardUtils.class.getClassLoader().getResourceAsStream(resourceName)) {
            if (inputStream == null) {
                throw new IllegalStateException("Could not find resource " + resourceName);
            } else {
                return readInputStreamContent(inputStream);
            }
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static String readFileContent(final String fileNameWithAbsolutePath) {
        try (final InputStream inputStream = new FileInputStream(fileNameWithAbsolutePath)) {
            return readInputStreamContent(inputStream);
        } catch (final IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    /**
     * Construct a class
     *
     * @param <T>      template type
     * @param theClass the class on which to invoke newInstance()
     * @return the instance
     */
    public static <T> T newInstance(final Class<T> theClass) {
        return ConfigPropertiesCascadeCommonUtils.newInstance(theClass);
    }

    public static void addResponseTokenHeader(final CsrfGuard csrfGuard, final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse, final TokenTO tokenTO) {
        if (csrfGuard.isAjaxEnabled() && CsrfGuardUtils.isAjaxRequest(httpServletRequest)) {
            if (!tokenTO.isEmpty()) {
                httpServletResponse.setHeader(csrfGuard.getTokenName(), tokenTO.toString());
            }
        }
    }

    public static boolean isAjaxRequest(final HttpServletRequest request) {
        final Enumeration<String> headers = request.getHeaders("X-Requested-With");
        return Objects.nonNull(headers) && Collections.list(headers).stream()
                                                      .flatMap(headerValue -> Arrays.stream(headerValue.split(",")))
                                                      .map(String::trim)
                                                      .anyMatch("XMLHttpRequest"::equals);
    }

    public static String normalizeResourceURI(final HttpServletRequest httpServletRequest) {
        return normalizeResourceURI(httpServletRequest.getRequestURI());
    }

    public static String normalizeResourceURI(final String resourceURI) {
        return resourceURI.startsWith("/") ? resourceURI : '/' + resourceURI;
    }

    private static String readInputStreamContent(final InputStream inputStream) {
        try {
            return IOUtils.toString(inputStream, Charset.defaultCharset());
        } catch (final IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    /**
     * for a url, get the protocol and domain, e.g. for url https://a.b/path, will return https://a.b
     *
     * @param url a string representing a URL
     * @return the protocol and path
     */
    private static String httpProtocolAndDomain(final String url) {
        final int firstSlashAfterProtocol = url.indexOf('/', 8); // FIXME this should be rewritten..
        return firstSlashAfterProtocol < 0 ? url // must not have a path
                                           : url.substring(0, firstSlashAfterProtocol);
    }
}
