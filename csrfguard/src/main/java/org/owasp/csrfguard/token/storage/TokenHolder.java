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

package org.owasp.csrfguard.token.storage;

import org.owasp.csrfguard.token.service.TokenService;

import java.util.Map;
import java.util.function.Supplier;

/**
 * Interface used for storing and manipulating tokens across the solution.
 *
 * Methods of this class should only be used through the {@link TokenService} and its relevant subclass(es)
 */
public interface TokenHolder {

    /**
     * Sets or overwrites the master token bound to a specific session key.
     * It does not overwrite the session key associated page tokens.
     *
     * @param sessionKey identifies the current logical session uniquely
     * @param value the value to be used as master token
     */
    void setMasterToken(final String sessionKey, final String value);

    /**
     * Creates and returns a new master token bound to the provided session key if there wasn't any or returns the existing value.
     *
     * @param sessionKey    identifies the current logical session uniquely
     * @param valueSupplier produces a new master token value lazily/on demand
     * @return the created master token
     */
    String createMasterTokenIfAbsent(final String sessionKey, final Supplier<String> valueSupplier);

    /**
     * Creates and returns a new page token bound to the provided resource URI and mapped to the session key if there wasn't any or returns the existing value.
     *
     * If there are no tokens associated to the session key it also creates a new master token.
     *
     * @param sessionKey    identifies the current logical session uniquely
     * @param resourceUri   the URI of the desired HTTP resource
     * @param valueSupplier produces a new page token value lazily/on demand
     * @return the existing or newly created page token
     */
    String createPageTokenIfAbsent(String sessionKey, String resourceUri, Supplier<String> valueSupplier);

    /**
     * Returns the master and page tokens associated to a logical session key
     *
     * @param sessionKey identifies the current logical session uniquely
     * @return a token object containing the master and page tokens
     */
    Token getToken(final String sessionKey);

    /**
     * Returns the page token based on the desired HTTP resource URI and logical session key
     *
     * @param sessionKey  identifies the current logical session uniquely
     * @param resourceUri the URI of the desired HTTP resource
     * @return a page token bound to a resource URI and associated to a logical session key
     * or NULL if there is no token with identified by the session key
     */
    String getPageToken(String sessionKey, String resourceUri);

    /**
     * Sets the value of a page token based on the desired HTTP resource URI and logical session key
     *
     * @param sessionKey  identifies the current logical session uniquely
     * @param resourceUri the URI of the desired HTTP resource
     * @param value the value to be used as token for the page
     */
    void setPageToken(String sessionKey, String resourceUri, String value);

    /**
     * Sets/overwrites the page tokens with the provided values
     *
     * @param sessionKey identifies the current logical session uniquely
     * @param pageTokens page tokens mapped to their resource URIs
     */
    void setPageTokens(final String sessionKey, final Map<String, String> pageTokens);

    /**
     * Returns all page tokens associated to the provided logical session key
     *
     * @param sessionKey identifies the current logical session uniquely
     * @return page tokens mapped to their resource URIs
     */
    Map<String, String> getPageTokens(String sessionKey);

    /**
     * Removes all tokens related to a specific logical session key
     *
     * @param sessionKey identifies the current logical session uniquely
     */
    void remove(String sessionKey);

    /**
     * Re-generates all existing tokens associated to the provided logical session key
     *
     * @param sessionKey identifies the current logical session uniquely
     * @param tokenValueSupplier produces a new page token value lazily/on demand
     */
    void rotateAllPageTokens(final String sessionKey, final Supplier<String> tokenValueSupplier);

    /**
     * Re-generates the value of a used page token
     *
     * @param sessionKey       identifies the current logical session uniquely
     * @param tokenFromRequest the token extracted from the request
     * @param tokenValueSupplier produces a new page token value lazily/on demand
     */
    void regenerateUsedPageToken(final String sessionKey, final String tokenFromRequest, final Supplier<String> tokenValueSupplier);
}
