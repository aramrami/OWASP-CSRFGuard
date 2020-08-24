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
import org.owasp.csrfguard.token.storage.impl.Token;

import java.util.Map;

/**
 * Methods of this class should only be used through the {@link TokenService} and its relevant subclass(es)
 * TODO document
 */
public interface TokenHolder {

    /**
     * TODO document
     * @param key
     * @param value
     */
    void setMasterToken(final String key, final String value);

    /**
     * Note: this method returns a copy of the tokens in order to prevent outside modification.
     * TODO document
     * @return
     */
    Map<String, Token> getTokens();

    /**
     * TODO document
     * @return
     */
    Token getToken(final String key);

    /**
     * TODO document
     * @param key
     * @param uri
     * @return
     */
    String getPageToken(String key, String uri);

    /**
     * TODO document
     * @param key
     * @param uri
     * @param value
     */
    void setPageToken(String key, String uri, String value);

    /**
     * Note: this method returns a copy of the page tokens in order to prevent outside modification.
     * TODO document
     * @return
     */
    Map<String, String> getPageTokens(String key);

    /**
     * TODO document
     * @param tokenKey
     */
    void remove(String tokenKey);

    /**
     * TODO document
     */
    void rotateAllPageTokens(final String key);

    /**
     * TODO document
     * @param tokenKey
     * @param tokenFromRequest
     */
    void regenerateUsedPageToken(final String tokenKey, final String tokenFromRequest);
}
