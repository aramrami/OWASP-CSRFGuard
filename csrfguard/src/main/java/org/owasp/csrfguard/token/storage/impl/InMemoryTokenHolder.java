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

package org.owasp.csrfguard.token.storage.impl;

import org.owasp.csrfguard.token.TokenUtils;
import org.owasp.csrfguard.token.storage.TokenHolder;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

// TODO make thread safe
public class InMemoryTokenHolder implements TokenHolder {

    private static final Map<String, Token> TOKENS = new ConcurrentHashMap<>();

    public InMemoryTokenHolder() {}

    public InMemoryTokenHolder(final String key, final Token token) {
        TOKENS.put(key, token);
    }

    @Override
    public void setMasterToken(final String key, final String value) {
        TOKENS.compute(key, (k, v) -> {
            final Token result;
            if (Objects.isNull(v)) {
                result = new Token(value);
            } else {
                v.setMasterToken(value);
                result = v;
            }
            return result;
        });
    }

    @Override
    public Map<String, Token> getTokens() {
        return TOKENS;
    }

    @Override
    public Token getToken(final String key) {
        return TOKENS.get(key);
    }

    @Override
    public String getPageToken(final String key, final String uri) {
        return TOKENS.get(key).getPageToken(uri);
    }

    @Override
    public void setPageToken(final String key, final String uri, final String value) {
        TOKENS.get(key).getPageTokens().put(uri, value);
    }

    @Override
    public Map<String, String> getPageTokens(final String key) {
        return TOKENS.get(key).getPageTokens();
    }

    @Override
    public void remove(final String tokenKey) {
        TOKENS.remove(tokenKey);
    }

    @Override
    public void rotateAllPageTokens(final String key) {
        final Map<String, String> pageTokens = getPageTokens(key);
        TokenUtils.rotateAllPageTokens(pageTokens);
    }

    @Override
    public void regenerateUsedPageToken(final String tokenKey, final String tokenFromRequest) {
        final Map<String, String> pageTokens = getPageTokens(tokenKey);
        TokenUtils.regenerateUsedPageToken(pageTokens, tokenFromRequest);
    }
}
