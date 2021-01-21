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

import org.apache.commons.lang3.tuple.Pair;
import org.owasp.csrfguard.token.storage.Token;
import org.owasp.csrfguard.token.storage.TokenHolder;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

public class InMemoryTokenHolder implements TokenHolder {

    private static final Map<String, Token> TOKENS = new ConcurrentHashMap<>();

    public InMemoryTokenHolder() {}

    @Override
    public void setMasterToken(final String sessionKey, final String value) {
        TOKENS.compute(sessionKey, (k, v) -> {
            final Token result;
            if (Objects.isNull(v)) {
                result = new InMemoryToken(value);
            } else {
                v.setMasterToken(value);
                result = v;
            }
            return result;
        });
    }

    @Override
    public String createMasterTokenIfAbsent(final String sessionKey, final Supplier<String> valueSupplier) {
        final Token token = TOKENS.computeIfAbsent(sessionKey, k -> new InMemoryToken(valueSupplier.get()));
        return token.getMasterToken();
    }

    @Override
    public String createPageTokenIfAbsent(final String sessionKey, final String resourceUri, final Supplier<String> valueSupplier) {
        final Token token = TOKENS.get(sessionKey);
        if (Objects.isNull(token)) {
            final String newPageToken = valueSupplier.get();
            TOKENS.computeIfAbsent(sessionKey, k -> new InMemoryToken(valueSupplier.get(), Pair.of(resourceUri, newPageToken)));
            return newPageToken;
        } else {
            return token.setPageTokenIfAbsent(resourceUri, valueSupplier);
        }
    }

    @Override
    public Token getToken(final String sessionKey) {
        return TOKENS.get(sessionKey);
    }

    @Override
    public String getPageToken(final String sessionKey, final String resourceUri) {
        final Token token = TOKENS.get(sessionKey);

        return Objects.nonNull(token) ? token.getPageToken(resourceUri) : null;
    }

    @Override
    public void setPageToken(final String sessionKey, final String resourceUri, final String value) {
        getTokenOrException(sessionKey).setPageToken(resourceUri, value);
    }

    @Override
    public void setPageTokens(final String sessionKey, final Map<String, String> pageTokens) {
        getTokenOrException(sessionKey).setPageTokens(pageTokens);
    }

    @Override
    public Map<String, String> getPageTokens(final String sessionKey) {
        return getTokenOrException(sessionKey).getPageTokens();
    }

    @Override
    public void remove(final String sessionKey) {
        TOKENS.remove(sessionKey);
    }

    @Override
    public void rotateAllPageTokens(final String sessionKey, final Supplier<String> tokenValueSupplier) {
        final Token token = getTokenOrException(sessionKey);
        token.rotateAllPageTokens(tokenValueSupplier);
    }

    @Override
    public void regenerateUsedPageToken(final String sessionKey, final String tokenFromRequest, final Supplier<String> tokenValueSupplier) {
        final Token token = getTokenOrException(sessionKey);
        token.regenerateUsedPageToken(tokenFromRequest, tokenValueSupplier);
    }

    private Token getTokenOrException(final String sessionKey) {
        final Token token = TOKENS.get(sessionKey);

        if (Objects.isNull(token)) {
            throw new IllegalStateException("Token with the provided session key does not exist!");
        } else {
            return token;
        }
    }
}
