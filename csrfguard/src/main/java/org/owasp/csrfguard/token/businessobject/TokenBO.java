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
package org.owasp.csrfguard.token.businessobject;

import org.apache.commons.lang3.tuple.Pair;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class TokenBO {

    private final Map<String, String> updatedPageTokens;

    private String updatedMasterToken;

    private Pair<TokenType, String> usedToken;

    public TokenBO() {
        this(null, new HashMap<>());
    }

    public TokenBO(final String updatedMasterToken) {
        this(updatedMasterToken, null);
    }

    public TokenBO(final Map<String, String> updatedPageTokens) {
        this(null, updatedPageTokens);
    }

    public TokenBO(final String updatedMasterToken, final Map<String, String> updatedPageTokens) {
        this.updatedMasterToken = updatedMasterToken;
        this.updatedPageTokens = updatedPageTokens;
    }

    public TokenBO setUsedPageToken(final String tokenValue) {
        setUsedToken(TokenType.PAGE, tokenValue);
        return this;
    }

    public TokenBO setUpdatedPageToken(final String uri, final String pageTokenValue) {
        if (this.updatedPageTokens.containsKey(uri)) {
            throw new IllegalStateException(String.format("Logical Error! A new value for the page token with the URI [%s] has already been prepared for update.", uri));
        } else {
            this.updatedPageTokens.put(uri, pageTokenValue);
        }
        return this;
    }

    public String getUpdatedMasterToken() {
        return this.updatedMasterToken;
    }

    public TokenBO setUpdatedMasterToken(final String masterToken) {
        if (Objects.isNull(this.updatedMasterToken)) {
            this.updatedMasterToken = masterToken;
            return this;
        } else {
            throw new IllegalStateException("Logical Error! A new value for the master token has already been prepared for update.");
        }
    }

    public Map<String, String> getUpdatedPageTokens() {
        return this.updatedPageTokens;
    }

    public boolean isUsedMasterToken() {
        if (Objects.isNull(this.usedToken)) {
            throw new IllegalStateException("Internal error! The token used to validate the request is not set.");
        } else {
            return this.usedToken.getKey() == TokenType.MASTER;
        }
    }

    public TokenBO setUsedMasterToken(final String tokenValue) {
        setUsedToken(TokenType.MASTER, tokenValue);
        return this;
    }

    private void setUsedToken(final TokenType page, final String tokenValue) {
        if (Objects.isNull(this.usedToken)) {
            this.usedToken = Pair.of(page, tokenValue);
        } else {
            throw new IllegalStateException("Used token was already set. A request cannot be validated by two different tokens!");
        }
    }

    private enum TokenType {
        MASTER, PAGE
    }
}
