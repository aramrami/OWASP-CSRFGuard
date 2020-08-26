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

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

public class Token {

    private String masterToken;
    private Map<String, String> pageTokens;

    public Token(final String masterToken) {
        this(masterToken, new HashMap<>());
    }

    public Token(final String masterToken, final Pair<String, String> pageToken) {
        this(masterToken, toMap(pageToken));
    }

    public Token(final String masterToken, final Map<String, String> pageTokens) {
        this.masterToken = masterToken;
        this.pageTokens = pageTokens;
    }

    public String getMasterToken() {
        return this.masterToken;
    }

    public void setMasterToken(final String masterToken) {
        this.masterToken = masterToken;
    }

    public Map<String, String> getPageTokens() {
        return this.pageTokens;
    }

    public void setPageTokens(final Map<String, String> pageTokens) {
        this.pageTokens = pageTokens;
    }

    public String getPageToken(final String uri) {
        return this.pageTokens.get(uri);
    }

    public String setPageTokenIfAbsent(final String uri, final Supplier<String> valueSupplier) {
        return this.pageTokens.computeIfAbsent(uri, k -> valueSupplier.get());
    }

    public void setPageToken(final String uri, final String value) {
        this.pageTokens.put(uri, value);
    }

    private static Map<String, String> toMap(final Pair<String, String> pageToken) {
        final HashMap<String, String> pageTokens = new HashMap<>();
        pageTokens.put(pageToken.getKey(), pageToken.getValue());
        return pageTokens;
    }
}
