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

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class InMemoryToken implements Token {

    private String masterToken;
    private Map<String, PageTokenValue> pageTokens;

    public InMemoryToken(final String masterToken) {
        this(masterToken, new ConcurrentHashMap<>());
    }

    public InMemoryToken(final String masterToken, final Pair<String, String> pageToken) {
        this(masterToken, toMap(pageToken));
    }

    private InMemoryToken(final String masterToken, final Map<String, PageTokenValue> pageTokens) {
        Objects.requireNonNull(masterToken, "Master token cannot be null");
        Objects.requireNonNull(pageTokens, "Page tokens cannot be null");

        this.masterToken = masterToken;
        this.pageTokens = new ConcurrentHashMap<>(pageTokens);
    }

    @Override
    public String getMasterToken() {
        return this.masterToken;
    }

    @Override
    public void setMasterToken(final String masterToken) {
        this.masterToken = masterToken;
    }

    @Override
    public String getPageToken(final String uri) {
        return this.pageTokens.get(uri).getValue();
    }

    @Override
    public PageTokenValue getTimedPageToken(final String uri) {
        return this.pageTokens.get(uri);
    }

    @Override
    public void setPageToken(final String uri, final String pageToken) {
        this.pageTokens.put(uri, PageTokenValue.from(pageToken));
    }

    @Override
    public String setPageTokenIfAbsent(final String uri, final Supplier<String> valueSupplier) {
        return this.pageTokens.computeIfAbsent(uri, k -> PageTokenValue.from(valueSupplier.get())).getValue();
    }

    @Override
    public Map<String, String> getPageTokens() {
        return this.pageTokens.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey,
                                                                            e -> e.getValue().getValue()));
    }

    @Override
    public void setPageTokens(final Map<String, String> pageTokens) {
        this.pageTokens = pageTokens.entrySet().stream()
                                    .collect(Collectors.toMap(Map.Entry::getKey,
                                                              e -> PageTokenValue.from(e.getValue()),
                                                              (e1, e2) -> e2,
                                                              ConcurrentHashMap::new
                                                             ));
    }

    @Override
    public void rotateAllPageTokens(final Supplier<String> tokenValueSupplier) {
        this.pageTokens.entrySet().forEach(e -> e.setValue(PageTokenValue.from(tokenValueSupplier.get())));
    }

    @Override
    public void regenerateUsedPageToken(final String tokenFromRequest, final Supplier<String> tokenValueSupplier) {
        this.pageTokens.replaceAll((k, v) -> v.getValue().equals(tokenFromRequest) ? PageTokenValue.from(tokenValueSupplier.get()) : v);
    }

    private static Map<String, PageTokenValue> toMap(final Pair<String, String> pageToken) {
        final Map<String, PageTokenValue> pageTokens = new ConcurrentHashMap<>();
        pageTokens.put(pageToken.getKey(), PageTokenValue.from(pageToken.getValue()));
        return pageTokens;
    }
}
