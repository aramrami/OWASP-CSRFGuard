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

import org.owasp.csrfguard.token.storage.impl.PageTokenValue;

import java.util.Map;
import java.util.function.Supplier;

/**
 * TODO
 */
public interface Token {

    /**
     * TODO
     * @return
     */
    String getMasterToken();

    /**
     * TODO
     * @param masterToken
     */
    void setMasterToken(final String masterToken);

    /**
     * TODO
     * @param uri
     * @return
     */
    String getPageToken(final String uri);

    /**
     * TODO
     * @param uri
     * @return
     */
    PageTokenValue getTimedPageToken(final String uri);

    /**
     * TODO
     * @param uri
     * @param pageToken
     */
    void setPageToken(final String uri, final String pageToken);

    /**
     * TODO
     * @param uri
     * @param valueSupplier
     * @return
     */
    String setPageTokenIfAbsent(final String uri, final Supplier<String> valueSupplier);

    /**
     * TODO
     * @return
     */
    Map<String, String> getPageTokens();

    /**
     * TODO
     * @param pageTokens
     */
    void setPageTokens(final Map<String, String> pageTokens);

    /**
     * TODO
     * @param tokenValueSupplier
     */
    void rotateAllPageTokens(final Supplier<String> tokenValueSupplier);

    /**
     * TODO is it worth the added performance penalty in case of a large application with a lot of pages? What would be the risk if this would be contextual to the assigned resource?
     * Disposes the current token from all the stored valid page tokens, disregarding to which resource it was assigned and replaces with a newly generated one.
     */
    void regenerateUsedPageToken(final String tokenFromRequest, final Supplier<String> tokenValueSupplier);
}
