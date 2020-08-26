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
package org.owasp.csrfguard.session;

import javax.servlet.http.HttpSession;
import java.util.Objects;

public class ContainerSession implements LogicalSession {

    private final HttpSession httpSession;
    private boolean areTokensGenerated;

    public ContainerSession(final HttpSession httpSession) {
        this.httpSession = httpSession;
    }

    @Override
    public String getKey() {
        return this.httpSession.getId();
    }

    @Override
    public boolean isNew() {
        return Objects.nonNull(this.httpSession) && this.httpSession.isNew();
    }

    @Override
    public void invalidate() {
        if (Objects.nonNull(this.httpSession)) {
            this.httpSession.invalidate();
        }
    }

    @Override
    public boolean areTokensGenerated() {
        return this.areTokensGenerated;
    }

    @Override
    public void setTokensGenerated(final boolean areTokensGenerated) {
        this.areTokensGenerated = areTokensGenerated;
    }

    @Override
    public void setAttribute(final String name, final Object value) {
        this.httpSession.setAttribute(name, value);
    }

    @Override
    public Object getAttribute(final String attributeName) {
        return this.httpSession.getAttribute(attributeName);
    }
}
