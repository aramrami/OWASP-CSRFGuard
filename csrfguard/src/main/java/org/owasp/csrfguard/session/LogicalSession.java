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

/**
 * Represents a logical session that enables decoupling from the container's session implementation in case the client application uses a stateless approach (e.g. token based authentication)
 */
public interface LogicalSession {

    /**
     * Returns the logical session key
     * @return identifier that uniquely identifies the current actor
     */
    String getKey();

    /**
     * Returns <code>true</code> if the client does not yet know about the
     * session or if the client chooses not to join the session.
     *
     * @see javax.servlet.http.HttpSession#isNew()
     *
     * @return <code>true</code> if the server has created a session, but the client has not yet joined
     */
    boolean isNew();

    /**
     * Invalidates this session then unbinds any objects bound to it.
     */
    void invalidate();

    /**
     * @return whether the objects were generated or not.
     */
    boolean areTokensGenerated();

    /**
     * Set whether the objects were generated or not.
     *
     * @param areTokensGenerated set <code>true</code> if the tokens were generated, <code>false</code> otherwise
     */
    void setTokensGenerated(boolean areTokensGenerated);

    /**
     * Saves an object to the current session
     *
     * @see HttpSession#setAttribute(java.lang.String, java.lang.Object)
     *
     * @param attribute the name to which the object is bound; cannot be null
     * @param value the object to be bound
     */
    void setAttribute(final String attribute, final Object value);

    /**
     * Retrieves an object from the session using its name
     *
     * @see HttpSession#getAttribute(String)
     *
     * @param attributeName - identifies a certain object on the session
     * @return the object associated to the attribute name
     */
    Object getAttribute(String attributeName);
}
