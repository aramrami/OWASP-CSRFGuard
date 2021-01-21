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

package org.owasp.csrfguard.config.properties.javascript;

import org.apache.commons.lang3.StringUtils;

public final class JavaScriptConfigParameters {

    private JavaScriptConfigParameters() {}

    // TODO document the names of the configurations that can be used for overriding the values from the web.xml in the properties file

    public static final StringJsConfigParameter CACHE_CONTROL = new StringJsConfigParameter("cache-control", "org.owasp.csrfguard.JavascriptServlet.cacheControl", "private, max-age=28800");
    public static final StringJsConfigParameter REFERER_PATTERN  = new StringJsConfigParameter("referer-pattern", "org.owasp.csrfguard.JavascriptServlet.refererPattern", ".*");
    public static final StringJsConfigParameter UNPROTECTED_EXTENSIONS = new StringJsConfigParameter("unprotected-extensions", "org.owasp.csrfguard.JavascriptServlet.UnprotectedExtensions", StringUtils.EMPTY);
    public static final StringJsConfigParameter SOURCE_FILE = new StringJsConfigParameter("source-file", "org.owasp.csrfguard.JavascriptServlet.sourceFile", null);
    public static final StringJsConfigParameter X_REQUESTED_WITH = new StringJsConfigParameter("x-requested-with", "org.owasp.csrfguard.JavascriptServlet.xRequestedWith", "OWASP CSRFGuard Project");
    public static final StringJsConfigParameter DYNAMIC_NODE_CREATION_EVENT_NAME = new StringJsConfigParameter("dynamic-node-creation-event", "org.owasp.csrfguard.JavascriptServlet.dynamicNodeCreationEventName", null);

    public static final BooleanJsConfigParameter DOMAIN_STRICT = new BooleanJsConfigParameter("domain-strict", "org.owasp.csrfguard.JavascriptServlet.domainStrict", true);
    public static final BooleanJsConfigParameter INJECT_INTO_ATTRIBUTES = new BooleanJsConfigParameter("inject-into-attributes", "org.owasp.csrfguard.JavascriptServlet.injectIntoAttributes", true);
    public static final BooleanJsConfigParameter INJECT_GET_FORMS = new BooleanJsConfigParameter("inject-get-forms", "org.owasp.csrfguard.JavascriptServlet.injectGetForms", true);
    public static final BooleanJsConfigParameter INJECT_FORM_ATTRIBUTES = new BooleanJsConfigParameter("inject-form-attributes", "org.owasp.csrfguard.JavascriptServlet.injectFormAttributes", true);
    public static final BooleanJsConfigParameter INJECT_INTO_FORMS = new BooleanJsConfigParameter("inject-into-forms", "org.owasp.csrfguard.JavascriptServlet.injectIntoForms", true);
    public static final BooleanJsConfigParameter INJECT_INTO_DYNAMICALLY_CREATED_NODES = new BooleanJsConfigParameter("inject-into-dynamic", "org.owasp.csrfguard.JavascriptServlet.injectIntoDynamicNodes", false);
    public static final BooleanJsConfigParameter REFERER_MATCH_PROTOCOL = new BooleanJsConfigParameter("referer-match-protocol", "org.owasp.csrfguard.JavascriptServlet.refererMatchProtocol", true);
    public static final BooleanJsConfigParameter REFERER_MATCH_DOMAIN = new BooleanJsConfigParameter("referer-match-domain", "org.owasp.csrfguard.JavascriptServlet.refererMatchDomain", true);
}
