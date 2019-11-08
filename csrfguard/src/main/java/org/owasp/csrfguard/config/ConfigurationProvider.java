/**
 * The OWASP CSRFGuard Project, BSD License
 * Eric Sheridan (eric@infraredsecurity.com), Copyright (c) 2011
 * All rights reserved.
 * <p>
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * <p>
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of OWASP nor the names of its contributors may be used
 * to endorse or promote products derived from this software without specific
 * prior written permission.
 * <p>
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
package org.owasp.csrfguard.config;

import java.security.SecureRandom;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import org.owasp.csrfguard.action.IAction;
import org.owasp.csrfguard.log.ILogger;

public interface ConfigurationProvider {

    /** @return true when this configuration provider can be cached for a minute, i.e. it is all setup */
    boolean isCacheable();

    boolean isPrintConfig();

    ILogger getLogger();

    String getTokenName();

    /**
     * If csrf guard filter should check even if there is no session for the user
     * Note: this changed around 2014/04, the default behavior used to be to
     * not check if there is no session.  If you want the legacy behavior (if your app
     * is not susceptible to CSRF if the user has no session), set this to false
     * @return true when validation is performed even when no session exists
     */
    boolean isValidateWhenNoSessionExists();

    int getTokenLength();

    boolean isRotateEnabled();

    boolean isTokenPerPageEnabled();

    boolean isTokenPerPagePrecreateEnabled();

    SecureRandom getPrng();

    String getNewTokenLandingPage();

    boolean isUseNewTokenLandingPage();

    boolean isAjaxEnabled();

    boolean isProtectEnabled();

    String getSessionKey();

    Set<String> getProtectedPages();

    Set<String> getUnprotectedPages();

    Set<String> getProtectedMethods();

    /**
     * if there are methods here, then all other HTTP methods are protected and these (e.g. GET) are unprotected
     * @return the unprotected methods
     */
    Set<String> getUnprotectedMethods();

    /**
     * if the filter is enabled
     * @return is csrf guard filter is enabled
     */
    boolean isEnabled();

    List<IAction> getActions();

    String getJavascriptSourceFile();

    boolean isJavascriptDomainStrict();

    String getDomainOrigin();

    String getJavascriptCacheControl();

    Pattern getJavascriptRefererPattern();

    /**
     * if the token should be injected in GET forms (which will be on the URL)
     * if the HTTP method GET is unprotected, then this should likely be false
     * @return true if the token should be injected in GET forms via Javascript
     */
    boolean isJavascriptInjectGetForms();

    /**
     * if the token should be injected in the action in forms
     * note, if injectIntoForms is true, then this might not need to be true
     * @return if inject
     */
    boolean isJavascriptInjectFormAttributes();

    boolean isJavascriptInjectIntoForms();

    /**
     * if the referer to the javascript must match match the protocol of the domain
     * @return true if the javascript must match the protocol of the domain
     */
    boolean isJavascriptRefererMatchProtocol();

    /**
     * if the referer to the javascript must match domain
     * @return true if the javascript must match domain
     */
    boolean isJavascriptRefererMatchDomain();

    boolean isJavascriptInjectIntoAttributes();

    String getJavascriptXrequestedWith();

    String getJavascriptTemplateCode();

    /**
     * example:"js,css,gif,png,ico,jpg"
     * @return
     */
    String getJavascriptUnprotectedExtensions();

}
