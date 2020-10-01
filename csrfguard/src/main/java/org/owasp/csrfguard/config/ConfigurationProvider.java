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

package org.owasp.csrfguard.config;

import org.owasp.csrfguard.action.IAction;
import org.owasp.csrfguard.log.ILogger;
import org.owasp.csrfguard.token.storage.LogicalSessionExtractor;
import org.owasp.csrfguard.token.storage.TokenHolder;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * TODO document
 */
public interface ConfigurationProvider {

    /**
     * TODO document
     *
     * @return true when this configuration provider can be cached for a minute, i.e. it is all setup
     */
    boolean isCacheable();

    /**
     * TODO document
     *
     * @return
     */
    boolean isPrintConfig();

    /**
     * TODO document
     *
     * @return
     */
    ILogger getLogger();

    /**
     * TODO document
     *
     * @return
     */
    String getTokenName();

    /**
     * If csrf guard filter should check even if there is no session for the user
     * Note: this changed around 2014/04, the default behavior used to be to
     * not check if there is no session.  If you want the legacy behavior (if your app
     * is not susceptible to CSRF if the user has no session), set this to false
     *
     * @return true when validation is performed even when no session exists
     */
    boolean isValidateWhenNoSessionExists();

    /**
     * TODO document
     *
     * @return
     */
    int getTokenLength();

    /**
     * TODO document
     *
     * @return
     */
    boolean isRotateEnabled();

    /**
     * TODO document
     *
     * @return
     */
    boolean isTokenPerPageEnabled();

    /**
     * TODO document
     *
     * @return
     */
    boolean isTokenPerPagePrecreateEnabled();

    /**
     * TODO document
     *
     * @return
     */
    SecureRandom getPrng();

    /**
     * TODO document
     *
     * @return
     */
    String getNewTokenLandingPage();

    /**
     * TODO document
     *
     * @return
     */
    boolean isUseNewTokenLandingPage();

    /**
     * TODO document
     *
     * @return
     */
    boolean isAjaxEnabled();

    /**
     * The default behavior of CSRFGuard is to protect all pages. Pages marked as unprotected will not be protected.<br>
     * If the Protect property is enabled, this behavior is reversed. Pages must be marked as protected to be protected.
     * All other pages will not be protected. This is useful when the CsrfGuardFilter is aggressively mapped (ex: /*),
     * but you only want to protect a few pages.
     *
     * @return false if all pages are protected, true if pages are required to be explicit protected
     */
    boolean isProtectEnabled();

    /**
     * TODO document
     *
     * @return
     */
    Set<String> getProtectedPages();

    /**
     * TODO document
     *
     * @return
     */
    Set<String> getUnprotectedPages();

    /**
     * TODO document
     *
     * @return
     */
    Set<String> getProtectedMethods();

    /**
     * if there are methods here, then all other HTTP methods are protected and these (e.g. GET) are unprotected
     *
     * @return the unprotected methods
     */
    Set<String> getUnprotectedMethods();

    /**
     * if the filter is enabled
     *
     * @return is csrf guard filter is enabled
     */
    boolean isEnabled();

    /**
     * TODO document
     *
     * @return
     */
    List<IAction> getActions();

    /**
     * TODO document
     *
     * @return
     */
    String getJavascriptSourceFile();

    /**
     * TODO document
     *
     * @return
     */
    boolean isJavascriptDomainStrict();

    /**
     * TODO document
     *
     * @return
     */
    String getDomainOrigin();

    /**
     * TODO document
     *
     * @return
     */
    String getJavascriptCacheControl();

    /**
     * TODO document
     *
     * @return
     */
    Pattern getJavascriptRefererPattern();

    /**
     * if the token should be injected in GET forms (which will be on the URL)
     * if the HTTP method GET is unprotected, then this should likely be false
     *
     *  @return true if the token should be injected in GET forms via Javascript
     */
    boolean isJavascriptInjectGetForms();

    /**
     * if the token should be injected in the action in forms
     * note, if injectIntoForms is true, then this might not need to be true
     *
     * @return if inject
     */
    boolean isJavascriptInjectFormAttributes();

    /**
     * TODO document
     *
     * @return
     */
    boolean isJavascriptInjectIntoForms();

    /**
     * if the referer to the javascript must match match the protocol of the domain
     *
     * @return true if the javascript must match the protocol of the domain
     */
    boolean isJavascriptRefererMatchProtocol();

    /**
     * if the referer to the javascript must match domain
     *
     *  @return true if the javascript must match domain
     */
    boolean isJavascriptRefererMatchDomain();

    /**
     * TODO document
     *
     * @return
     */
    boolean isJavascriptInjectIntoAttributes();

    /**
     * TODO
     * @return
     */
    boolean isJavascriptInjectIntoDynamicallyCreatedNodes();

    /**
     * TODO
     * @return
     */
    String getJavascriptDynamicNodeCreationEventName();

    /**
     * TODO document
     *
     * @return
     */
    String getJavascriptXrequestedWith();

    /**
     * TODO document
     *
     * @return
     */
    String getJavascriptTemplateCode();

    /**
     * TODO document
     * example: "js,css,gif,png,ico,jpg"
     *
     * @return
     */
    String getJavascriptUnprotectedExtensions();

    /**
     * TODO document
     * @return
     */
    TokenHolder getTokenHolder();

    /**
     * TODO document
     * @return
     */
    LogicalSessionExtractor getLogicalSessionExtractor();

    /**
     * TODO document
     * @return
     */
    Duration getPageTokenSynchronizationTolerance();
}
