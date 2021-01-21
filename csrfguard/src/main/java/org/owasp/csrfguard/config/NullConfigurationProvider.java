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
import org.owasp.csrfguard.config.properties.ConfigParameters;
import org.owasp.csrfguard.log.ConsoleLogger;
import org.owasp.csrfguard.log.ILogger;
import org.owasp.csrfguard.token.storage.LogicalSessionExtractor;
import org.owasp.csrfguard.token.storage.TokenHolder;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * {@link ConfigurationProvider} which returns all null or empty values (except for the logger).
 * Used before initialization has occurred.
 */
public final class NullConfigurationProvider implements ConfigurationProvider {

    private static final ILogger LOGGER = new ConsoleLogger();

    public NullConfigurationProvider() {}

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public boolean isPrintConfig() {
        return false;
    }

    @Override
    public ILogger getLogger() {
        return LOGGER;
    }

    @Override
    public String getTokenName() {
        return null;
    }

    @Override
    public boolean isValidateWhenNoSessionExists() {
        return false;
    }

    @Override
    public int getTokenLength() {
        return 0;
    }

    @Override
    public boolean isRotateEnabled() {
        return false;
    }

    @Override
    public boolean isTokenPerPageEnabled() {
        return false;
    }

    @Override
    public boolean isTokenPerPagePrecreateEnabled() {
        return false;
    }

    @Override
    public SecureRandom getPrng() {
        try {
            return SecureRandom.getInstance(ConfigParameters.DEFAULT_PRNG.getValue(), ConfigParameters.DEFAULT_PRNG.getKey());
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getNewTokenLandingPage() {
        return null;
    }

    @Override
    public boolean isUseNewTokenLandingPage() {
        return false;
    }

    @Override
    public boolean isAjaxEnabled() {
        return false;
    }

    @Override
    public boolean isProtectEnabled() {
        return false;
    }

    @Override
    public Set<String> getProtectedPages() {
        return Collections.emptySet();
    }

    @Override
    public Set<String> getUnprotectedPages() {
        return Collections.emptySet();
    }

    @Override
    public Set<String> getProtectedMethods() {
        return Collections.emptySet();
    }

    @Override
    public Set<String> getUnprotectedMethods() {
        return Collections.emptySet();
    }

    @Override
    public boolean isEnabled() {
        return false;
    }

    @Override
    public List<IAction> getActions() {
        return Collections.emptyList();
    }

    @Override
    public String getJavascriptSourceFile() {
        return null;
    }

    @Override
    public boolean isJavascriptDomainStrict() {
        return false;
    }

    @Override
    public String getDomainOrigin() {
        return null;
    }

    @Override
    public String getJavascriptCacheControl() {
        return null;
    }

    @Override
    public Pattern getJavascriptRefererPattern() {
        return null;
    }

    @Override
    public boolean isJavascriptInjectGetForms() {
        return false;
    }

    @Override
    public boolean isJavascriptInjectFormAttributes() {
        return false;
    }

    @Override
    public boolean isJavascriptInjectIntoForms() {
        return false;
    }

    @Override
    public boolean isJavascriptRefererMatchProtocol() {
        return false;
    }

    @Override
    public boolean isJavascriptRefererMatchDomain() {
        return false;
    }

    @Override
    public boolean isJavascriptInjectIntoAttributes() {
        return false;
    }

    @Override
    public boolean isJavascriptInjectIntoDynamicallyCreatedNodes() {
        return false;
    }

    @Override
    public String getJavascriptDynamicNodeCreationEventName() {
        return null;
    }

    @Override
    public String getJavascriptXrequestedWith() {
        return null;
    }

    @Override
    public String getJavascriptTemplateCode() {
        return null;
    }

    @Override
    public String getJavascriptUnprotectedExtensions() {
        return null;
    }

    @Override
    public TokenHolder getTokenHolder() {
        return null;
    }

    @Override
    public LogicalSessionExtractor getLogicalSessionExtractor() {
        return null;
    }

    @Override
    public Duration getPageTokenSynchronizationTolerance() {
        return null;
    }
}
