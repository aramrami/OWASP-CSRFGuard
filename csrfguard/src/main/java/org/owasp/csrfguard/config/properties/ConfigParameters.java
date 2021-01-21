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

package org.owasp.csrfguard.config.properties;

import org.apache.commons.lang3.tuple.Pair;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

public final class ConfigParameters {

    public static final SimpleBooleanConfigParameter ROTATE = new SimpleBooleanConfigParameter("org.owasp.csrfguard.Rotate", false);
    public static final SimpleBooleanConfigParameter TOKEN_PER_PAGE = new SimpleBooleanConfigParameter("org.owasp.csrfguard.TokenPerPage", false);
    public static final SimpleBooleanConfigParameter VALIDATE_WHEN_NO_SESSION_EXISTS = new SimpleBooleanConfigParameter("org.owasp.csrfguard.ValidateWhenNoSessionExists", true);
    public static final SimpleBooleanConfigParameter TOKEN_PER_PAGE_PRECREATE = new SimpleBooleanConfigParameter("org.owasp.csrfguard.TokenPerPagePrecreate", false);
    public static final SimpleBooleanConfigParameter PRINT_ENABLED = new SimpleBooleanConfigParameter("org.owasp.csrfguard.Config.Print", false);
    public static final SimpleBooleanConfigParameter CSRFGUARD_ENABLED = new SimpleBooleanConfigParameter("org.owasp.csrfguard.Enabled", true);
    public static final SimpleBooleanConfigParameter AJAX_ENABLED = new SimpleBooleanConfigParameter("org.owasp.csrfguard.Ajax", false);
    public static final SimpleBooleanConfigParameter CSRFGUARD_PROTECT = new SimpleBooleanConfigParameter("org.owasp.csrfguard.Protect", false);

    public static final SimpleIntConfigParameter TOKEN_LENGTH = new SimpleIntConfigParameter("org.owasp.csrfguard.TokenLength", 32);
    public static final SimpleDurationParameter PAGE_TOKEN_SYNCHRONIZATION_TOLERANCE = new SimpleDurationParameter("org.owasp.csrfguard.PageTokenSynchronizationTolerance", Duration.of(2, ChronoUnit.SECONDS));

    public static final Pair<String, String> TOKEN_NAME = Pair.of("org.owasp.csrfguard.TokenName", "OWASP-CSRFGUARD");
    public static final Pair<String, String> LOGGER = Pair.of("org.owasp.csrfguard.Logger", "org.owasp.csrfguard.log.ConsoleLogger");
    public static final Pair<String, String> DOMAIN_ORIGIN = Pair.of("org.owasp.csrfguard.domainOrigin", null);
    public static final Pair<String, String> DEFAULT_PRNG = Pair.of("SUN", "SHA1PRNG");
    public static final Pair<String, String> PRNG = Pair.of("org.owasp.csrfguard.PRNG", DEFAULT_PRNG.getValue());
    public static final Pair<String, String> PRNG_PROVIDER = Pair.of("org.owasp.csrfguard.PRNG.Provider", DEFAULT_PRNG.getKey());
    public static final Pair<String, String> TOKEN_HOLDER = Pair.of("org.owasp.csrfguard.TokenHolder", "org.owasp.csrfguard.token.storage.impl.InMemoryTokenHolder");

    public static final String LOGICAL_SESSION_EXTRACTOR_NAME = "org.owasp.csrfguard.LogicalSessionExtractor";

    public static final String NEW_TOKEN_LANDING_PAGE = "org.owasp.csrfguard.NewTokenLandingPage";
    public static final String UNPROTECTED_METHODS = "org.owasp.csrfguard.UnprotectedMethods";
    public static final String PROTECTED_METHODS = "org.owasp.csrfguard.ProtectedMethods";

    public static final String CONFIG_OVERLAY_HIERARCHY_PROPERTY_NAME = "org.owasp.csrfguard.configOverlay.hierarchy";
    public static final String CONFIG_OVERLAY_UPDATE_CHECK_PROPERTY_NAME = "org.owasp.csrfguard.configOverlay.secondsBetweenUpdateChecks";
    public static final String CONFIG_PROVIDER_FACTORY_PROPERTY_NAME = "org.owasp.csrfguard.configuration.provider.factory";

    public static final String ACTION_PREFIX = "org.owasp.csrfguard.action.";
    public static final String ACTION_ATTRIBUTE_NAME = "AttributeName";

    public final static String PROTECTED_PAGE_PREFIX = "org.owasp.csrfguard.protected.";
    public final static String UNPROTECTED_PAGE_PREFIX = "org.owasp.csrfguard.unprotected.";

    private ConfigParameters() {}

    public static SimpleBooleanConfigParameter getUseNewTokenLandingPage(final String newTokenLandingPage) {
        final String newTokenLandingPagePropertyName = "org.owasp.csrfguard.UseNewTokenLandingPage";
        return new SimpleBooleanConfigParameter(newTokenLandingPagePropertyName, newTokenLandingPage != null);
    }
}
