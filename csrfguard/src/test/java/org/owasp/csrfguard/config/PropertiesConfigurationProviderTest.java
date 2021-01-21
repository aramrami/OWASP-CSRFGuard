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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.owasp.csrfguard.MandatoryProperties;
import org.owasp.csrfguard.config.properties.ConfigParameters;

import java.security.SecureRandom;
import java.util.Properties;

class PropertiesConfigurationProviderTest {

    @Test
    void testDefaultPRNG() {
        final PropertiesConfigurationProvider configurationProvider = new PropertiesConfigurationProvider(new MandatoryProperties().get());
        final SecureRandom secureRandom = configurationProvider.getPrng();
        Assertions.assertNotNull(secureRandom);
    }

    @Test
    void testInvalidProvider() {
        final Properties properties = new MandatoryProperties().add(ConfigParameters.PRNG_PROVIDER.getKey(), "InvalidProvider").get();

        final PropertiesConfigurationProvider configurationProvider = new PropertiesConfigurationProvider(properties);
        final SecureRandom secureRandom = configurationProvider.getPrng();
        Assertions.assertNotNull(secureRandom);
    }

    @Test
    void testInvalidAlgorithm() {
        final Properties properties = new MandatoryProperties().add(ConfigParameters.PRNG.getKey(), "InvalidAlgorithm").get();

        final PropertiesConfigurationProvider configurationProvider = new PropertiesConfigurationProvider(properties);
        final SecureRandom secureRandom = configurationProvider.getPrng();
        Assertions.assertNotNull(secureRandom);
    }

    @Test
    void testInvalidPRNG() {
        final Properties properties = new MandatoryProperties().add(ConfigParameters.PRNG.getKey(), "InvalidAlgorithm")
                                                               .add(ConfigParameters.PRNG_PROVIDER.getKey(), "InvalidProvider")
                                                               .get();

        final PropertiesConfigurationProvider configurationProvider = new PropertiesConfigurationProvider(properties);
        final SecureRandom secureRandom = configurationProvider.getPrng();
        Assertions.assertNotNull(secureRandom);
    }

    @Test
    void testInvalidTokenLength() {
        final Properties properties = new MandatoryProperties().add(ConfigParameters.TOKEN_LENGTH.getName(), String.valueOf(3)).get();
        final RuntimeException exception = Assertions.assertThrows(RuntimeException.class, () -> new PropertiesConfigurationProvider(properties));

        Assertions.assertEquals(IllegalArgumentException.class, exception.getCause().getClass());
        Assertions.assertTrue(exception.getMessage().contains("token length"));
    }

    @Test
    void testInvalidHttpMethods() {
        testHttpMethods(ConfigParameters.PROTECTED_METHODS);
        testHttpMethods(ConfigParameters.UNPROTECTED_METHODS);
    }

    @Test
    void testHttpMethodProtectionDuplication() {
        final String httpMethods = "POST, GET";
        final Properties properties = new MandatoryProperties().add(ConfigParameters.PROTECTED_METHODS, httpMethods)
                                                               .add(ConfigParameters.UNPROTECTED_METHODS, httpMethods)
                                                               .get();

        final RuntimeException exception = Assertions.assertThrows(RuntimeException.class, () -> new PropertiesConfigurationProvider(properties));
        Assertions.assertEquals(IllegalArgumentException.class, exception.getCause().getClass());
        Assertions.assertEquals(exception.getCause().getMessage(), "The [POST, GET] HTTP method(s) cannot be both protected and unprotected.");
    }

    private void testHttpMethods(final String protectedMethods) {
        final Properties properties = new MandatoryProperties().add(protectedMethods, "POST, get, OpTiOns, INVALID,PATch ").get();
        final RuntimeException exception = Assertions.assertThrows(RuntimeException.class, () -> new PropertiesConfigurationProvider(properties));

        Assertions.assertEquals(IllegalArgumentException.class, exception.getCause().getClass());
        Assertions.assertEquals(exception.getCause().getMessage(), "The provided input 'INVALID' is not a valid HTTP method!");
    }
}