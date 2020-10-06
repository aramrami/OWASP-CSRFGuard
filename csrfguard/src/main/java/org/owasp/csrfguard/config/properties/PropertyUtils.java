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

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.owasp.csrfguard.CsrfGuardServletContextListener;

import java.time.Duration;
import java.util.Objects;
import java.util.Properties;
import java.util.function.Function;

public final class PropertyUtils {

    private PropertyUtils() {}

    /**
     * property string and substitutions
     *
     * @param properties   The properties from which to fetch a value
     * @param propertyName The name of the desired property
     * @return the value, with common substitutions performed
     * @see #commonSubstitutions(String)
     */
    public static String getProperty(final Properties properties, final String propertyName) {
        return getProperty(properties, propertyName, null);
    }

    public static String getProperty(final Properties properties, final Pair<String, String> propertyWithDefaultValue) {
        return getProperty(properties, propertyWithDefaultValue.getKey(), propertyWithDefaultValue.getValue());
    }

    public static int getProperty(final Properties properties, final SimpleIntConfigParameter configParameter) {
        return getProperty(properties, configParameter, Integer::parseInt);
    }

    public static boolean getProperty(final Properties properties, final SimpleBooleanConfigParameter configParameter) {
        return getProperty(properties, configParameter, Boolean::parseBoolean);
    }

    public static <T> T getProperty(final Properties properties, final SimpleConfigParameter<String, T> configParameter, final Function<String, T> function) {
        return getProperty(properties, configParameter.getName(), configParameter.getDefaultValue(), function);
    }

    public static Duration getProperty(final Properties properties, final SimpleDurationParameter configParameter) {
        return getProperty(properties, configParameter.getName(), configParameter.getDefaultValue(), millis -> Duration.ofMillis(Long.parseLong(millis)));
    }

    public static <T> T getProperty(final Properties properties, final String propertyName, final T defaultValue, final Function<String, T> function) {
        final String property = getProperty(properties, propertyName);
        return StringUtils.isBlank(property) ? defaultValue : function.apply(property);
    }

    /**
     * property string and substitutions
     *
     * @param properties   The properties from which to fetch a value
     * @param propertyName The name of the desired property
     * @param defaultValue The value to use when the propertyName does not exist
     * @return the value, with common substitutions performed
     * @see #commonSubstitutions(String)
     */
    public static String getProperty(final Properties properties, final String propertyName, final String defaultValue) {
        final String value;
        if (Objects.isNull(defaultValue)) {
            value = properties.getProperty(propertyName);
        } else {
            if (!properties.containsKey(propertyName)) {
                // TODO use Logger instead when SLF4J is in place
                System.out.printf("The '%s' property was not defined, using '%s' as default value. %n", propertyName, defaultValue);
            }
            value = properties.getProperty(propertyName, defaultValue);
        }

        return commonSubstitutions(value);
    }

    /**
     * Replaces percent-bounded expressions such as "%servletContext%."
     * common substitutions in config values
     *
     * @param input A string with expressions that should be replaced
     * @return new string with "common" expressions replaced by configuration values
     */
    public static String commonSubstitutions(final String input) {
        if (!StringUtils.contains(input, "%")) {
            return input;
        }
        return input.replace("%servletContext%", StringUtils.defaultString(CsrfGuardServletContextListener.getServletContext()));
    }
}
