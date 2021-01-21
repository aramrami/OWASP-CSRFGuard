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

import javax.servlet.ServletConfig;
import java.util.Properties;
import java.util.function.Function;

public abstract class JsConfigParameter<T> {

    public abstract T getProperty(final ServletConfig servletConfig, final Properties propertyCache);

    public static String getInitParameter(final ServletConfig servletConfig, final String name, final String configFileDefaultParamValue, final String defaultValue) {
        return getInitParameter(servletConfig, name, configFileDefaultParamValue, defaultValue, Function.identity());
    }

    public static boolean getInitParameter(final ServletConfig servletConfig, final String name, final String configFileDefaultParamValue, final boolean defaultValue) {
        return getInitParameter(servletConfig, name, configFileDefaultParamValue, defaultValue, Boolean::parseBoolean);
    }

    public static <T> T getInitParameter(final ServletConfig servletConfig, final String name, final String configFileDefaultParamValue, final T defaultValue, final Function<String, T> function) {
        final T result;

        final String initParameter = servletConfig.getInitParameter(name);

        if (StringUtils.isNotBlank(initParameter)) {
            result = function.apply(initParameter);
        } else if (StringUtils.isNotBlank(configFileDefaultParamValue)) {
            result = function.apply(configFileDefaultParamValue);
        } else {
            result = defaultValue;
        }

        return result;
    }
}
