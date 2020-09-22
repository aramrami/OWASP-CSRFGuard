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
package org.owasp.csrfguard.util;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.RecursiveToStringStyle;
import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.owasp.csrfguard.action.IAction;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Collection;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CsrfGuardPropertiesToStringBuilder extends ReflectionToStringBuilder {

    private static final String PREFIX_CHARACTER = "*";
    private static final String PREFIX = PREFIX_CHARACTER + StringUtils.SPACE;
    private static final int CONFIG_DELIMITER_LENGTH = 60;
    private static final String NEW_LINE = System.lineSeparator();

    private static final Function<String, String> FIELD_NAME_TRANSFORMER = fieldName -> StringUtils.capitalize(StringUtils.join(StringUtils.splitByCharacterTypeCamelCase(fieldName), StringUtils.SPACE));

    private static final String[] FIELDS_TO_EXCLUDE = {"propertiesCache"};

    public CsrfGuardPropertiesToStringBuilder(final Object object) {
        super(object, new CustomStyle());
        setExcludeFieldNames(FIELDS_TO_EXCLUDE);
    }

    @Override
    public String toString() {
        final String marginals = Stream.generate(() -> PREFIX_CHARACTER).limit(CONFIG_DELIMITER_LENGTH).collect(Collectors.joining(StringUtils.EMPTY, NEW_LINE, NEW_LINE));

        return marginals
               + PREFIX + "OWASP CSRFGuard properties" + NEW_LINE
               + NEW_LINE
               + PREFIX + super.toString()
               + marginals;
    }

    @Override
    public ToStringBuilder append(final String fieldName, final boolean value) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), value);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final boolean[] array) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), array);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final boolean[] array, final boolean fullDetail) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), array, fullDetail);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final byte value) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), value);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final byte[] array) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), array);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final byte[] array, final boolean fullDetail) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), array, fullDetail);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final char value) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), value);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final char[] array) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), array);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final char[] array, final boolean fullDetail) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), array, fullDetail);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final double value) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), value);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final double[] array) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), array);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final double[] array, final boolean fullDetail) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), array, fullDetail);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final float value) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), value);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final float[] array) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), array);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final float[] array, final boolean fullDetail) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), array, fullDetail);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final int value) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), value);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final int[] array) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), array);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final int[] array, final boolean fullDetail) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), array, fullDetail);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final long value) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), value);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final long[] array) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), array);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final long[] array, final boolean fullDetail) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), array, fullDetail);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final Object obj) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), obj);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final Object obj, final boolean fullDetail) {
        final Object value = customToString(obj);
        return Objects.isNull(value) ? this
                                     : super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), value, fullDetail);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final Object[] array) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), array);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final Object[] array, final boolean fullDetail) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), array, fullDetail);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final short value) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), value);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final short[] array) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), array);
    }

    @Override
    public ToStringBuilder append(final String fieldName, final short[] array, final boolean fullDetail) {
        return super.append(FIELD_NAME_TRANSFORMER.apply(fieldName), array, fullDetail);
    }

    private Object customToString(final Object obj) {
        return customToString(obj, StringUtils.EMPTY);
    }

    private Object customToString(final Object obj, final String prefixOffset) {
        final Object result;
        if (Objects.isNull(obj)) {
            result = null;
        } else {
            final String className = obj.getClass().getName();
            if (obj instanceof Collection) {
                result = handleCollections((Collection<?>) obj);
            } else if (obj instanceof SecureRandom) {
                final SecureRandom secureRandom = (SecureRandom) obj;
                result = String.format("%s(algorithm: %s, provider: %s)", secureRandom.getClass().getName(), secureRandom.getAlgorithm(), secureRandom.getProvider());
            } else if (obj instanceof Duration) {
                result = ((Duration) obj).toMillis() + " ms";
            } else if (obj instanceof IAction) {
                result = handleActions((IAction) obj, prefixOffset);
            } else if (className.startsWith("org.owasp.csrfguard")) { // TODO extract and reuse
                result = className;
            } else {
                result = obj;
            }
        }
        return result;
    }

    private Object handleActions(final IAction action, final String prefixOffset) {
        final String parameters = action.getParameterMap().entrySet().stream()
                                        .map(e -> String.format("%s\t%sParameter: %s = %s", prefixOffset, PREFIX, e.getKey(), e.getValue()))
                                        .collect(Collectors.joining(NEW_LINE));

        final String actionString = action.getClass().getName();
        return StringUtils.isBlank(parameters) ? actionString
                                               : actionString + NEW_LINE + parameters;
    }

    private Object handleCollections(final Collection<?> collection) {
        return collection.isEmpty() ? null
                                    : collection.stream()
                                                .map(element -> NEW_LINE + '\t' + PREFIX + customToString(element, "\t"))
                                                .collect(Collectors.joining());
    }

    private static class CustomStyle extends RecursiveToStringStyle {
        public CustomStyle() {
            super();

            setUseClassName(false);
            setUseIdentityHashCode(false);
            setFieldSeparator(NEW_LINE + PREFIX);
            setFieldNameValueSeparator(':' + StringUtils.SPACE);
            setContentStart(StringUtils.EMPTY);
            setContentEnd(StringUtils.EMPTY);
        }
    }
}
