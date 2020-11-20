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

package org.owasp.csrfguard;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.owasp.csrfguard.servlet.JavaScriptServlet;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CsrfValidatorTest {

    @Test
    void testResourceValidationWithNoRules() {
        final Set<String> matchingRules = Collections.emptySet();
        final List<String> resourcesToTest = Arrays.asList("test.html", "/test.html");

        testResourceValidation(matchingRules, Collections.emptyList(), resourcesToTest);
    }

    @Test
    void testResourceValidationWithPathMatchingRule() {
        final Set<String> matchingRules = Collections.singleton("/*");

        final List<String> resourceSet = Arrays.asList("protect.html", "/protect.html", "something/protect.txt", "/something/protect.txt");

        testResourceValidation(matchingRules, resourceSet, Collections.emptyList());
    }

    @Test
    void testResourceValidationWithStaticRules() {
        final Set<String> matchingRules = Stream.of("/unprotected.html", "/also_unprotected.jsp").collect(Collectors.toSet());

        final List<String> firstResourceSet = Arrays.asList("unprotected.html", "also_unprotected.jsp", "/unprotected.html", "/also_unprotected.jsp");
        final List<String> secondResourceSet = Arrays.asList("test.html", "/test.html", "test.jsp", "/test.jsp");

        testResourceValidation(matchingRules, firstResourceSet, secondResourceSet);
    }

    @Test
    void testResourceValidationWithRegexRules() {
        final String matchingRule = "^.*protect\\..*$";
        final List<String> firstResourceSet = Arrays.asList("protect.html", "/protect.html", "something/protect.txt", "/something/protect.txt");
        final List<String> secondResourceSet = Arrays.asList("test.html", "/test.html", "/protect");

        testResourceValidation(matchingRule, firstResourceSet, secondResourceSet);
    }

    @Test
    void testResourceValidationWithPartialPathMatchingRule() {
        final String matchingRule = "/protected/*";

        final List<String> firstResourceSet = Arrays.asList("protected/test.html", "/protected/test.html");
        final List<String> secondResourceSet = Arrays.asList("test.html", "/test.html", "/protect");

        testResourceValidation(matchingRule, firstResourceSet, secondResourceSet);
    }

    @Test
    void testResourceValidationWithExtensionMatchingRule() {
        final String matchingRule = "*.jsp";

        final List<String> firstResourceSet = Arrays.asList("protected/test.jsp", "/protected/test.jsp");
        final List<String> secondResourceSet = Arrays.asList("something/test.html", "/test.html", "/protect");

        testResourceValidation(matchingRule, firstResourceSet, secondResourceSet);
    }

    private static void executeInMockedContext(final Consumer<CsrfGuard> csrfGuardConsumer) {
        final CsrfGuard csrfGuard = mock(CsrfGuard.class);

        try (final MockedStatic<JavaScriptServlet> javaScriptServletMockedStatic = mockStatic(JavaScriptServlet.class)) {
            javaScriptServletMockedStatic.when(JavaScriptServlet::getJavascriptUris).thenReturn(Collections.singleton("/JavaScriptServlet"));

            try (final MockedStatic<CsrfGuard> csrfGuardMockedStatic = mockStatic(CsrfGuard.class)) {
                csrfGuardMockedStatic.when(CsrfGuard::getInstance).thenReturn(csrfGuard);
                csrfGuardConsumer.accept(CsrfGuard.getInstance());
            }
        }
    }

    private void testResourceValidation(final String matchingRule, final List<String> firstResourceSet, final List<String> secondResourceSet) {
        testResourceValidation(Collections.singleton(matchingRule), firstResourceSet, secondResourceSet);
    }

    private void testResourceValidation(final Set<String> matchingRule, final List<String> firstResourceSet, final List<String> secondResourceSet) {
        testResourceValidation(true, matchingRule, firstResourceSet, secondResourceSet);
        testResourceValidation(false, matchingRule, secondResourceSet, firstResourceSet);
    }

    private void testResourceValidation(final boolean isProtect, final Set<String> matchingRules, final List<String> protectedResources, final List<String> unProtectedResources) {
        executeInMockedContext(csrfGuard -> {
            final CsrfValidator csrfValidator = initializeValidator(csrfGuard, isProtect, matchingRules);

            assertPagesAreProtected(csrfValidator, protectedResources);
            assertPagesAreNotProtected(csrfValidator, unProtectedResources);
        });
    }

    private CsrfValidator initializeValidator(final CsrfGuard csrfGuard, final boolean isProtect, final Set<String> matchingRules) {
        when(csrfGuard.isProtectEnabled()).thenReturn(isProtect);

        if (isProtect) {
            when(csrfGuard.getProtectedPages()).thenReturn(matchingRules);
        } else {
            when(csrfGuard.getUnprotectedPages()).thenReturn(matchingRules);
        }

        return new CsrfValidator();
    }

    private void assertPagesAreProtected(final CsrfValidator csrfValidator, final List<String> resources) {
        assertPageProtection(csrfValidator, true, resources);
    }

    private void assertPagesAreNotProtected(final CsrfValidator csrfValidator, final List<String> resources) {
        assertPageProtection(csrfValidator, false, resources);
    }

    private void assertPageProtection(final CsrfValidator csrfValidator, final boolean isProtected, final List<String> resources) {
        resources.forEach(resource -> {
            final ProtectionResult protectionResult = csrfValidator.isProtectedPageAndMethod(resource, "not relevant");

            testResourceNormalized(resource, protectionResult);

            if (isProtected != protectionResult.isProtected()) {
                fail(String.format("The '%s' resource should %s protected!", resource, isProtected ? "be" : "not be"));
            }
        });
    }

    private void testResourceNormalized(final String resource, final ProtectionResult protectionResult) {
        final String normalizedResource = protectionResult.getResourceIdentifier();
        final Predicate<Character> normalizationTester = startingCharacter -> (normalizedResource.charAt(0) != startingCharacter) && (normalizedResource.charAt(1) != startingCharacter);

        if (normalizationTester.test('/') && normalizationTester.test('^')) {
            fail(String.format("The '%s' resource should start with a '^' character if a regular expression has matched it, '/' otherwise!", resource));
        }
    }
}
