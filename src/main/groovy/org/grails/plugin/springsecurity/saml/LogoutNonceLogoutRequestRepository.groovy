package org.grails.plugin.springsecurity.saml


import groovy.transform.CompileStatic

/*
 * Copyright 2002-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import org.springframework.security.crypto.codec.Utf8
import org.springframework.security.saml2.core.Saml2ParameterNames
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestRepository
import org.springframework.util.Assert

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import jakarta.servlet.http.HttpSession
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

@CompileStatic
class LogoutNonceLogoutRequestRepository implements Saml2LogoutRequestRepository {

    /**
     * An implementation of an {@link Saml2LogoutRequestRepository} that stores
     * {@link Saml2LogoutRequest} in the {@code HttpSession}.
     *
     * @author Josh Cummings
     * @since 5.6
     * @see Saml2LogoutRequestRepository
     * @see Saml2LogoutRequest
     */

    LogoutNonceService logoutNonceService

    private ConcurrentHashMap<String, Saml2LogoutRequest> logoutRequestByNonce = new ConcurrentHashMap<>()

    /**
     * {@inheritDoc}
     */
    @Override
    Saml2LogoutRequest loadLogoutRequest(HttpServletRequest request) {
        Assert.notNull(request, "request cannot be null");
        // Read the logout nonce
        String logoutNonce = logoutNonceService.getCookieNonce(request)
        Saml2LogoutRequest logoutRequest = logoutRequestByNonce.get(logoutNonce)
        if (stateParameterEquals(request, logoutRequest)) {
            return logoutRequest
        }
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    void saveLogoutRequest(Saml2LogoutRequest logoutRequest, HttpServletRequest request,
                                  HttpServletResponse response) {
        Assert.notNull(request, "request cannot be null");
        Assert.notNull(response, "response cannot be null");
        if (logoutRequest == null) {
            // Remove using nonce
            String logoutNonce = logoutNonceService.getCookieNonce(request)
            logoutRequestByNonce.remove(logoutNonce)
            return;
        }
        String state = logoutRequest.getRelayState();
        Assert.hasText(state, "logoutRequest.state cannot be empty");
        String logoutNonce = logoutNonceService.getCookieNonce(request)
        logoutRequestByNonce.put(logoutNonce, logoutRequest)
    }

    /**
     * {@inheritDoc}
     */
    @Override
    Saml2LogoutRequest removeLogoutRequest(HttpServletRequest request, HttpServletResponse response) {
        Assert.notNull(request, "request cannot be null");
        Assert.notNull(response, "response cannot be null");
        Saml2LogoutRequest logoutRequest = loadLogoutRequest(request);
        if (logoutRequest == null) {
            return null
        }
        // Read from the logout nonce session
        String logoutNonce = logoutNonceService.getCookieNonce(request)
        HttpSession session = logoutNonceService.getSession(logoutNonce)
        logoutRequestByNonce.remove(logoutNonce)
        logoutNonceService.cleanupSession(session)
        logoutNonceService.cleanupResponse(response, logoutNonce)
        return logoutRequest
    }

    private String getStateParameter(HttpServletRequest request) {
        return request.getParameter(Saml2ParameterNames.RELAY_STATE);
    }

    private boolean stateParameterEquals(HttpServletRequest request, Saml2LogoutRequest logoutRequest) {
        String stateParameter = getStateParameter(request);
        if (stateParameter == null || logoutRequest == null) {
            return false;
        }
        String relayState = logoutRequest.getRelayState();
        return MessageDigest.isEqual(Utf8.encode(stateParameter), Utf8.encode(relayState));
    }
}
