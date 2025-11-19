package org.grails.plugin.springsecurity.saml

import grails.web.http.HttpHeaders
import groovy.json.JsonOutput
import groovy.json.JsonSlurper

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

import groovy.transform.CompileStatic
import org.springframework.http.ResponseCookie
import org.springframework.security.crypto.codec.Utf8
import org.springframework.security.saml2.core.Saml2ParameterNames
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestRepository
import org.springframework.util.Assert

import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import java.security.MessageDigest

@CompileStatic
class CookieLogoutRequestRepository implements Saml2LogoutRequestRepository {

    public static final String COOKIE_NAME = CookieLogoutRequestRepository.class.getName() + ".Saml2LogoutRequest";
    private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    CookieLogoutRequestRepository(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
        this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository
    }

    /**
     * {@inheritDoc}
     */
    @Override
    Saml2LogoutRequest loadLogoutRequest(HttpServletRequest request) {
        Assert.notNull(request, "request cannot be null")

        Cookie cookie = request.getCookies().find {it.name == COOKIE_NAME}
        if (cookie == null) {
            println "Cookie $COOKIE_NAME is null!"
            return null;
        }
        Saml2LogoutRequest logoutRequest = getSaml2LogoutRequestFromCookie(cookie)
        if (stateParameterEquals(request, logoutRequest)) {
            return logoutRequest
        }
        return null
    }

    /**
     * {@inheritDoc}
     */
    @Override
    void saveLogoutRequest(Saml2LogoutRequest logoutRequest, HttpServletRequest request,
                                  HttpServletResponse response) {
        Assert.notNull(request, "request cannot be null")
        Assert.notNull(response, "response cannot be null")
        if (logoutRequest == null) {
            ResponseCookie cookie = getSaml2LogoutRequestCookie(logoutRequest, 0)
            response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString())
            return
        }

        String state = logoutRequest.getRelayState()
        Assert.hasText(state, "logoutRequest.state cannot be empty");

        ResponseCookie cookie = getSaml2LogoutRequestCookie(logoutRequest)
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString())
    }

    /**
     * {@inheritDoc}
     */
    @Override
    Saml2LogoutRequest removeLogoutRequest(HttpServletRequest request, HttpServletResponse response) {
        Assert.notNull(request, "request cannot be null")
        Assert.notNull(response, "response cannot be null")
        Saml2LogoutRequest logoutRequest = loadLogoutRequest(request)
        if (logoutRequest == null) {
            return null;
        }
        ResponseCookie cookie = getSaml2LogoutRequestCookie(logoutRequest, 0, true)
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString())
        return logoutRequest;
    }

    ResponseCookie getSaml2LogoutRequestCookie(Saml2LogoutRequest saml2LogoutRequest, Integer maxAge = -1, Boolean remove = false) {
        def json = JsonOutput.toJson([
            id: saml2LogoutRequest.getId(),
            location: saml2LogoutRequest.getLocation(),
            binding: saml2LogoutRequest.getBinding().getUrn(),
            parameters: saml2LogoutRequest.getParameters(),
            relyingPartyRegistrationId: saml2LogoutRequest.getRelyingPartyRegistrationId()
        ])
        def value = Base64.getEncoder().encodeToString(json.getBytes())
        if (remove) {
            value = ""
        }
        return ResponseCookie.from(COOKIE_NAME, value)
                .path("/")
                .secure(true)
                .httpOnly(true)
                .maxAge(maxAge)
                .sameSite("None")
                .build()
    }

    /**
     *
     * @param saml2LogoutRequest
     * @param maxAge 0 deletes the cookie, -1 keeps it until the browser is closed
     * @return
     */
    Saml2LogoutRequest getSaml2LogoutRequestFromCookie(Cookie cookie) {
        def value = cookie.getValue()
        def json = new String(Base64.getDecoder().decode(value))
        def obj = new JsonSlurper().parseText(json)
        def map = obj as Map

        def parameters = map.parameters as Map

        def relyingPartyRegistration = relyingPartyRegistrationRepository.findByRegistrationId(map.relyingPartyRegistrationId as String)
        Assert.notNull(relyingPartyRegistration, "relyingPartyRegistration ${map.relyingPartyRegistrationId} cannot be null")

        return Saml2LogoutRequest.withRelyingPartyRegistration(relyingPartyRegistration)
            .id(map.id as String)
            .location(map.location as String)
            .binding(Saml2MessageBinding.from(map.binding as String))
            .parameters { it  -> it.putAll(parameters)}
            .build()
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
