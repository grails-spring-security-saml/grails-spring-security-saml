package org.grails.plugin.springsecurity.saml

import org.springframework.core.convert.converter.Converter
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestRepository

import javax.servlet.http.HttpServletRequest

public class DefaultRegistrationResolver implements Converter<HttpServletRequest, RelyingPartyRegistration> {

    def relyingPartyRegistrationResolver
    def defaultRegistration
    Saml2AuthenticationRequestRepository authenticationRequestRepository
    // Saml2LogoutRequestRepository logoutRequestRepository

    RelyingPartyRegistration convert(HttpServletRequest request) {
        AbstractSaml2AuthenticationRequest authenticationRequest = authenticationRequestRepository.loadAuthenticationRequest(request)
        // Saml2LogoutRequest logoutRequest = logoutRequestRepository.loadLogoutRequest(request)

        String relyingPartyRegistrationId = defaultRegistration
        if (authenticationRequest != null) {
            relyingPartyRegistrationId = authenticationRequest.getRelyingPartyRegistrationId()
        }
        /* if (logoutRequest != null) {
            relyingPartyRegistrationId = logoutRequest.relyingPartyRegistrationId
        } */
        return relyingPartyRegistrationResolver.resolve(request, relyingPartyRegistrationId)
    }
}
