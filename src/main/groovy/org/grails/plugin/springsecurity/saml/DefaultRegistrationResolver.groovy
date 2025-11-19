package org.grails.plugin.springsecurity.saml

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver

/**
 * If no relyingPartyRegistrationId is associated with a request (= null),
 * use the first relying party in the list, or alternatively, the one specified in conf.saml.metadata.defaultIdp
 */
public class DefaultRegistrationResolver implements RelyingPartyRegistrationResolver {

    def relyingPartyRegistrationResolver
    def defaultRegistration
    // Saml2AuthenticationRequestRepository authenticationRequestRepository
    // Saml2LogoutRequestRepository logoutRequestRepository

    @Override
    RelyingPartyRegistration resolve(HttpServletRequest request, String relyingPartyRegistrationId) {
        // Saml2LogoutRequest logoutRequest = logoutRequestRepository.loadLogoutRequest(request)

        if (relyingPartyRegistrationId == null) {
            relyingPartyRegistrationId = defaultRegistration
        }
        /* if (logoutRequest != null) {
            relyingPartyRegistrationId = logoutRequest.relyingPartyRegistrationId
        } */
        return relyingPartyRegistrationResolver.resolve(request, relyingPartyRegistrationId)
    }
}
