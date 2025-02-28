package org.grails.plugin.springsecurity.saml

import groovy.util.logging.Slf4j
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestRepository

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Slf4j('logger')
class LoginNonceSaml2AuthenticationRequestRepository
        implements Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> {

    LoginNonceService loginNonceService

    @Override
    AbstractSaml2AuthenticationRequest loadAuthenticationRequest(HttpServletRequest request) {
        def loginNonce = loginNonceService.getCookieNonce(request)
        // check that this SSO attempt is actually associated with the nonce
        def relayStateNonce = request.getParameter("RelayState")

        if (loginNonce == relayStateNonce) {
            return loginNonceService.getAuthenticationRequest(loginNonce)
        } else {
            logger.warn("The login nonce \"$loginNonce\" did not match the relayNonce \"$relayStateNonce\". " +
                    "This was most likely caused by an expiry of the login nonce cookie.")
            return null
        }
    }

    @Override
    void saveAuthenticationRequest(AbstractSaml2AuthenticationRequest authenticationRequest,
                                   HttpServletRequest request, HttpServletResponse response) {
        if (authenticationRequest == null) {
            removeAuthenticationRequest(request, response);
            return;
        }
        def nonce = loginNonceService.getSessionNonce(request.getSession())
        loginNonceService.prepareResponse(response, nonce)
        loginNonceService.setAuthenticationRequest(nonce, authenticationRequest)
    }

    @Override
    AbstractSaml2AuthenticationRequest removeAuthenticationRequest(HttpServletRequest request,
                                                                   HttpServletResponse response) {
        AbstractSaml2AuthenticationRequest authenticationRequest = loadAuthenticationRequest(request)
        if (authenticationRequest == null) {
            return null
        }
        def nonce = loginNonceService.getCookieNonce(request)
        loginNonceService.cleanupResponse(response, nonce)
        return loginNonceService.removeAuthenticationRequest(nonce)
    }

}
