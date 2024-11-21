package org.grails.plugin.springsecurity.saml

import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestRepository

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;

class LoginNonceSaml2AuthenticationRequestRepository
        implements Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> {

    LoginNonceService loginNonceService

    private static final String DEFAULT_SAML2_AUTHN_REQUEST_ATTR_NAME = LoginNonceSaml2AuthenticationRequestRepository.class
        .getName()
        .concat(".SAML2_AUTHN_REQUEST");

    private String saml2AuthnRequestAttributeName = DEFAULT_SAML2_AUTHN_REQUEST_ATTR_NAME;

    @Override
    AbstractSaml2AuthenticationRequest loadAuthenticationRequest(HttpServletRequest request) {
        def loginNonce = loginNonceService.getCookieNonce(request)
        // obtain session based on cookie (getSession also verifies that the returned session created the login nonce)
        HttpSession httpSession = loginNonceService.getSession(loginNonce) ?: request.getSession(false)
        if (httpSession == null) {
            return null
        }
        AbstractSaml2AuthenticationRequest savedRequest = ((AbstractSaml2AuthenticationRequest) httpSession
            .getAttribute(this.saml2AuthnRequestAttributeName))

        def relayStateNonce = savedRequest.getRelayState()
        // check that this SSO attempt is actually associated with the previous httpSession
        if (loginNonce == relayStateNonce) {
            return savedRequest
        } else {
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
        def loginNonce = loginNonceService.getCookieNonce(request)
        HttpSession httpSession = loginNonceService.getSession(loginNonce) ?: request.getSession(false)
        httpSession.setAttribute(this.saml2AuthnRequestAttributeName, authenticationRequest)
    }

    @Override
    AbstractSaml2AuthenticationRequest removeAuthenticationRequest(HttpServletRequest request,
                                                                          HttpServletResponse response) {
        AbstractSaml2AuthenticationRequest authenticationRequest = loadAuthenticationRequest(request)
        if (authenticationRequest == null) {
            return null
        }
        def loginNonce = loginNonceService.getCookieNonce(request)
        HttpSession httpSession = loginNonceService.getSession(loginNonce) ?: request.getSession(false)
        httpSession.removeAttribute(this.saml2AuthnRequestAttributeName)
        loginNonceService.cleanupResponse(response, loginNonce)
        return authenticationRequest
    }

}
