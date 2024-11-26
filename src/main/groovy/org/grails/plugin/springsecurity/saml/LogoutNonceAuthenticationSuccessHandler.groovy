package org.grails.plugin.springsecurity.saml

import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.AuthenticationSuccessHandler

import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class LogoutNonceAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    LogoutNonceService logoutNonceService
    AuthenticationSuccessHandler authenticationSuccessHandler

    @Override
    void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws ServletException, IOException {
        authenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication)

        def logoutNonce = logoutNonceService.getNonce()
        def session = request.getSession()
        logoutNonceService.prepareSession(session, logoutNonce)
        logoutNonceService.prepareResponse(response, logoutNonce)
    }
}
