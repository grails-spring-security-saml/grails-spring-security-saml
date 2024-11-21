package org.springframework.security.saml2.provider.service.web


import org.grails.plugin.springsecurity.saml.LoginNonceService
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestFactory
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher

import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class LoginNonceSaml2WebSsoAuthenticationRequestFilter extends Saml2WebSsoAuthenticationRequestFilter {
    LoginNonceService loginNonceService
    def loginNonceRedirectMatcher = new AntPathRequestMatcher("/saml2/authenticate/{registrationId}")

    LoginNonceSaml2WebSsoAuthenticationRequestFilter(Saml2AuthenticationRequestResolver authenticationRequestResolver) {
        super(authenticationRequestResolver)
    }

    void setRedirectMatcher(RequestMatcher redirectMatcher) {
        super.setRedirectMatcher (redirectMatcher)
        this.loginNonceRedirectMatcher = redirectMatcher
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        RequestMatcher.MatchResult matcher = loginNonceRedirectMatcher.matcher(request)
        if (matcher.isMatch()) {
            // set nonce cookie and record old session
            // the nonce cookie is necessary since SSO login hands off the login process to the IDP
            // and the returning request is considered a cross origin request
            // the nonce cookie lets the browser prove that it participated in the last login request with the previous session
            // because the nonce cookie is SameSite=None, but the JSESSIONID is SameSite=Lax and therefore reset
            // the nonce is only used for a single login attempt
            def nonce = loginNonceService.getNonce()
            loginNonceService.prepareSession(request.getSession(), nonce)
            loginNonceService.prepareResponse(response, nonce)
        }
        super.doFilterInternal(request, response, filterChain)
    }
}
