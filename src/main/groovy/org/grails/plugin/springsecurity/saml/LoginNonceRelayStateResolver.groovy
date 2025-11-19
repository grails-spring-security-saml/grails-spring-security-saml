package org.grails.plugin.springsecurity.saml

import jakarta.servlet.http.HttpServletRequest
import org.springframework.core.convert.converter.Converter

// 	private Converter<HttpServletRequest, String> relayStateResolver = (request) -> UUID.randomUUID().toString();
class LoginNonceRelayStateResolver implements Converter<HttpServletRequest, String> {

    LoginNonceService loginNonceService

    @Override
    String convert(HttpServletRequest source) {
        loginNonceService.prepareNonce(source.getSession())
        return loginNonceService.getSessionNonce(source.getSession())
    }
}
