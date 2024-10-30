package org.grails.plugin.springsecurity.saml

import org.springframework.boot.web.server.Cookie
import org.springframework.boot.web.servlet.server.CookieSameSiteSupplier
import org.springframework.util.ObjectUtils

class JSESSIONIDCookieSameSiteSupplier implements CookieSameSiteSupplier {
    //private static final String NAME = Authentication.class.getName();

    @Override
    Cookie.SameSite getSameSite(javax.servlet.http.Cookie cookie) {
        if (ObjectUtils.nullSafeEquals(cookie.getName(), "JSESSIONID")) {
            /*RequestAttributes attributes = RequestContextHolder.currentRequestAttributes()
            Authentication authentication = (Authentication) attributes.getAttribute(NAME, RequestAttributes.SCOPE_REQUEST)
            return (authentication == null || !authentication.isAuthenticated()) ?
                    Cookie.SameSite.NONE : Cookie.SameSite.STRICT;*/
            return Cookie.SameSite.LAX
        } else {
            return null
        }
    }
}
