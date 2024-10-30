package org.grails.plugin.springsecurity.saml

import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseCookie

import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpSession
import java.util.concurrent.ConcurrentHashMap

class LoginNonceService {
    public static final String ATTRIBUTE_NAME = "LoginNonce";
    public static final String COOKIE_NAME = "LoginNonce";

    ConcurrentHashMap<String, HttpSession> sessionByAttribute = new ConcurrentHashMap<>()

    def getNonce() {
        return UUID.randomUUID().toString()
    }

    def prepareSession(HttpSession session, String nonce) {
        session.setAttribute(ATTRIBUTE_NAME, nonce)
        sessionByAttribute.put(nonce, session)
    }

    def prepareResponse(HttpServletResponse response, String nonce) {
        def cookie = createNonceCookie(nonce)
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString())
    }

    ResponseCookie createNonceCookie(String nonce) {
        return ResponseCookie.from(COOKIE_NAME, nonce)
            .path("/")
            .secure(true)
            .httpOnly(true)
            .maxAge(60)
            .sameSite("None")
            .build()
    }

    def getCookieNonce(HttpServletRequest request) {
        //Assert.notNull(request, "request cannot be null")
        Cookie cookie = request.getCookies().find {it.name == COOKIE_NAME}
        if (cookie == null) {
            return null;
        }
        return cookie.getValue()
    }

    def getSession(String nonce) {
        if (nonce == null) {
            return null
        }
        def session =  sessionByAttribute.get(nonce)
        if (session != null && session.getAttribute(ATTRIBUTE_NAME) == nonce) {
            return session
        } else {
            return null
        }
    }

    def cleanupSession(HttpSession session) {
        def nonceAttribute = session.getAttribute(ATTRIBUTE_NAME)
        session.removeAttribute(ATTRIBUTE_NAME)
        if (nonceAttribute) {
            sessionByAttribute.remove(nonceAttribute)
        } else {
            // TODO this is unnecessarily slow
            sessionByAttribute.removeAll {it.value == session }
        }
    }
}
