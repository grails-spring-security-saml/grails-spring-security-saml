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

    /**
     * Generate a new nonce
     * @return
     */
    def getNonce() {
        return UUID.randomUUID().toString()
    }

    /**
     * Obtain the nonce associated with this session
     * @param session
     * @return
     */
    def getSessionNonce(HttpSession session) {
        return session.getAttribute(ATTRIBUTE_NAME)
    }

    /**
     * Associate the given session with the nonce
     * @param session
     * @param nonce
     * @return
     */
    def prepareSession(HttpSession session, String nonce) {
        cleanupSession(session)
        session.setAttribute(ATTRIBUTE_NAME, nonce)
        sessionByAttribute.put(nonce, session)
    }

    /**
     * Set the login nonce as a SameSite=None cookie for cross site correlation
     * @param session
     * @param nonce
     * @return
     */
    def prepareResponse(HttpServletResponse response, String nonce) {
        def cookie = createNonceCookie(nonce, 60)
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString())
    }

    /**
     * Remove the login nonce cookie
     * @param session
     * @param nonce
     * @return
     */
    def cleanupResponse(HttpServletResponse response, String nonce) {
        def cookie = createNonceCookie(nonce, 0)
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString())
    }

    /**
     * Create a SameSite=None cookie based on a login nonce
     * @param nonce
     * @param expiry
     * @return
     */
    ResponseCookie createNonceCookie(String nonce, Integer expiry) {
        return ResponseCookie.from(COOKIE_NAME, nonce)
            .path("/")
            .secure(true)
            .httpOnly(true)
            .maxAge(expiry)
            .sameSite("None")
            .build()
    }

    /**
     * Get the nonce of the current http request based on its cookies
     * @param request
     * @return
     */
    def getCookieNonce(HttpServletRequest request) {
        //Assert.notNull(request, "request cannot be null")
        Cookie cookie = request.getCookies().find {it.name == COOKIE_NAME}
        if (cookie == null) {
            return null;
        }
        return cookie.getValue()
    }

    /**
     * Retrieve an old session based on a nonce
     * The retrieved session is tested for having been associated with this nonce
     * @param nonce
     * @return
     */
    def getSession(String nonce) {
        if (nonce == null) {
            return null
        }
        def session = sessionByAttribute.get(nonce)
        if (session != null && session.getAttribute(ATTRIBUTE_NAME) == nonce) {
            return session
        } else {
            return null
        }
    }

    /**
     * Remove the nonce association from this session and prevent the session from being retrieved in the future
     * @param session
     * @return
     */
    def cleanupSession(HttpSession session) {
        def nonceAttribute = session.getAttribute(ATTRIBUTE_NAME)
        session.removeAttribute(ATTRIBUTE_NAME)
        if (nonceAttribute) {
            sessionByAttribute.remove(nonceAttribute)
        } else {
            sessionByAttribute.removeAll {it.value == session }
        }
    }
}
