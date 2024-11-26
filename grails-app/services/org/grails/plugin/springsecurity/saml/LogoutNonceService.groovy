package org.grails.plugin.springsecurity.saml

import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseCookie

import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpSession
import java.util.concurrent.ConcurrentHashMap

/**
 * They key difference between the LoginNonceService and the LogoutNonceService
 * is that a login nonce bridges between a pre-login and a post-login session and is therefore short-lived,
 * but a logout nonce needs to essentially be just a second JSESSIONID that can only be used for logout
 */
class LogoutNonceService {
    public static final String ATTRIBUTE_NAME = "LogoutNonce";
    public static final String COOKIE_NAME = "LogoutNonce";

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
     * Set the logout nonce as a SameSite=None cookie for cross site correlation
     * @param session
     * @param nonce
     * @return
     */
    def prepareResponse(HttpServletResponse response, String nonce) {
        def cookie = createNonceCookie(nonce, -1)
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString())
    }

    /**
     * Remove the logout nonce cookie
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
    HttpSession getSession(String nonce) {
        if (nonce == null) {
            return null
        }
        def session = sessionByAttribute.get(nonce)
        try {
            if (session != null && session.getAttribute(ATTRIBUTE_NAME) == nonce) {
                return session
            } else {
                return null
            }
        } catch(IllegalStateException e) {
            // session is invalid
            sessionByAttribute.remove(nonce)
            return null
        }
    }

    /**
     * Remove the nonce association from this session and prevent the session from being retrieved in the future
     * @param session
     * @return
     */
    def cleanupSession(HttpSession session) {
        if (session == null) {
            return
        }
        def nonceAttribute = session.getAttribute(ATTRIBUTE_NAME)
        session.removeAttribute(ATTRIBUTE_NAME)
        if (nonceAttribute) {
            sessionByAttribute.remove(nonceAttribute)
        } else {
            sessionByAttribute.removeAll {it.value == session }
        }
    }
}
