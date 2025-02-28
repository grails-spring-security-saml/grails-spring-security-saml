package org.grails.plugin.springsecurity.saml

import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseCookie
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestRepository
import org.springframework.security.web.savedrequest.DefaultSavedRequest

import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpSession
import java.util.concurrent.ConcurrentHashMap

class LoginNonceService {
    public static final String ATTRIBUTE_NAME = "LoginNonce";
    public static final String REQUEST_CACHE_ATTRIBUTE_NAME = "LoginNonce-CachedRequest";
    public static final String COOKIE_NAME = "LoginNonce";

    private ConcurrentHashMap<String, DefaultSavedRequest> cachedRequests = new ConcurrentHashMap<>()
    private ConcurrentHashMap<String, AbstractSaml2AuthenticationRequest> authenticationRequests = new ConcurrentHashMap<>()

    Integer cookieExpiry = 30 * 60 // 30 minutes

    /**
     * Generate a new nonce
     * @return
     */
    String getNonce() {
        return UUID.randomUUID().toString()
    }

    /**
     * Obtain the nonce associated with this session
     * @param session
     * @return
     */
    String getSessionNonce(HttpSession session) {
        return session.getAttribute(ATTRIBUTE_NAME)
    }

    /**
     * Store the to be cached request in the session first,
     * so that it can be associated to the nonce at a later time
     * @param session
     * @return savedRequest
     */
    void prepareRequestCache(HttpSession session, DefaultSavedRequest savedRequest) {
        session.setAttribute(REQUEST_CACHE_ATTRIBUTE_NAME, savedRequest)
    }

    /**
     * Associate the given session with a new nonce
     * @param session
     * @return
     */
    void prepareNonce(HttpSession session) {
        def nonce = getNonce()
        session.setAttribute(ATTRIBUTE_NAME, nonce)

        DefaultSavedRequest savedRequest = session.getAttribute(REQUEST_CACHE_ATTRIBUTE_NAME)
        if (savedRequest != null) {
            cachedRequests.put(nonce, savedRequest)
        }
        session.removeAttribute(REQUEST_CACHE_ATTRIBUTE_NAME)
    }

    void setCachedRequest(String nonce, DefaultSavedRequest savedRequest) {
        cachedRequests.put(nonce, savedRequest)
    }

    DefaultSavedRequest getCachedRequest(String nonce) {
        if (nonce != null) {
            return cachedRequests.get(nonce)
        } else {
            return null
        }
    }

    DefaultSavedRequest removeCachedRequest(String nonce) {
        if (nonce != null) {
            return cachedRequests.remove(nonce)
        } else {
            return null
        }
    }

    void setAuthenticationRequest(String nonce, AbstractSaml2AuthenticationRequest savedRequest) {
        authenticationRequests.put(nonce, savedRequest)
    }

    AbstractSaml2AuthenticationRequest getAuthenticationRequest(String nonce) {
        return authenticationRequests.get(nonce)
    }

    AbstractSaml2AuthenticationRequest removeAuthenticationRequest(String nonce) {
        if (nonce != null) {
            return authenticationRequests.remove(nonce)
        } else {
            return null
        }
    }

    /**
     * Set the login nonce as a SameSite=None cookie for cross site correlation
     * @param session
     * @param nonce
     * @return
     */
    def prepareResponse(HttpServletResponse response, String nonce) {
        def cookie = createNonceCookie(nonce, cookieExpiry)
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
}
