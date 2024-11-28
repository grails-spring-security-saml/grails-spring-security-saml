package org.grails.plugin.springsecurity.saml

import org.springframework.security.web.savedrequest.DefaultSavedRequest
import org.springframework.security.web.savedrequest.RequestCache
import org.springframework.security.web.savedrequest.SavedRequest
import org.springframework.security.web.savedrequest.SavedRequestAwareWrapper

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpSession

import org.apache.commons.logging.Log
import org.apache.commons.logging.LogFactory

import org.springframework.core.log.LogMessage
import org.springframework.security.web.PortResolver
import org.springframework.security.web.PortResolverImpl
import org.springframework.security.web.util.UrlUtils
import org.springframework.security.web.util.matcher.AnyRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher

import java.util.concurrent.ConcurrentHashMap

class LoginNonceRequestCache implements RequestCache {
    static final String SAVED_REQUEST = "SPRING_SECURITY_SAVED_REQUEST";

    protected final Log logger = LogFactory.getLog(this.getClass());

    private PortResolver portResolver = new PortResolverImpl();

    private boolean createSessionAllowed = true;

    private RequestMatcher requestMatcher = AnyRequestMatcher.INSTANCE;

    private String sessionAttrName = SAVED_REQUEST;

    private LoginNonceService loginNonceService;

    /**
     * Stores the current request, provided the configuration properties allow it.
     */
    @Override
    void saveRequest(HttpServletRequest request, HttpServletResponse response) {
        if (!this.requestMatcher.matches(request)) {
            if (this.logger.isTraceEnabled()) {
                this.logger.trace(
                        LogMessage.format("Did not save request since it did not match [%s]", this.requestMatcher));
            }
            return;
        }
        DefaultSavedRequest savedRequest = new DefaultSavedRequest(request, this.portResolver);
        // this is called in sendStartAuthentication, when a protected resource is accessed
        // and you are redirected to the authentication page instead, so that it can redirect you back
        loginNonceService.prepareRequestCache(request.getSession(), savedRequest)
        if (this.logger.isDebugEnabled()) {
            this.logger.debug(LogMessage.format("Saved request %s to session", savedRequest.getRedirectUrl()));
        }
    }

    @Override
    SavedRequest getRequest(HttpServletRequest request, HttpServletResponse response) {
        def nonce = loginNonceService.getCookieNonce(request)
        // check relayState
        def relayStateNonce = request.getParameter("RelayState")
        if (nonce == relayStateNonce) {
            return loginNonceService.getCachedRequest(nonce)
        } else {
            throw new RuntimeException("$nonce != $relayStateNonce")
            // return null
        }
    }

    @Override
    void removeRequest(HttpServletRequest request, HttpServletResponse response) {
        def nonce = loginNonceService.getCookieNonce(request)
        loginNonceService.removeCachedRequest(nonce)
    }

    @Override
    HttpServletRequest getMatchingRequest(HttpServletRequest request, HttpServletResponse response) {
        SavedRequest saved = getRequest(request, response);
        if (saved == null) {
            this.logger.trace("No saved request");
            return null;
        }
        if (!matchesSavedRequest(request, saved)) {
            if (this.logger.isTraceEnabled()) {
                this.logger.trace(LogMessage.format("Did not match request %s to the saved one %s",
                        UrlUtils.buildRequestUrl(request), saved));
            }
            return null;
        }
        removeRequest(request, response);
        if (this.logger.isDebugEnabled()) {
            this.logger.debug(LogMessage.format("Loaded matching saved request %s", saved.getRedirectUrl()));
        }
        return new SavedRequestAwareWrapper(saved, request);
    }

    private boolean matchesSavedRequest(HttpServletRequest request, SavedRequest savedRequest) {
        if (savedRequest instanceof DefaultSavedRequest) {
            DefaultSavedRequest defaultSavedRequest = (DefaultSavedRequest) savedRequest;
            return defaultSavedRequest.doesRequestMatch(request, this.portResolver);
        }
        String currentUrl = UrlUtils.buildFullRequestUrl(request);
        return savedRequest.getRedirectUrl().equals(currentUrl);
    }

    /**
     * Allows selective use of saved requests for a subset of requests. By default any
     * request will be cached by the {@code saveRequest} method.
     * <p>
     * If set, only matching requests will be cached.
     * @param requestMatcher a request matching strategy which defines which requests
     * should be cached.
     */
    void setRequestMatcher(RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
    }

    /**
     * If <code>true</code>, indicates that it is permitted to store the target URL and
     * exception information in a new <code>HttpSession</code> (the default). In
     * situations where you do not wish to unnecessarily create <code>HttpSession</code>s
     * - because the user agent will know the failed URL, such as with BASIC or Digest
     * authentication - you may wish to set this property to <code>false</code>.
     */
    void setCreateSessionAllowed(boolean createSessionAllowed) {
        this.createSessionAllowed = createSessionAllowed;
    }

    void setPortResolver(PortResolver portResolver) {
        this.portResolver = portResolver;
    }

    /**
     * If the {@code sessionAttrName} property is set, the request is stored in the
     * session using this attribute name. Default is "SPRING_SECURITY_SAVED_REQUEST".
     * @param sessionAttrName a new session attribute name.
     * @since 4.2.1
     */
    void setSessionAttrName(String sessionAttrName) {
        this.sessionAttrName = sessionAttrName;
    }

    void setLoginNonceService(LoginNonceService loginNonceService) {
        this.loginNonceService = loginNonceService;
    }

}
