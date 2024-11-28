package org.grails.plugin.springsecurity.saml

import org.springframework.security.web.authentication.logout.LogoutHandler

/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

/**
 * @author Ben Alex
 * @author Rob Winch
 */
class LogoutNonceSecurityContextLogoutHandler implements LogoutHandler {

    protected final Log logger = LogFactory.getLog(this.getClass());

    private boolean invalidateHttpSession = true;

    private boolean clearAuthentication = true;

    LogoutNonceService logoutNonceService

    // taken from HttpSessionSecurityContextRepository
    // I had to copy paste the entire class, because the Spring Security devs decided to get the security context
    // from a thread local variable that will never be populated properly due to SameSite restrictions on the JSESSIONID cookie

    public static final String SPRING_SECURITY_CONTEXT_KEY = "SPRING_SECURITY_CONTEXT";
    private String springSecurityContextKey = SPRING_SECURITY_CONTEXT_KEY;

    /**
     * @param httpSession the session obtained from the request.
     */
    private SecurityContext readSecurityContextFromSession(HttpSession httpSession) {
        if (httpSession == null) {
            this.logger.trace("No HttpSession currently exists");
            return null;
        }
        // Session exists, so try to obtain a context from it.
        Object contextFromSession = httpSession.getAttribute(this.springSecurityContextKey);
        if (contextFromSession == null) {
            if (this.logger.isTraceEnabled()) {
                this.logger.trace(LogMessage.format("Did not find SecurityContext in HttpSession %s "
                        + "using the SPRING_SECURITY_CONTEXT session attribute", httpSession.getId()));
            }
            return null;
        }

        // We now have the security context object from the session.
        if (!(contextFromSession instanceof SecurityContext)) {
            this.logger.warn(LogMessage.format(
                    "%s did not contain a SecurityContext but contained: '%s'; are you improperly "
                            + "modifying the HttpSession directly (you should always use SecurityContextHolder) "
                            + "or using the HttpSession attribute reserved for this class?",
                    this.springSecurityContextKey, contextFromSession));
            return null;
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace(
                    LogMessage.format("Retrieved %s from %s", contextFromSession, this.springSecurityContextKey));
        }
        else if (this.logger.isDebugEnabled()) {
            this.logger.debug(LogMessage.format("Retrieved %s", contextFromSession));
        }
        // Everything OK. The only non-null return from this method.
        return (SecurityContext) contextFromSession;
    }

    /**
     * Requires the request to be passed in.
     * @param request from which to obtain a HTTP session (cannot be null)
     * @param response not used (can be <code>null</code>)
     * @param authentication not used (can be <code>null</code>)
     */
    @Override
    void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Assert.notNull(request, "HttpServletRequest required");

        if (logoutNonceService == null) {
            return
        }

        def nonce = logoutNonceService.getCookieNonce(request)
        if (nonce == null) {
            return
        }
        // obtain the session that initiated the logout
        HttpSession session = logoutNonceService.getSession(nonce)
        if (session == null) {
            return
        }
        SecurityContext context = readSecurityContextFromSession(session)
        if (this.invalidateHttpSession) {
            if (session != null) {
                session.invalidate();
                if (this.logger.isDebugEnabled()) {
                    this.logger.debug(LogMessage.format("Invalidated session %s", session.getId()));
                }
            }
        }
        SecurityContextHolder.clearContext()
        if (this.clearAuthentication) {
            context.setAuthentication(null)
        }

        logoutNonceService.cleanupResponse(response, nonce)
    }
}

