package org.grails.plugin.springsecurity.saml


import javax.servlet.http.*

class LoginNonceSessionListener implements HttpSessionListener {
    LoginNonceService loginNonceService

    @Override
    void sessionCreated(HttpSessionEvent se) {
        /* Not required for this */
    }

    @Override
    void sessionDestroyed(HttpSessionEvent se) {
        // Cleanup session attributes from the map
        HttpSession session = se.getSession()
        loginNonceService.cleanupSession(session)
    }
}
