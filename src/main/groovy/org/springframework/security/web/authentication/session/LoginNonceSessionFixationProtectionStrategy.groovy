package org.springframework.security.web.authentication.session

import org.grails.plugin.springsecurity.saml.LoginNonceService
import org.springframework.core.log.LogMessage
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest
import org.springframework.util.Assert

import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpSession

/**
 *
 */
class LoginNonceSessionFixationProtectionStrategy extends AbstractSessionFixationProtectionStrategy {
    LoginNonceService loginNonceService

    Boolean migrateSessionAttributes = true

    LoginNonceSessionFixationProtectionStrategy() {
        super()
    }

    protected Map<String, Object> extractAttributes(HttpSession session) {
        return this.createMigratedAttributeMap(session);
    }

    @Override
    final HttpSession applySessionFixation(HttpServletRequest request) {
        // freshly generated or possibly a previous but anonymous session
        HttpSession session = request.getSession();

        // retrieve old session from SSO login nonce
        def loginNonce = loginNonceService.getCookieNonce(request)
        if (loginNonce) {
            session = loginNonceService.getSession(loginNonce)
            loginNonceService.cleanupSession(session)
        }

        String originalSessionId = session.getId();
        this.logger.debug(LogMessage.of(() -> {
            return "Invalidating session with Id '" + originalSessionId + "' " + (this.migrateSessionAttributes ? "and" : "without") + " migrating attributes.";
        }));
        Map<String, Object> attributesToMigrate = this.extractAttributes(session);
        int maxInactiveIntervalToMigrate = session.getMaxInactiveInterval();
        session.invalidate();
        session = request.getSession(true);
        this.logger.debug(LogMessage.format("Started new session: %s", session.getId()));
        this.transferAttributes(attributesToMigrate, session);
        if (this.migrateSessionAttributes) {
            session.setMaxInactiveInterval(maxInactiveIntervalToMigrate);
        }

        return session;
    }

    void transferAttributes(Map<String, Object> attributes, HttpSession newSession) {
        if (attributes != null) {
            Objects.requireNonNull(newSession);
            attributes.forEach(newSession::setAttribute);
        }

    }

    private HashMap<String, Object> createMigratedAttributeMap(HttpSession session) {
        HashMap<String, Object> attributesToMigrate = new HashMap();
        Enumeration<String> enumeration = session.getAttributeNames();

        while(true) {
            String key;
            do {
                if (!enumeration.hasMoreElements()) {
                    return attributesToMigrate;
                }

                key = (String)enumeration.nextElement();
            } while(!this.migrateSessionAttributes && !key.startsWith("SPRING_SECURITY_"));

            attributesToMigrate.put(key, session.getAttribute(key));
        }
    }

    public void setMigrateSessionAttributes(boolean migrateSessionAttributes) {
        this.migrateSessionAttributes = migrateSessionAttributes;
    }
}
