package org.grails.plugin.springsecurity.saml

import org.springframework.core.log.LogMessage
import org.springframework.security.web.DefaultRedirectStrategy
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse

class PostAwareRedirectStrategy extends DefaultRedirectStrategy {

    @Override
    public void sendRedirect(HttpServletRequest request, HttpServletResponse response, String url) throws IOException {
        String redirectUrl = calculateRedirectUrl(request.getContextPath(), url);
        redirectUrl = response.encodeRedirectURL(redirectUrl);
        if (this.logger.isDebugEnabled()) {
            this.logger.debug(LogMessage.format("Redirecting to %s", redirectUrl));
        }
        if (request.getMethod() == "POST") {
            response.setStatus(303)
            response.setHeader("Location", redirectUrl)
        } else {
            response.sendRedirect(redirectUrl);
        }
    }
}
