package org.grails.plugin.springsecurity.saml

import org.apache.commons.logging.Log
import org.apache.commons.logging.LogFactory
import org.springframework.core.log.LogMessage
import org.springframework.http.MediaType
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.context.SecurityContextHolderStrategy
import org.springframework.security.saml2.core.Saml2ParameterNames
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidator
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidatorParameters
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutValidatorResult
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestFilter
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseResolver
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2MessageBindingUtils
import org.springframework.security.web.DefaultRedirectStrategy
import org.springframework.security.web.RedirectStrategy
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler
import org.springframework.security.web.authentication.logout.LogoutHandler
import org.springframework.security.web.context.HttpRequestResponseHolder
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.util.Assert
import org.springframework.util.StringUtils
import org.springframework.web.filter.GenericFilterBean
import org.springframework.web.filter.OncePerRequestFilter
import org.springframework.web.util.HtmlUtils
import org.springframework.web.util.UriComponentsBuilder

import javax.servlet.DispatcherType
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpSession
import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidatorParameters;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutValidatorResult;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;

/*
 * Copyright 2002-2023 the original author or authors.
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

/**
 * A filter for handling logout requests in the form of a &lt;saml2:LogoutRequest&gt; sent
 * from the asserting party.
 *
 * @author Josh Cummings
 * @since 5.6
 * @see Saml2LogoutRequestValidator
 */
class LogoutNonceSaml2LogoutRequestFilter extends OncePerRequestFilter {

    private final Log logger = LogFactory.getLog(getClass());

    private final Saml2LogoutRequestValidator logoutRequestValidator;

    private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

    private final Saml2LogoutResponseResolver logoutResponseResolver;

    private final LogoutHandler handler;

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    private RequestMatcher logoutRequestMatcher = new AntPathRequestMatcher("/logout/saml2/slo");

    /* MODIFICATIONS START */
    LogoutNonceService logoutNonceService
    /* MODIFICATIONS END */

    /**
     * Constructs a {@link org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseFilter} for accepting SAML 2.0 Logout
     * Requests from the asserting party
     * @param relyingPartyRegistrationResolver the strategy for resolving a
     * {@link org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration}
     * @param logoutRequestValidator the SAML 2.0 Logout Request authenticator
     * @param logoutResponseResolver the strategy for creating a SAML 2.0 Logout Response
     * @param handlers the actions that perform logout
     */
    LogoutNonceSaml2LogoutRequestFilter(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver,
                                    Saml2LogoutRequestValidator logoutRequestValidator, Saml2LogoutResponseResolver logoutResponseResolver,
                                    LogoutHandler... handlers) {
        this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
        this.logoutRequestValidator = logoutRequestValidator;
        this.logoutResponseResolver = logoutResponseResolver;
        this.handler = new CompositeLogoutHandler(handlers);
    }

    /* MODIFICATIONS START */
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
    /* MODIFICATIONS END */

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (!this.logoutRequestMatcher.matches(request)) {
            chain.doFilter(request, response);
            return;
        }

        if (request.getParameter(Saml2ParameterNames.SAML_REQUEST) == null) {
            chain.doFilter(request, response);
            return;
        }
        /* MODIFICATIONS START */

        //Authentication authentication = this.securityContextHolderStrategy.getContext().getAuthentication();
        // obtain authentication via LogoutNonce
        def nonce = logoutNonceService.getCookieNonce(request)
        def httpSession = logoutNonceService.getSession(nonce)

        SecurityContext securityContext = readSecurityContextFromSession(httpSession)
        if (securityContext == null) {
            throw new IllegalStateException("No SecurityContext could be retrieved for this logout request")
        }

        Authentication authentication = readSecurityContextFromSession(httpSession).getAuthentication()
        if (authentication == null) {
            throw new IllegalStateException("No Authentication is associated with this SecurityContext")
        }

        /* MODIFICATIONS END */
        RelyingPartyRegistration registration = this.relyingPartyRegistrationResolver.resolve(request,
                getRegistrationId(authentication));
        if (registration == null) {
            this.logger
                    .trace("Did not process logout request since failed to find associated RelyingPartyRegistration");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        if (registration.getSingleLogoutServiceLocation() == null) {
            this.logger.trace(
                    "Did not process logout request since RelyingPartyRegistration has not been configured with a logout request endpoint");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        Saml2MessageBinding saml2MessageBinding = Saml2MessageBindingUtils.resolveBinding(request);
        if (!registration.getSingleLogoutServiceBindings().contains(saml2MessageBinding)) {
            this.logger.trace("Did not process logout request since used incorrect binding");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        String serialized = request.getParameter(Saml2ParameterNames.SAML_REQUEST);
        Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
                .samlRequest(serialized)
                .relayState(request.getParameter(Saml2ParameterNames.RELAY_STATE))
                .binding(saml2MessageBinding)
                .location(registration.getSingleLogoutServiceLocation())
                .parameters((params) -> params.put(Saml2ParameterNames.SIG_ALG,
                        request.getParameter(Saml2ParameterNames.SIG_ALG)))
                .parameters((params) -> params.put(Saml2ParameterNames.SIGNATURE,
                        request.getParameter(Saml2ParameterNames.SIGNATURE)))
                .parametersQuery((params) -> request.getQueryString())
                .build();
        Saml2LogoutRequestValidatorParameters parameters = new Saml2LogoutRequestValidatorParameters(logoutRequest,
                registration, authentication);
        Saml2LogoutValidatorResult result = this.logoutRequestValidator.validate(parameters);
        if (result.hasErrors()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, result.getErrors().iterator().next().toString());
            this.logger.debug(LogMessage.format("Failed to validate LogoutRequest: %s", result.getErrors()));
            return;
        }
        this.handler.logout(request, response, authentication);
        Saml2LogoutResponse logoutResponse = this.logoutResponseResolver.resolve(request, authentication);
        if (logoutResponse == null) {
            this.logger.trace("Returning 401 since no logout response generated");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        /* MODIFICATIONS START */
        logoutNonceService.cleanupResponse(response)
        logoutNonceService.cleanupSession(httpSession)
        /* MODIFICATIONS END */

        if (logoutResponse.getBinding() == Saml2MessageBinding.REDIRECT) {
            doRedirect(request, response, logoutResponse);
        }
        else {
            doPost(response, logoutResponse);
        }
    }

    void setLogoutRequestMatcher(RequestMatcher logoutRequestMatcher) {
        Assert.notNull(logoutRequestMatcher, "logoutRequestMatcher cannot be null");
        this.logoutRequestMatcher = logoutRequestMatcher;
    }

    /**
     * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
     * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
     *
     * @since 5.8
     */
    void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
        Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
        this.securityContextHolderStrategy = securityContextHolderStrategy;
    }

    private String getRegistrationId(Authentication authentication) {
        if (authentication == null) {
            return null;
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof Saml2AuthenticatedPrincipal) {
            return ((Saml2AuthenticatedPrincipal) principal).getRelyingPartyRegistrationId();
        }
        return null;
    }

    private void doRedirect(HttpServletRequest request, HttpServletResponse response,
                            Saml2LogoutResponse logoutResponse) throws IOException {
        String location = logoutResponse.getResponseLocation();
        UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(location)
                .query(logoutResponse.getParametersQuery());
        this.redirectStrategy.sendRedirect(request, response, uriBuilder.build(true).toUriString());
    }

    private void doPost(HttpServletResponse response, Saml2LogoutResponse logoutResponse) throws IOException {
        String location = logoutResponse.getResponseLocation();
        String saml = logoutResponse.getSamlResponse();
        String relayState = logoutResponse.getRelayState();
        String html = createSamlPostRequestFormData(location, saml, relayState);
        response.setContentType(MediaType.TEXT_HTML_VALUE);
        response.getWriter().write(html);
    }

    private String createSamlPostRequestFormData(String location, String saml, String relayState) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n");
        html.append("<html>\n").append("    <head>\n");
        html.append("        <meta http-equiv=\"Content-Security-Policy\" ")
                .append("content=\"script-src 'sha256-oZhLbc2kO8b8oaYLrUc7uye1MgVKMyLtPqWR4WtKF+c='\">\n");
        html.append("        <meta charset=\"utf-8\" />\n");
        html.append("    </head>\n");
        html.append("    <body>\n");
        html.append("        <noscript>\n");
        html.append("            <p>\n");
        html.append("                <strong>Note:</strong> Since your browser does not support JavaScript,\n");
        html.append("                you must press the Continue button once to proceed.\n");
        html.append("            </p>\n");
        html.append("        </noscript>\n");
        html.append("        \n");
        html.append("        <form action=\"");
        html.append(location);
        html.append("\" method=\"post\">\n");
        html.append("            <div>\n");
        html.append("                <input type=\"hidden\" name=\"SAMLResponse\" value=\"");
        html.append(HtmlUtils.htmlEscape(saml));
        html.append("\"/>\n");
        if (StringUtils.hasText(relayState)) {
            html.append("                <input type=\"hidden\" name=\"RelayState\" value=\"");
            html.append(HtmlUtils.htmlEscape(relayState));
            html.append("\"/>\n");
        }
        html.append("            </div>\n");
        html.append("            <noscript>\n");
        html.append("                <div>\n");
        html.append("                    <input type=\"submit\" value=\"Continue\"/>\n");
        html.append("                </div>\n");
        html.append("            </noscript>\n");
        html.append("        </form>\n");
        html.append("        \n");
        html.append("        <script>window.onload = function() { document.forms[0].submit(); }</script>\n");
        html.append("    </body>\n");
        html.append("</html>");
        return html.toString();
    }
}
