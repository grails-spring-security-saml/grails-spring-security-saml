package org.grails.plugin.springsecurity.saml

import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString
import grails.compiler.GrailsCompileStatic

import grails.plugin.springsecurity.userdetails.GrailsUser
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import java.io.Serializable
import org.springframework.util.Assert

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.AuthenticatedPrincipal;
import java.security.Principal;


@GrailsCompileStatic
class NamedSaml2Authentication extends Saml2Authentication  {

    private final String name;

    public NamedSaml2Authentication(String name, SamlUserDetails principal, String saml2Response,
        Collection<? extends GrantedAuthority> authorities) {
        super(principal, saml2Response, authorities);
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }
}
