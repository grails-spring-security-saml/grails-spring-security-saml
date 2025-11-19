package org.grails.plugin.springsecurity.saml

import grails.compiler.GrailsCompileStatic
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication

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
