package org.grails.plugin.springsecurity.saml;

import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken;

public class SamlResponseAuthenticationConverter extends Converter<ResponseToken, ? extends AbstractAuthenticationToken> {

    SpringSamlUserDetailsService userDetailsService

    AbstractAuthenticationToken convert(ResponseToken responseToken) {
        Saml2Authentication authentication = OpenSaml4AuthenticationProvider
                .createDefaultResponseAuthenticationConverter()
                .convert(responseToken);
        Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal)authentication.principal;
        UserDetails userDetails = userDetailsService.loadUserBySAML(principal);
        def customAuthentication = new Saml2Authentication(authentication.principal, authentication.saml2Response, getEntitlements(userDetails));
        customAuthentication.setDetails(userDetails)
        return customAuthentication
    }

    public Collection<? extends GrantedAuthority> getEntitlements(Object userDetail)
    {
        //logger.info("****** object is instance of UserDetails :"+ (userDetail instanceof UserDetails));

        if (userDetail instanceof UserDetails)
        {
            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.addAll(((UserDetails) userDetail).getAuthorities());
            return authorities;
        }
        else if(userDetail instanceof UsernamePasswordAuthenticationToken)
        {
            List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
            authorities.addAll(((UsernamePasswordAuthenticationToken) userDetail).getAuthorities());
            return authorities;

        } else {
            return Collections.emptyList();
        }
    }
}
