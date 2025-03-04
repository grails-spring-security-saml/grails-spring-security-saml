## SAML 2.0 Plugin for Grails 4, 5 and 6

This plugin provides SAML 2.0 support for Grails 4, 5 and 6 applications. It was originally built from the Plugin that supported Grails 2 applications and was rewritten entirely for Grails 5. It enables SAML configuration directly from your application.yml or application.groovy without having to manually configure the Spring SAML Plugin and Grails Spring Security Plugin

### Plugin Compatibility with Grails
* Grails 3.0.x - Use Version 3.0.x of the plugin
* Grails 3.1.x - Use Version 3.1.x of the plugin
* Grails 3.3.x - Use Version 3.3.x of the plugin
* Grails 4.0.x - Use Version 4.0.2 of the plugin
* Grails 5.1.x - Use Version 5.1.0 of the plugin
* Grails 6.x.x - Use Version 6.0.9 of the plugin

### Installation
Grails 4:

```gradle
compile 'org.grails.plugins:spring-security-saml:<version>'
```

Grails 5 and 6:

```gradle
implementation 'io.github.grails-spring-security-saml:spring-security-saml:<version>'
```

NOTE: you may have to add the following repositories (Grails 4 or 5)

```
repositories {
    maven { url "http://central.maven.org/maven2/"}
    maven { url "https://build.shibboleth.net/nexus/content/repositories/releases"}
    maven { url "https://build.shibboleth.net/nexus/content/groups/public/"}
    maven { url "https://code.lds.org/nexus/content/groups/main-repo"}
    maven { url "http://repository.jboss.org/maven2/"}
}
```

alternatively the following repositories for Grails 6

```
repositories {
    maven { url "https://repo.maven.apache.org/maven2"}
    maven { url "https://build.shibboleth.net/maven/releases/"}
}
```

plus

```
implementation 'org.springframework.security:spring-security-saml2-service-provider:5.8.15'
```

to prevent the downgrade of the spring-security-saml2-service-provider forced by the grails gradle plugins down to 5.7.x.

See the [documentation page](https://jeffwils.github.io/grails-spring-security-saml/) and index.md (for Grails 5 and 6) for more information.
