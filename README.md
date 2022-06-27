## SAML 2.0 Plugin for Grails 4 and 5

This plugin provides SAML 2.0 support for Grails 4 and 5 applications. It was originally built from the Plugin that supported Grails 2 applications and was rewritten entirely for Grails 5. It enables SAML configuration directly from your application.yml or application.groovy without having to manually configure the Spring SAML Plugin and Grails Spring Security Plugin

### Plugin Compatibility with Grails
* Grails 3.0.x - Use Version 3.0.x of the plugin
* Grails 3.1.x - Use Version 3.1.x of the plugin
* Grails 3.3.x - Use Version 3.3.x of the plugin
* Grails 4.0.x - Use Version 4.0.2 of the plugin
* Grails 5.1.x - Use Version 5.0.0-RC2 of the plugin

### Installation
Grails 4.0.0:

```gradle
compile 'org.grails.plugins:spring-security-saml:4.0.2'
```

Grails 5.0.0:

```gradle
implementation 'io.github.grails-spring-security-saml:spring-security-saml:5.0.0-RC2'
```


NOTE: you may have to add the following repositories

```
repositories {
    maven { url "http://central.maven.org/maven2/"}
    maven { url "https://build.shibboleth.net/nexus/content/repositories/releases"}
    maven { url "https://build.shibboleth.net/nexus/content/groups/public/"}
    maven { url "https://code.lds.org/nexus/content/groups/main-repo"}
    maven { url "http://repository.jboss.org/maven2/"}
}
```

See the [documentation page](https://jeffwils.github.io/grails-spring-security-saml/) for more information.
