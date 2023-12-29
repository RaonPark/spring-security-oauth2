package io.security.oauth2.springsecurityoauth2

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.ClientRegistrations
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository

@Configuration
class OAuth2ClientConfig {
    @Bean
    fun clientRegistrationRepository(): ClientRegistrationRepository {
        return InMemoryClientRegistrationRepository(keyCloakClientRegistration())
    }

    private fun keyCloakClientRegistration(): ClientRegistration {
        val clientRegistration = ClientRegistrations
            .fromIssuerLocation("http://localhost:8081/realms/oauth2")
            .registrationId("keycloak")
            .clientId("oauth2-client-app")
            .redirectUri("http://localhost:8080/login/oauth2/code/keycloak")
            .build()

        return clientRegistration
    }
}