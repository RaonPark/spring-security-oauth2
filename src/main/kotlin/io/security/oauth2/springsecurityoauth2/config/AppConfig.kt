package io.security.oauth2.springsecurityoauth2.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository

@Configuration
class AppConfig {
    @Bean
    fun oAuth2AuthorizedClientManager(clientRegistrationRepository: ClientRegistrationRepository,
                                      oAuth2AuthorizedClientRepository: OAuth2AuthorizedClientRepository): OAuth2AuthorizedClientManager {
        val oAuth2AuthorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
            .authorizationCode()
            .password()
            .clientCredentials()
            .refreshToken()
            .build()

        val defaultOAuth2AuthorizedClientManager = DefaultOAuth2AuthorizedClientManager(clientRegistrationRepository,
            oAuth2AuthorizedClientRepository)
        defaultOAuth2AuthorizedClientManager.setAuthorizedClientProvider(oAuth2AuthorizedClientProvider)

        return defaultOAuth2AuthorizedClientManager
    }
}