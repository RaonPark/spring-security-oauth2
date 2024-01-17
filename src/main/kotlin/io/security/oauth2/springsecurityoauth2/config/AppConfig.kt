package io.security.oauth2.springsecurityoauth2.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.util.StringUtils
import javax.servlet.http.HttpServletRequest

@Configuration
class AppConfig {
    @Bean
    fun oAuth2AuthorizedClientManager(clientRegistrationRepository: ClientRegistrationRepository,
                                      oAuth2AuthorizedClientRepository: OAuth2AuthorizedClientRepository): DefaultOAuth2AuthorizedClientManager {
        val oAuth2AuthorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
            .authorizationCode()
            .password()
            .clientCredentials()
            .refreshToken()
            .build()

        val defaultOAuth2AuthorizedClientManager = DefaultOAuth2AuthorizedClientManager(clientRegistrationRepository,
            oAuth2AuthorizedClientRepository)
        defaultOAuth2AuthorizedClientManager.setAuthorizedClientProvider(oAuth2AuthorizedClientProvider)
        defaultOAuth2AuthorizedClientManager.setContextAttributesMapper { contextAttributesMapper(it) }

        return defaultOAuth2AuthorizedClientManager
    }

    private fun contextAttributesMapper(oAuth2AuthorizeRequest: OAuth2AuthorizeRequest): MutableMap<String, Any> {
        val contextAttributes = mutableMapOf<String, Any>()
        val request = oAuth2AuthorizeRequest.attributes[HttpServletRequest::class.java.name] as HttpServletRequest
        val username= request.getParameter(OAuth2ParameterNames.USERNAME)
        val password = request.getParameter(OAuth2ParameterNames.PASSWORD)

        if(StringUtils.hasText(username) && StringUtils.hasText(password)) {
            contextAttributes[OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME] = username
            contextAttributes[OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME] = password
        }

        return contextAttributes
    }
}