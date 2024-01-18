package io.security.oauth2.springsecurityoauth2.config

import io.security.oauth2.springsecurityoauth2.filter.CustomOAuth2AuthenticationFilter
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.web.servlet.invoke
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

@EnableWebSecurity
class OAuth2ClientConfig @Autowired constructor(
    private val oAuth2AuthorizedClientManager: DefaultOAuth2AuthorizedClientManager,
    private val oAuth2AuthorizedClientRepository: OAuth2AuthorizedClientRepository
){

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeRequests {
                authorize("/", permitAll)
                authorize("/oauth2Login", permitAll)
                authorize("/client", permitAll)
                authorize(anyRequest, authenticated)
            }

            oauth2Client {
                Customizer.withDefaults<Any>()
            }

            logout {
                logoutSuccessUrl = "/home"
            }

            addFilterBefore<UsernamePasswordAuthenticationFilter>(customOAuth2AuthenticationFilter())
        }

        return http.build()
    }

    private fun customOAuth2AuthenticationFilter(): CustomOAuth2AuthenticationFilter {
        val oAuth2AuthenticationFilter = CustomOAuth2AuthenticationFilter(oAuth2AuthorizedClientManager, oAuth2AuthorizedClientRepository)

        oAuth2AuthenticationFilter.setAuthenticationSuccessHandler {
                _, response, _ -> response.sendRedirect("/home")
        }

        return oAuth2AuthenticationFilter
    }

}