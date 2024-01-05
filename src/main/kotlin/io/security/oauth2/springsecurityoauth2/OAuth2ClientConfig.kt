package io.security.oauth2.springsecurityoauth2

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.web.servlet.invoke
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler

@EnableWebSecurity
class OAuth2ClientConfig @Autowired constructor(
    private val clientRegistrationRepository: ClientRegistrationRepository
) {
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeRequests {
//                authorize("/loginPage", permitAll)
                authorize(anyRequest, authenticated)
            }
            // oauth2Login { loginPage = "/loginPage" }
            oauth2Login { Customizer.withDefaults<Any>() }
            logout {
                logoutSuccessHandler = oidcLogoutSuccessHandler()
                invalidateHttpSession = true
                clearAuthentication = true
                deleteCookies("JSESSIONID")
            }
        }

        return http.build()
    }

    private fun oidcLogoutSuccessHandler(): LogoutSuccessHandler {
        val successHandler = OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository)
        successHandler.setPostLogoutRedirectUri("http://localhost:8080/login")

        return successHandler
    }
}