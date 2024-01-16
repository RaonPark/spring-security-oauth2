package io.security.oauth2.springsecurityoauth2

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.web.servlet.invoke
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler

/**
 * OAuth2ClientConfigurer
 * init 과 configure 를 한다.
 * init
 * OAuth2AuthorizationCodeAuthenticationProvider authorizationCodeAuthenticationProvider = new OAuth2AuthorizationCodeAuthenticationProvider(
 * 					getAccessTokenResponseClient());
 * 			builder.authenticationProvider(postProcess(authorizationCodeAuthenticationProvider));
 *
 * configure
 * OAuth2AuthorizationRequestRedirectFilter authorizationRequestRedirectFilter = createAuthorizationRequestRedirectFilter(
 * 					builder);
 * 			builder.addFilter(postProcess(authorizationRequestRedirectFilter));
 * 			OAuth2AuthorizationCodeGrantFilter authorizationCodeGrantFilter = createAuthorizationCodeGrantFilter(
 * 					builder);
 * 			builder.addFilter(postProcess(authorizationCodeGrantFilter));
 *
 * OAuth2AuthorizationCodeGrantFilter 는 인가까지만 하지만 최종적으로는 최종 사용자의 인증처리는 하지 않는다.
 *
 */

@EnableWebSecurity
class OAuth2ClientConfig @Autowired constructor(
    private val clientRegistrationRepository: ClientRegistrationRepository
) {
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeRequests {
                authorize("/home", permitAll)
                authorize(anyRequest, authenticated)
            }
            oauth2Login {
                authorizationEndpoint {
                    authorizationRequestResolver = customOAuth2AuthorizationRequestResolver()
                }
            }
            logout {
                logoutSuccessUrl = "/home"
            }
        }

        return http.build()
    }

    private fun customOAuth2AuthorizationRequestResolver(): OAuth2AuthorizationRequestResolver {
        return CustomOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorization")
    }
}