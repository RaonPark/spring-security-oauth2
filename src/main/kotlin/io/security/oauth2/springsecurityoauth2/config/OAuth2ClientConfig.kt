package io.security.oauth2.springsecurityoauth2.config

import io.security.oauth2.springsecurityoauth2.service.CustomOAuth2UserService
import io.security.oauth2.springsecurityoauth2.service.CustomOidcUserService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer
import org.springframework.security.config.web.servlet.invoke
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper
import org.springframework.security.web.SecurityFilterChain

@EnableWebSecurity
class OAuth2ClientConfig (
    private val customOAuth2UserService: CustomOAuth2UserService,
    private val customOidcUserService: CustomOidcUserService
) {

    @Bean
    fun webSecurityCustomizer(): WebSecurityCustomizer {
        return WebSecurityCustomizer {
            it.ignoring().antMatchers(
                "/static/js/**", "/static/images/**", "/static/css/**", "/static/scss/**", "/static/icomoon/**"
            )
        }
    }

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeRequests {
                authorize("/", permitAll)
                authorize("/api/user", hasAnyRole("SCOPE_profile", "SCOPE_email"), permitAll)
                authorize("/api/oidc", hasAnyRole("SCOPE_openid"), permitAll)
                authorize(anyRequest, authenticated)
            }

            oauth2Login {
                userInfoEndpoint {
                    userService = customOAuth2UserService
                    oidcUserService = customOidcUserService
                }
            }

            logout {
                logoutSuccessUrl = "/"
            }
        }

        return http.build()
    }

    @Bean
    fun customAuthorityMapper(): GrantedAuthoritiesMapper {
        return CustomAuthorityMapper()
    }

}