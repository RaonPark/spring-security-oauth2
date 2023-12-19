package io.security.oauth2.springsecurityoauth2

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.web.servlet.invoke
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.client.RestTemplate

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
class OAuth2ResourceServer {
    @Bean
    fun securityFilterChain1(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeRequests {
                authorize("/", permitAll)
                authorize(anyRequest, authenticated)
            }
            oauth2Login {
                defaultSuccessUrl("/", true)
            }
        }

        return http.build()
    }

    @Bean
    fun restTemplate(): RestTemplate {
        return RestTemplate()
    }
}