package io.security.oauth2.springsecurityoauth2

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.web.servlet.invoke
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.web.SecurityFilterChain

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
class OAuth2ResourceServer {
    @Bean
    fun securityFilterChain1(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeRequests {
                authorize("/photos/1", hasAuthority("ROLE_photo"))
                authorize("/photos/3", hasAuthority("ROLE_default-roles-oauth2"))
                authorize(anyRequest, authenticated)
            }
            oauth2ResourceServer {
                jwt {
                    jwtAuthenticationConverter = jwtAuthenticationConverter()
                }
            }
        }

        return http.build()
    }

    @Bean
    fun securityFilterChain2(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeRequests {
                authorize("/photos/2", permitAll)
                authorize(anyRequest, authenticated)
            }
            oauth2ResourceServer {
                jwt {

                }
            }
        }

        return http.build()
    }

    private fun jwtAuthenticationConverter(): JwtAuthenticationConverter {
        val jwtAuthenticationConverter = JwtAuthenticationConverter()
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(CustomRoleConvert())
        return jwtAuthenticationConverter
    }
}