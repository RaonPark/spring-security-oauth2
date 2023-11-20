package io.security.oauth2.springsecurityoauth2.macrsa.config

import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.jwk.RSAKey
import io.security.oauth2.springsecurityoauth2.macrsa.filter.authentication.JwtAuthenticationFilter
import io.security.oauth2.springsecurityoauth2.macrsa.filter.authorization.JwtAuthorizationMacFilter
import io.security.oauth2.springsecurityoauth2.macrsa.filter.authorization.JwtAuthorizationRsaFilter
import io.security.oauth2.springsecurityoauth2.macrsa.filter.authorization.JwtAuthorizationRsaPublicKeyFilter
import io.security.oauth2.springsecurityoauth2.macrsa.signature.MacSigner
import io.security.oauth2.springsecurityoauth2.macrsa.signature.RsaPublicKeySecuritySigner
import io.security.oauth2.springsecurityoauth2.macrsa.signature.RsaSigner
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.config.web.servlet.invoke
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.DelegatingPasswordEncoder
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import javax.servlet.Filter

@Configuration
class OAuth2ResourceServerConfig @Autowired constructor(
    private val properties: OAuth2ResourceServerProperties,
    private val octetSequenceKey: OctetSequenceKey,
    private val macSigner: MacSigner,
) {
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            csrf {
                disable()
            }
            sessionManagement {
                SessionCreationPolicy.STATELESS
            }
            authorizeRequests {
                authorize("/", permitAll)
                authorize(anyRequest, authenticated)
            }
            userDetailsService()
            oauth2ResourceServer {
                jwt {

                }
            }
            // addFilterBefore<UsernamePasswordAuthenticationFilter>(jwtAuthenticationFilter(macSigner, octetSequenceKey))
//            addFilterBefore<UsernamePasswordAuthenticationFilter>(jwtAuthenticationFilter(null, null))
            // addFilterBefore<UsernamePasswordAuthenticationFilter>(JwtAuthorizationMacFilter(octetSequenceKey))
            // addFilterBefore<UsernamePasswordAuthenticationFilter>(jwtAuthorizationRsaFilter(null))
//            addFilterBefore<UsernamePasswordAuthenticationFilter>(jwtAuthorizationRsaPublicKeyFilter(null))
        }

        return http.build()
    }

//    @Bean
//    fun jwtAuthorizationRsaFilter(rsaKey: RSAKey?): JwtAuthorizationRsaFilter {
//        return JwtAuthorizationRsaFilter(RSASSAVerifier(rsaKey!!.toRSAPublicKey()))
//    }

    @Bean
    fun jwtAuthorizationRsaPublicKeyFilter(jwtDecoder: JwtDecoder?): JwtAuthorizationRsaPublicKeyFilter {
        return JwtAuthorizationRsaPublicKeyFilter(jwtDecoder)
    }

    @Bean
    fun authenticationManager(authenticationConfiguration: AuthenticationConfiguration?): AuthenticationManager {
        return authenticationConfiguration!!.authenticationManager
    }

    @Bean
    fun jwtAuthenticationFilter(rsaSigner: RsaPublicKeySecuritySigner?, rsaKey: RSAKey?): JwtAuthenticationFilter {
        val jwtAuthenticationFilter = JwtAuthenticationFilter(rsaSigner!!, rsaKey!!)
        jwtAuthenticationFilter.setAuthenticationManager(authenticationManager(null))
        return jwtAuthenticationFilter
    }

//    @Bean
//    fun jwtDecoder(): JwtDecoder {
//        return JwtDecoders.fromIssuerLocation(properties.jwt.issuerUri)
//    }

//    @Bean
//    fun jwtDecoder2(): JwtDecoder {
//        return NimbusJwtDecoder.withJwkSetUri(properties.jwt.jwkSetUri)
//            .jwsAlgorithms { SignatureAlgorithm.RS512 }.build()
//    }

    @Bean
    fun userDetailsService(): UserDetailsService {
        val user = User.withUsername("user").password("1234").authorities("ROLE_USER").build()
        return InMemoryUserDetailsManager(user)
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return NoOpPasswordEncoder.getInstance()
    }
}