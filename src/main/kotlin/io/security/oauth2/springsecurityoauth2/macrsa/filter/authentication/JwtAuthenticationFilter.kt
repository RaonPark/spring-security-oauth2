package io.security.oauth2.springsecurityoauth2.macrsa.filter.authentication

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.nimbusds.jose.jwk.JWK
import io.security.oauth2.springsecurityoauth2.macrsa.dto.LoginDto
import io.security.oauth2.springsecurityoauth2.macrsa.signature.MacSigner
import io.security.oauth2.springsecurityoauth2.macrsa.signature.SecuritySigner
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class JwtAuthenticationFilter(
    private val securitySigner: SecuritySigner,
    private val jwk: JWK
) : UsernamePasswordAuthenticationFilter() {

    override fun attemptAuthentication(request: HttpServletRequest?, response: HttpServletResponse?): Authentication {
        val objectMapper = ObjectMapper().registerKotlinModule()
        val loginDto: LoginDto = objectMapper.readValue(request!!.inputStream, LoginDto::class.java)

        val authenticationToken = UsernamePasswordAuthenticationToken(loginDto.username, loginDto.password)

        return authenticationManager.authenticate(authenticationToken)
    }

    override fun successfulAuthentication(
        request: HttpServletRequest,
        response: HttpServletResponse,
        chain: FilterChain?,
        authResult: Authentication?
    ) {
        SecurityContextHolder.getContext().authentication = authResult
        val user = authResult!!.principal as User

        val jwtToken = securitySigner.getToken(user, jwk)
        response.addHeader("Authorization", "Bearer $jwtToken")
    }
}