package io.security.oauth2.springsecurityoauth2.macrsa.filter.authorization

import com.nimbusds.jose.JWSVerifier
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.stereotype.Component
import java.util.*
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class JwtAuthorizationRsaPublicKeyFilter @Autowired constructor(
    private val jwtDecoder: JwtDecoder?
):
    JwtAuthorizationFilter(null) {

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        if(tokenResolve(request)) {
            filterChain.doFilter(request, response)
            return
        }

        if(jwtDecoder != null) {
            val jwt = jwtDecoder.decode(getToken(request))

            val username = jwt.getClaimAsString("username")
            val authority = jwt.getClaimAsStringList("authority")

            val user = User.withUsername(username)
                .password(UUID.randomUUID().toString())
                .authorities(authority[0] as String)
                .build()

            val authentication = UsernamePasswordAuthenticationToken(user, null, user.authorities)
            SecurityContextHolder.getContext().authentication = authentication
        }
    }
}