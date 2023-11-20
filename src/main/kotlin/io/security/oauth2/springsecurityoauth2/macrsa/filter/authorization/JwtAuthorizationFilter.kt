package io.security.oauth2.springsecurityoauth2.macrsa.filter.authorization

import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jwt.SignedJWT
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.web.filter.OncePerRequestFilter
import java.util.*
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

abstract class JwtAuthorizationFilter(
    private val jwsVerifier: JWSVerifier?
): OncePerRequestFilter() {
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        if(tokenResolve(request)) {
            filterChain.doFilter(request, response)
            return
        }

        val token = getToken(request)

        val signedJWT = SignedJWT.parse(token)
        val verify = signedJWT.verify(jwsVerifier)

        if(verify) {
            val jwtClaimSet = signedJWT.jwtClaimsSet
            val username = jwtClaimSet.getClaim("username").toString()
            val authority = jwtClaimSet.getClaim("authority") as MutableList<*>

            val user = User.withUsername(username)
                .password(UUID.randomUUID().toString())
                .authorities(authority[0] as String)
                .build()

            val authentication = UsernamePasswordAuthenticationToken(user, null, user.authorities)
            SecurityContextHolder.getContext().authentication = authentication
        }

        filterChain.doFilter(request, response)
    }

    fun tokenResolve(request: HttpServletRequest): Boolean {
        val header = request.getHeader("Authorization")
        return header == null || !header.startsWith("Bearer ")
    }

    fun getToken(request: HttpServletRequest): String {
        return request.getHeader("Authorization").replace("Bearer ", "")
    }
}