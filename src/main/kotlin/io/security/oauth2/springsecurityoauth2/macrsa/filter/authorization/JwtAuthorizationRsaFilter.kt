package io.security.oauth2.springsecurityoauth2.macrsa.filter.authorization

import com.nimbusds.jose.JWSVerifier

class JwtAuthorizationRsaFilter(
    private val jwsVerifier: JWSVerifier
): JwtAuthorizationFilter(jwsVerifier) {

}