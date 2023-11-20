package io.security.oauth2.springsecurityoauth2.macrsa.signature

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.springframework.security.core.userdetails.UserDetails
import java.util.*

abstract class SecuritySigner {
    protected fun getJwtTokenInternal(jwsSigner: JWSSigner, userDetails: UserDetails, jwk: JWK): String {
        val header = JWSHeader.Builder(jwk.algorithm as JWSAlgorithm).keyID(jwk.keyID).build()
        val authorities = userDetails.authorities.map {
            auth -> auth.authority
        }.toList()
        val jwtClaimsSet = JWTClaimsSet.Builder()
            .subject("user")
            .issuer("http://localhost:8080")
            .claim("username", userDetails.username)
            .claim("authority", authorities)
            .expirationTime(Date(Date().time + 60 * 1000 * 5))
            .build()

        val signedJWT = SignedJWT(header, jwtClaimsSet)
        signedJWT.sign(jwsSigner)
        return signedJWT.serialize()
    }

    abstract fun getToken(userDetails: UserDetails, jwk: JWK): String
}