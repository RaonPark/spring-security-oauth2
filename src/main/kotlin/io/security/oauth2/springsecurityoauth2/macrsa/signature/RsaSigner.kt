package io.security.oauth2.springsecurityoauth2.macrsa.signature

import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import org.springframework.security.core.userdetails.UserDetails

class RsaSigner: SecuritySigner() {
    override fun getToken(userDetails: UserDetails, jwk: JWK): String {
        val jwsSigner = RSASSASigner(jwk as RSAKey)
        return super.getJwtTokenInternal(jwsSigner, userDetails, jwk)
    }
}