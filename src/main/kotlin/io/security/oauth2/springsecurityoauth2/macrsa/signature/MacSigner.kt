package io.security.oauth2.springsecurityoauth2.macrsa.signature

import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetSequenceKey
import org.springframework.security.core.userdetails.UserDetails

class MacSigner: SecuritySigner() {
    override fun getToken(userDetails: UserDetails, jwk: JWK): String {
        val jwsSigner = MACSigner((jwk as OctetSequenceKey).toSecretKey())
        return getJwtTokenInternal(jwsSigner, userDetails, jwk)
    }
}