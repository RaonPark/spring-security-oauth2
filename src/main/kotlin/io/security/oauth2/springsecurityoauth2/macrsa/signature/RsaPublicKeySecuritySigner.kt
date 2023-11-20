package io.security.oauth2.springsecurityoauth2.macrsa.signature

import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWK
import org.springframework.security.core.userdetails.UserDetails
import java.security.PrivateKey

class RsaPublicKeySecuritySigner: SecuritySigner() {

    private lateinit var privateKey: PrivateKey

    override fun getToken(userDetails: UserDetails, jwk: JWK): String {
        val jwsSigner = RSASSASigner(privateKey)
        return super.getJwtTokenInternal(jwsSigner, userDetails, jwk)
    }

    fun setPrivateKey(privateKey: PrivateKey) {
        this.privateKey = privateKey
    }
}