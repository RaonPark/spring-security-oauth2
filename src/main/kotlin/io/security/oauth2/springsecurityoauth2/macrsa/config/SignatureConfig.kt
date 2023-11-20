package io.security.oauth2.springsecurityoauth2.macrsa.config

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import io.security.oauth2.springsecurityoauth2.macrsa.signature.MacSigner
import io.security.oauth2.springsecurityoauth2.macrsa.signature.RsaPublicKeySecuritySigner
import io.security.oauth2.springsecurityoauth2.macrsa.signature.RsaSigner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class SignatureConfig {
    @Bean
    fun macSecuritySigner(): MacSigner {
        return MacSigner()
    }

    @Bean
    fun octetSequenceKey(): OctetSequenceKey {
        val octetSequenceKey = OctetSequenceKeyGenerator(256)
            .keyID("macKey")
            .algorithm(JWSAlgorithm.HS256)
            .generate()

        return octetSequenceKey
    }

    @Bean
    fun rsaSecuritySigner(): RsaSigner {
        return RsaSigner()
    }

    @Bean
    fun rsaKey(): RSAKey {
        return RSAKeyGenerator(2048)
            .keyID("rsaKey")
            .algorithm(JWSAlgorithm.RS256)
            .generate()
    }

    @Bean
    fun rsaPublicKeySecuritySigner(): RsaPublicKeySecuritySigner {
        return RsaPublicKeySecuritySigner()
    }
}