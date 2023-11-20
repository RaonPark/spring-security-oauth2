package io.security.oauth2.springsecurityoauth2.jwk

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKMatcher
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyOperation
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import javax.crypto.spec.SecretKeySpec

class JWKTest {
    companion object {
        fun jwk() {
            val rsaGenerator = KeyPairGenerator.getInstance("RSA")
            rsaGenerator.initialize(2048)

            val keyPair = rsaGenerator.genKeyPair()
            val publicKey = keyPair.public as RSAPublicKey
            val privateKey = keyPair.private as RSAPrivateKey

            val rsaKey1 = RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyID("rsa-kid1")
                .build()

            val rsaKey2 = RSAKeyGenerator(2048)
                .keyID("rsa-kid2")
                .keyUse(KeyUse.SIGNATURE)
                .keyOperations(hashSetOf(KeyOperation.SIGN))
                .algorithm(JWSAlgorithm.RS512)
                .generate()

            val secretKey = SecretKeySpec(
                Base64.getDecoder().decode("bCzY/M48bbkwBEWjmNSIEPfwApcvXOnkCxORBEbPr+4="), "AES")

            val octetSequenceKey1 = OctetSequenceKey.Builder(secretKey)
                .keyID("secret-kid1")
                .keyUse(KeyUse.SIGNATURE)
                .keyOperations(hashSetOf(KeyOperation.SIGN))
                .algorithm(JWSAlgorithm.HS256)
                .build()

            val octetSequenceKey2 = OctetSequenceKeyGenerator(256)
                .keyID("secret-kid2")
                .keyUse(KeyUse.SIGNATURE)
                .keyOperations(hashSetOf(KeyOperation.SIGN))
                .algorithm(JWSAlgorithm.HS384)
                .generate();

            // val kId = rsaKey1.keyID
            val kId = octetSequenceKey1.keyID
            val alg = octetSequenceKey1.algorithm as JWSAlgorithm
            val typ = KeyType.OCT

            jwkSet(kId, alg, typ, rsaKey1, rsaKey2, octetSequenceKey1, octetSequenceKey2)
        }

        private fun jwkSet(kId: String, alg: JWSAlgorithm, typ: KeyType, vararg jwk: JWK) {
            val jwkSet = JWKSet(jwk.toMutableList())
            val jwkSource = JWKSource<SecurityContext> { jwkSelector, context -> jwkSelector.select(jwkSet) }

            val jwkMatcher = JWKMatcher.Builder()
                .keyType(typ)
                .keyID(kId)
                .keyUses(KeyUse.SIGNATURE)
                .algorithm(alg)
                .build()

            val jwkSelector = JWKSelector(jwkMatcher)
            val jwks = jwkSource[jwkSelector, null]

            if(jwks.isNotEmpty()) {
                val jwk1 = jwks[0]

                val keyType = jwk1.keyType
                println { "keyType = $keyType" }

                val keyID = jwk1.keyID
                println { "keyID = $keyID" }

                val algorithm = jwk1.algorithm
                println { "algorithm = $algorithm" }
            }
        }
    }
}