package io.security.oauth2.springsecurityoauth2.jcajce

import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher

class RSAGen {
    companion object {
        fun genKeyPair(): KeyPair {
            val gen = KeyPairGenerator.getInstance("RSA")
            gen.initialize(1024, SecureRandom())
            return gen.genKeyPair()
        }

        fun encrypt(plainText: String, publicKey: PublicKey): String {
            val cipher = Cipher.getInstance("RSA")
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)

            val bytePlain = cipher.doFinal(plainText.toByteArray())
            return Base64.getEncoder().encodeToString(bytePlain)
        }

        fun decrypt(encrypted: String, privateKey: PrivateKey): String {
            val cipher = Cipher.getInstance("RSA")
            val byteEncrypted = Base64.getDecoder().decode(encrypted)

            cipher.init(Cipher.DECRYPT_MODE, privateKey)
            val bytePlain = cipher.doFinal(byteEncrypted)
            return String(bytePlain, StandardCharsets.UTF_8)
        }

        fun getPublicKeyFromKeySpec(base64PublicKey: String): PublicKey {
            val decodedBase64PubKey = Base64.getDecoder().decode(base64PublicKey)

            return KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(decodedBase64PubKey))
        }

        fun getPrivateKeyFromKeySpec(base64PrivateKey: String): PrivateKey {
            val decodedBase64PrivateKey = Base64.getDecoder().decode(base64PrivateKey)

            return KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(decodedBase64PrivateKey))
        }
    }
}