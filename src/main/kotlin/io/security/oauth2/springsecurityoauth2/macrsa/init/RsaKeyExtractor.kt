package io.security.oauth2.springsecurityoauth2.macrsa.init

import io.security.oauth2.springsecurityoauth2.macrsa.signature.RsaPublicKeySecuritySigner
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.stereotype.Component
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.OutputStreamWriter
import java.nio.charset.Charset
import java.security.KeyPair
import java.security.KeyStore
import java.security.PrivateKey
import java.util.Base64

@Component
class RsaKeyExtractor(
    private val rsaPublicKeySecuritySigner: RsaPublicKeySecuritySigner
): ApplicationRunner {

    override fun run(args: ApplicationArguments?) {
        val path = "/home/sumin/test/spring-security-oauth2/src/main/resources/certs/"
        val file = File(path + "publicKey.txt")

        val fis = FileInputStream(path + "apiKey.jks")
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
        keyStore.load(fis, "pass1234".toCharArray())

        val alias = "apiKey"
        val key = keyStore.getKey(alias, "pass1234".toCharArray())

        if(key is PrivateKey) {
            val certificate = keyStore.getCertificate(alias)
            val publicKey = certificate.publicKey
            val keyPair = KeyPair(publicKey, key)
            rsaPublicKeySecuritySigner.setPrivateKey(keyPair.private)

            if(!file.exists()) {
                var publicStr = Base64.getMimeEncoder().encodeToString(publicKey.encoded)
                publicStr = "-----BEGIN PUBLIC KEY-----\r\n$publicStr\r\n-----END PUBLIC KEY-----"

                val writer = OutputStreamWriter(FileOutputStream(file), Charset.defaultCharset())
                writer.write(publicStr)
                writer.close()
            }
        }

        fis.close()
    }
}