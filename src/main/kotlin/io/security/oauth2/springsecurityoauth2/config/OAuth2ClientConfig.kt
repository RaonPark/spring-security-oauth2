package io.security.oauth2.springsecurityoauth2.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.web.servlet.invoke
import org.springframework.security.web.SecurityFilterChain

/**
 * OAuth2AuthorizedClient 는 인가받은 클라이언트를 의미하는 클래스다.
 * 최종 사용자가 클라이언트에게 리소스를 접근할 수 있는 권한을 부여하면, 클라이언트를 인가된 클라이언트로 간주한다.
 * OAuth2AuthorizedClient는 AccessToken과 RefreshToken을 ClientRegistration과 권한을 부여한 최종 사용자인 Principal과 함께 묶어준다.
 * AccessToken으로 리소스 서버의 자원에 접근할 수 있고, 인가 서버와의 통신으로 토큰을 검증할 수 있다.
 * ClientRegistration과 AccessToken을 사용하여 UserInfo 엔드포인트로 요청할 수 있다.
 *
 * OAuth2AuthorizedClientRepository는 다른 웹 요청이 와도 동일한 OAuth2AuthorizedClient를 유지하는 역할을 담당한다.
 * OAuth2AuthorizedClientService에게 OAuth2AuthorizedClient의 저장, 조회, 삭제, 처리를 위임한다.
 *
 * OAuth2AuthorizedClientService는 어플리케이션 레벨에서 OAuth2AuthorizedClient를 관리하는 일을 한다.
 *
 * RestTemplate을 사용하여 OAuth2AuthorizedClient가 ResourceServer와 통신할 수 있다.
 *
 * OAuth2AuthorizationCodeGrantFilter 권한 부여 요청을 지원하는 필터
 * 인가서버로부터 리다이렉트 되면서 전달된 code를 인가서버의 AccessToken으로 교환한다.
 * 인가까지만 하며 최종 인증 처리는 하지 않는다.
 * 요청 파라미터에 code와 state 값이 존재하는지 확인
 * OAuth2AuthorizationRequest 객체가 존재하는지 확인
 * -> 클라이언트가 인가를 요청할 때 code, state등이 전달되며, OAuth2AuthorizationRequest 역시도 전달된다. 따라서 이 값이 이 필터 이전에 존재하게 된다.
 *
 */

@EnableWebSecurity
class OAuth2ClientConfig {
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeRequests {
                authorize("/", permitAll)
                authorize("/oauth2Login", permitAll)
                authorize("/client", permitAll)
                authorize(anyRequest, authenticated)
            }

            oauth2Client {
                Customizer.withDefaults<Any>()
            }

            logout {
                logoutSuccessUrl = "/home"
            }
        }

        return http.build()
    }

}