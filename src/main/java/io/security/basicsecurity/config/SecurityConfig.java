package io.security.basicsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity // 웹보안 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    /* 인증, 인가에 관련한 설정을 할 수 있다. */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //인가
        http
                .authorizeRequests()
                .anyRequest().authenticated();

        //인증
        // 로그인 성공 후 핸들러
        // 로그인 실패 후 핸들러
        http
                .formLogin()
                //.loginPage("/loginPage")                // 사용자 정의 로그인 페이지
                .defaultSuccessUrl("/home")				// 로그인 성공 후 이동 페이지
                .failureUrl("/login")	                // 로그인 실패 후 이동 페이지
                .usernameParameter("userId")			// 아이디 파라미터명 설정
                .passwordParameter("passwd")			// 패스워드 파라미터명 설정
                .loginProcessingUrl("/login_proc")		// 로그인 Form Action Url
                .successHandler((request, response, authentication) -> {
                    //authentication : 인증한 결과를 받는다.
                    System.out.println("###############################################");
                    System.out.println("Successed Login");
                    System.out.println("Name : " + authentication.getName());
                    System.out.println("Principal : " + authentication.getPrincipal());
                    System.out.println("Details : " + authentication.getDetails());
                    System.out.println("Authentication : " + SecurityContextHolder.getContext().getAuthentication());
                    System.out.println("###############################################");
                    response.sendRedirect("/");
                })
                .failureHandler((request, response, exception) -> {
                    System.out.println("exception : " + exception.getMessage());
                    response.sendRedirect("/login");
                })
                .permitAll(); // loginPage로 요청이 올 경우엔 인증없이 접근가능

        // 로그아웃 핸들러
        // 로그아웃 성공 후 핸들러
        http.logout()                           // 로그아웃 처리
                .logoutUrl("/logout")           // 로그아웃 처리 URL
	            //.logoutSuccessUrl("/login")	// 로그아웃 성공 후 이동페이지
                .deleteCookies("remember-me")	// 로그아웃 후 쿠키 삭제
                .addLogoutHandler((request, response, authentication) -> {
                    HttpSession session = request.getSession();
                    session.invalidate();//세션 무효화
                })
                .logoutSuccessHandler((request, response, authentication) -> response.sendRedirect("/login"));

        // 1.Security Context에 인증 정보가 없을 경우(null)
        // 2.RemeberMe 쿠키를 가지고 있는 경우
        // RemeberMeAuthenticationFilter가 인증을 시도한다.
        http.rememberMe()
                .rememberMeParameter("remember")
                .tokenValiditySeconds(60) // 디폴트는 14일
                //.alwaysRemember(true) //리멤버 미 기능이 활성화되지 않아도 항상 실행
                .userDetailsService(userDetailsService); // 사용자 계정을 조회할 때 사용

        // 동시 세션 제어
        http.sessionManagement()
                .maximumSessions(1) // -1 무제한 로그인 세션 허용
                .maxSessionsPreventsLogin(true) // true : 동시 로그인 차단, false : 기존 세션 만료(default)
                .expiredUrl("/expired");

    }


}
