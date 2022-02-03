package io.security.basicsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
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

    /* 인증, 인가에 관련한 설정을 할 수 있다. */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //인가
        http
                .authorizeRequests()
                .anyRequest().authenticated();

        //인증
        http
                .formLogin()
                //.loginPage("/loginPage")                // 사용자 정의 로그인 페이지
                .defaultSuccessUrl("/home")				// 로그인 성공 후 이동 페이지
                .failureUrl("/login")	                // 로그인 실패 후 이동 페이지
                .usernameParameter("userId")			// 아이디 파라미터명 설정
                .passwordParameter("passwd")			// 패스워드 파라미터명 설정
                .loginProcessingUrl("/login_proc")		// 로그인 Form Action Url
                .successHandler(new AuthenticationSuccessHandler() { // 로그인 성공 후 핸들러
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        //authentication : 인증한 결과를 받는다.
                        System.out.println("authentication : " + authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() { // 로그인 실패 후 핸들러
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception : " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                .permitAll(); // loginPage로 요청이 올 경우엔 인증없이 접근가능

        http.logout()                           // 로그아웃 처리
                .logoutUrl("/logout")           // 로그아웃 처리 URL
	            //.logoutSuccessUrl("/login")	// 로그아웃 성공 후 이동페이지
                .deleteCookies("remember-me")	// 로그아웃 후 쿠키 삭제
                .addLogoutHandler(new LogoutHandler() { // 로그아웃 핸들러
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();//세션 무효화
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() { 	// 로그아웃 성공 후 핸들러
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                });


    }


}
