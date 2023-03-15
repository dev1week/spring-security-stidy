package com.sp.fc.web.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity(debug = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {



    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(request->{
                    request
                            //메인 페이지 뚫어놓기
                            .antMatchers("/").permitAll()
                            .anyRequest().authenticated()
                            ;
                })
                .formLogin(
                        //로그인 페이지 뚫어놓기
                        login->login.loginPage("/login")
                                .permitAll()
                                //로그인 후 반환 페이지
                                //alwaysUse를 거짓 처리 해놓아야한다.
                                .defaultSuccessUrl("/", false)
                                //로그인 실패 후 반환 페이지
                                .failureUrl("/login-error")
                )
                //로그아웃 후 반환 페이지
                .logout(logout -> logout.logoutSuccessUrl("/"))
                .exceptionHandling(exception->exception.accessDeniedPage("/access-denied"));

    }

    @Bean
    RoleHierarchy roleHierarchy(){
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
        return roleHierarchy;
    }

    @Override
    public void configure(WebSecurity web) throws Exception{
        web.ignoring()
                .requestMatchers(
                        //정적 파일 뚫어놓기
                        PathRequest.toStaticResources().atCommonLocations()
                )
        ;
    }

    //임시 회원 등록
    //개발 단계에서만 사용하자
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser(
                        User.withDefaultPasswordEncoder()
                                .username("user1")
                                .password("1111")
                                .roles("USER")
                ).withUser(
                        User.withDefaultPasswordEncoder()
                                .username("admin")
                                .password("2222")
                                .roles("ADMIN")
                );

    }
}
