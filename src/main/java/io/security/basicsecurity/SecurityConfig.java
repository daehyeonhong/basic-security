package io.security.basicsecurity;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    @Bean
    @Order(SecurityProperties.BASIC_AUTH_ORDER)
    public SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();
        http
                .formLogin()
                .loginPage("/loginPage")
                .defaultSuccessUrl("/")
                .failureForwardUrl("/login")
                .usernameParameter("username")
                .passwordParameter("password")
                .loginProcessingUrl("/login_proc")
                .successHandler((request, response, authentication) -> {
                    log.info("authentication: {}", authentication.getName());
                    response.sendRedirect("/");
                }).failureHandler((request, response, exception) -> {
                    log.error("exception", exception);
                    response.sendRedirect("/login");
                })
                .permitAll()
        ;
        return http.build();
    }
}
