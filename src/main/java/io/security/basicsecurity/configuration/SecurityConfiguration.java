package io.security.basicsecurity.configuration;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@Configuration
public class SecurityConfiguration {
    @Bean
    public SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> authorizationManagerRequestMatcherRegistry.anyRequest().authenticated());

        http
                .formLogin(
                        httpSecurityFormLoginConfigurer ->
                                httpSecurityFormLoginConfigurer
                                        .defaultSuccessUrl("/")
                                        .failureUrl("/login")
                                        .usernameParameter("userId")
                                        .passwordParameter("passwd")
                                        .loginProcessingUrl("/login_proc")
                                        .successHandler((request, response, authentication) -> {
                                            log.info("authentication: {}", authentication.getName());
                                            response.sendRedirect("/");
                                        })
                                        .failureHandler(
                                                (request, response, exception) -> {
                                                    log.error("exception: {}", exception.getMessage());
                                                    response.sendRedirect("/login");
                                                }
                                        )
                                        .permitAll()
                );

        http
                .logout(
                        httpSecurityLogoutConfigurer ->
                                httpSecurityLogoutConfigurer
                                        .logoutUrl("/logout")
                                        .logoutSuccessUrl("/login")
                                        .addLogoutHandler((request, response, authentication) -> request.getSession().invalidate())
                                        .logoutSuccessHandler((request, response, authentication) -> response.sendRedirect("/login"))
                                        .deleteCookies("remember-me")
                                        .permitAll()
                );

        return http.build();
    }
}
