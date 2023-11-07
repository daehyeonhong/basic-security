package io.security.basicsecurity.configuration;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final UserDetailsService userDetailsService;

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

        http
                .rememberMe(
                        httpSecurityRememberMeConfigurer ->
                                httpSecurityRememberMeConfigurer
                                        .rememberMeParameter("remember")
                                        .tokenValiditySeconds(3_600)
                                        .userDetailsService(this.userDetailsService)
                );

        http
                .sessionManagement(
                        httpSecuritySessionManagementConfigurer ->
                        {
                            httpSecuritySessionManagementConfigurer
                                    .invalidSessionUrl("/invalid")
                                    .sessionFixation().changeSessionId()
                                    .maximumSessions(1)
                                    .maxSessionsPreventsLogin(true)
                                    .expiredUrl("/expired");
                        }
                );

        return http.build();
    }
}
