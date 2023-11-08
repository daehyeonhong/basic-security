package io.security.basicsecurity.configuration;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final UserDetailsService userDetailsService;

    @Bean
    public static UserDetailsManager userDetailsManager() {
        final UserDetails user = User.builder()
                .username("user")
                .password("{noop}1111")
                .roles("USER")
                .build();

        final UserDetails sys = User.builder()
                .username("sys")
                .password("{noop}1111")
                .roles("SYS")
                .build();

        final UserDetails admin = User.builder()
                .username("admin")
                .password("{noop}1111")
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, sys, admin);
    }

    @Bean
    public SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry ->
                        authorizationManagerRequestMatcherRegistry
                                .requestMatchers("/login").permitAll()
                                .requestMatchers("/user").hasRole("USER")
                                .requestMatchers("/admin/pay").hasRole("ADMIN")
                                .requestMatchers("/admin/**").hasAnyRole("ADMIN", "SYS")
                                .anyRequest().authenticated()
                );

        http.csrf(AbstractHttpConfigurer::disable);

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
                                            final RequestCache requestCache = new HttpSessionRequestCache();
                                            final SavedRequest savedRequest = requestCache.getRequest(request, response);
                                            final String redirectUrl = savedRequest.getRedirectUrl();
                                            response.sendRedirect(redirectUrl);
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
                                httpSecuritySessionManagementConfigurer
                                        .invalidSessionUrl("/invalid")
                                        .sessionFixation().changeSessionId()
//                                        .maximumSessions(1)
//                                        .maxSessionsPreventsLogin(true)
//                                        .expiredUrl("/expired")
                );

        http
                .exceptionHandling(
                        httpSecurityExceptionHandlingConfigurer ->
                                httpSecurityExceptionHandlingConfigurer
//                                        .authenticationEntryPoint((request, response, authException) -> response.sendRedirect("/login"))
                                        .accessDeniedHandler((request, response, accessDeniedException) -> response.sendRedirect("/denied"))
                );

        return http.build();
    }
}
