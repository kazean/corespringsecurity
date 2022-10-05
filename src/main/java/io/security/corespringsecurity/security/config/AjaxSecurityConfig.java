package io.security.corespringsecurity.security.config;

import io.security.corespringsecurity.security.common.AjaxLoginAuthenticationEntryPoint;
import io.security.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import io.security.corespringsecurity.security.handler.AjaxAccessDeniedHandler;
import io.security.corespringsecurity.security.handler.AjaxAuthenticationFailureHandler;
import io.security.corespringsecurity.security.handler.AjaxAuthenticationSuccessHandler;
import io.security.corespringsecurity.security.provider.AjaxAuthenticationProvider;
import io.security.corespringsecurity.security.service.CustomUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Order(0)
@Configuration
public class AjaxSecurityConfig {

    @Autowired
    CustomUserDetailService customUserDetailService;

    @Bean
    public SecurityFilterChain ajaxFilterChain(HttpSecurity httpSecurity
//            , AuthenticationConfiguration authenticationConfiguration
            , AuthenticationManagerBuilder authenticationManagerBuilder
    ) throws Exception {
        httpSecurity
                .antMatcher("/api/**")
                .authorizeRequests()
                .antMatchers("/api/login").permitAll()
                .antMatchers("/api/ajaxLogin").permitAll()
                .antMatchers("/api/messages").hasRole("MANAGER")
                .anyRequest().authenticated()
            .and()
                .exceptionHandling()
                .authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint())
                .accessDeniedHandler(new AjaxAccessDeniedHandler());
//        httpSecurity.csrf().disable();
//        httpSecurity
//                .authenticationProvider(ajaxAuthenticationProvider());
//            .and()
//                .addFilterBefore(ajaxLoginProcessingFilter(authenticationConfiguration), UsernamePasswordAuthenticationFilter.class);
        authenticationManagerBuilder.authenticationProvider(ajaxAuthenticationProvider());


        return httpSecurity.build();
    }
    @Bean
    public AuthenticationManager authenticationManagerBean(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
        ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManagerBean(authenticationConfiguration));
        ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(new AjaxAuthenticationSuccessHandler());
        ajaxLoginProcessingFilter.setAuthenticationFailureHandler(new AjaxAuthenticationFailureHandler());
        return ajaxLoginProcessingFilter;
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider ajaxAuthenticationProvider() {
        AjaxAuthenticationProvider ajaxAuthenticationProvider = new AjaxAuthenticationProvider(customUserDetailService, passwordEncoder());
//        auth.authenticationProvider(ajaxAuthenticationProvider);
        return ajaxAuthenticationProvider;
    }

    private void customConfigurer(HttpSecurity http, AuthenticationConfiguration authenticationConfiguration) throws Exception {
        http.apply(new AjaxLoginConfigurer<>())
                .successHandlerAjax(new AjaxAuthenticationSuccessHandler())
                .failureHandlerAjax(new AjaxAuthenticationFailureHandler())
                .loginProcessingUrl("/api/ajaxLogin")
                .setAuthenticationManagerAjax(authenticationManagerBean(authenticationConfiguration));
    }

}
