package io.security.corespringsecurity.security.config;

import io.security.corespringsecurity.security.common.FormAuthenticationDetailsSource;
import io.security.corespringsecurity.security.factory.UrlResourceMapFactoryBean;
import io.security.corespringsecurity.security.filter.PermitAllFilter;
import io.security.corespringsecurity.security.handler.CustomAccessDeniedHandler;
import io.security.corespringsecurity.security.handler.CustomAuthenticationFailureHandler;
import io.security.corespringsecurity.security.handler.CustomAuthenticationSuccessHandler;
import io.security.corespringsecurity.security.meatadatasource.UrlSecurityMetadataSource;
import io.security.corespringsecurity.security.processor.provider.FormAuthenticationProvider;
import io.security.corespringsecurity.security.voter.IpAddressVoter;
import io.security.corespringsecurity.service.SecurityResourceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.util.ArrayList;
import java.util.List;

@Order(1)
@Configuration
public class SecurityConfig {

    @Autowired
    UserDetailsService customUserDetailService;
    @Autowired
    FormAuthenticationDetailsSource formAuthenticationDetailsSource;
    @Autowired
    CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;
    @Autowired
    CustomAuthenticationFailureHandler customAuthenticationFailureHandler;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    AuthenticationManager authenticationManagerBean;
    @Autowired
    SecurityResourceService securityResourceService;

    private String[] permitResources = new String[]{"/", "/users", "/user/login**", "/login*"};

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity, AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        httpSecurity
                .authorizeRequests()
//                .antMatchers("/", "/users", "/users/login**", "/login*").permitAll()
//                .antMatchers("/mypage").hasRole("USER")
//                .antMatchers("/messages").hasRole("MANAGER")
//                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()
            .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .defaultSuccessUrl("/")
                .authenticationDetailsSource(formAuthenticationDetailsSource)
                .successHandler(customAuthenticationSuccessHandler)
                .failureHandler(customAuthenticationFailureHandler)
                .permitAll()
            .and()
                .exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                .accessDeniedHandler(accessDeniedHandler())
            .and()
//                .addFilterBefore(customFilterSecurityInterceptor(), FilterSecurityInterceptor.class);
                .addFilterBefore(permitAllFilter(), FilterSecurityInterceptor.class);

        httpSecurity
                .authenticationProvider(formAuthenticationProvider());
//        authenticationManagerBuilder.authenticationProvider(formAuthenticationProvider());

        return httpSecurity.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> {
            web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
        };
    }

    //    @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
        String password = passwordEncoder.encode("1111");
        User.UserBuilder userBuilder = User.builder();
        UserDetails user = userBuilder.username("user").password(password).roles("USER").build();
        UserDetails manager = userBuilder.username("manager").password(password).roles("MANAGER", "USER").build();
        UserDetails admin = userBuilder.username("admin").password(password).roles("ADMIN", "MANAGER", "USER").build();

        return new InMemoryUserDetailsManager(user, manager, admin);
    }

    public AccessDeniedHandler accessDeniedHandler() {
        CustomAccessDeniedHandler customAccessDeniedHandler = new CustomAccessDeniedHandler();
        customAccessDeniedHandler.setErrorPage("/denied");
        return customAccessDeniedHandler;
    }

    @Bean
    public AuthenticationProvider formAuthenticationProvider() {
        FormAuthenticationProvider formAuthenticationProvider = new FormAuthenticationProvider(customUserDetailService, passwordEncoder);
//        auth.authenticationProvider(formAuthenticationProvider);
        return formAuthenticationProvider;
    }

//    @Bean
    public FilterSecurityInterceptor customFilterSecurityInterceptor() throws Exception {
        FilterSecurityInterceptor customFilterSecurityInterceptor = new FilterSecurityInterceptor();
        customFilterSecurityInterceptor.setSecurityMetadataSource(urlFilterInvocation());
        customFilterSecurityInterceptor.setAccessDecisionManager(affirmativeBased());
        customFilterSecurityInterceptor.setAuthenticationManager(authenticationManagerBean);
        return customFilterSecurityInterceptor;
    }

    @Bean
    public PermitAllFilter permitAllFilter() throws Exception {
        PermitAllFilter permitAllFilter = new PermitAllFilter(permitResources);
        permitAllFilter.setSecurityMetadataSource(urlFilterInvocation());
        permitAllFilter.setAccessDecisionManager(affirmativeBased());
        permitAllFilter.setAuthenticationManager(authenticationManagerBean);
        return permitAllFilter;
    }

    @Bean
    public FilterInvocationSecurityMetadataSource urlFilterInvocation() throws Exception {
        return new UrlSecurityMetadataSource(urlResourceMapFactoryBean().getObject(), securityResourceService);
    }

    @Bean
    public UrlResourceMapFactoryBean urlResourceMapFactoryBean() {
        return new UrlResourceMapFactoryBean(securityResourceService);
    }

    @Bean
    public AccessDecisionManager affirmativeBased() {
        AffirmativeBased affirmativeBased = new AffirmativeBased(getAccessDecisionVoters());
        return affirmativeBased;
    }

    private List<AccessDecisionVoter<?>> getAccessDecisionVoters() {
//        return Arrays.asList(new RoleVoter());
        List<AccessDecisionVoter<? extends Object>> decisionVoters = new ArrayList<>();
        decisionVoters.add(ipAddressVoter());
        decisionVoters.add(roleVoter());
        return decisionVoters;
    }

    @Bean
    public AccessDecisionVoter<? extends Object> roleVoter() {
        RoleHierarchyVoter roleHierarchyVoter = new RoleHierarchyVoter(roleHierarch());
        return roleHierarchyVoter;
    }

    @Bean
    public RoleHierarchy roleHierarch() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        return roleHierarchy;
    }

    @Bean
    public AccessDecisionVoter<? extends Object> ipAddressVoter() {
        return new IpAddressVoter(securityResourceService);
    }


}
