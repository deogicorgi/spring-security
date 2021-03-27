package com.deogicorgi.security.config;

import com.deogicorgi.security.authenticate.AuthenticationService;
import com.deogicorgi.security.authenticate.AuthenticationServiceImpl;
import com.deogicorgi.security.authenticate.DefaultAuthenticationProvider;
import com.deogicorgi.security.config.properties.SecurityProperties;
import com.deogicorgi.security.handler.DefaultAuthenticationFailureHandler;
import com.deogicorgi.security.handler.DefaultAuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth, AuthenticationService authenticationService, SecurityProperties securityProperties) throws Exception {
        auth.authenticationProvider(authenticationProvider(authenticationService));
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

        SecurityProperties securityProperties = securityProperties();
        System.out.println(securityProperties);

        HttpSecurity httpSecurity = http.csrf().disable()
                .authorizeRequests()
                .anyRequest().authenticated()
                .and();

        // form login setting
        FormLoginConfigurer<HttpSecurity> formLogin = httpSecurity.formLogin();

        formLogin.loginPage(securityProperties.getHttp().getFormLogin().getUrl().getLoginUrl())
                .loginProcessingUrl(securityProperties.getHttp().getFormLogin().getUrl().getProcessUrl())
                .usernameParameter(securityProperties.getHttp().getFormLogin().getParameter().getUsername())
                .passwordParameter(securityProperties.getHttp().getFormLogin().getParameter().getPassword())
                .permitAll();

        if (true) {
            formLogin = formLogin
                    .successHandler(successHandler())
                    .failureHandler(failureHandler());
        }

        httpSecurity = formLogin.and();

        //form login success and failure setting


        httpSecurity = httpSecurity.oauth2Login()
                .loginPage("")
                .loginProcessingUrl("")
                .permitAll()
                .and();

        httpSecurity.logout()
                .logoutUrl(securityProperties.getHttp().getFormLogin().getUrl().getLogoutUrl())
                .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler(HttpStatus.OK))
                .deleteCookies("JSESSIONID")
                .invalidateHttpSession(true)
                .permitAll();

    }

    public AuthenticationProvider authenticationProvider(AuthenticationService authenticationService) {
        return new DefaultAuthenticationProvider(authenticationService);
    }

    private AuthenticationSuccessHandler successHandler() {
        return new DefaultAuthenticationSuccessHandler();
    }

    private AuthenticationFailureHandler failureHandler() {
        return new DefaultAuthenticationFailureHandler();
    }

    @Bean
    @ConfigurationProperties(prefix = "security")
    public SecurityProperties securityProperties() {
        return new SecurityProperties();
    }

    @Bean
    @ConditionalOnClass(AuthenticationService.class)
    public AuthenticationService authenticationService() {
        return new AuthenticationServiceImpl();
    }
}
