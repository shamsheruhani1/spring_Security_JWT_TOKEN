package com.securtiy.security.configuration;

import com.securtiy.security.jwt.AuthEntryPointJWT;
import com.securtiy.security.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguration {

    @Autowired
    private DataSource dataSource;

    @Autowired
    private AuthEntryPointJWT unAuthorizeHandler;

    @Bean
    public AuthTokenFilter authenticationJwtFilter(){
        return new AuthTokenFilter();
    }
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests ->
                requests
                        .requestMatchers("/signin").permitAll()
                .anyRequest().authenticated());
        //http.formLogin(withDefaults());
        http.sessionManagement(
                session-> session.sessionCreationPolicy(
                        SessionCreationPolicy.STATELESS));

        http.exceptionHandling(exception->
                exception.authenticationEntryPoint(unAuthorizeHandler));
        http.csrf(AbstractHttpConfigurer::disable);
        //http.httpBasic(withDefaults());
        http.addFilterBefore(authenticationJwtFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(){

        UserDetails user= User.withUsername("user").
                password(passwordEncoder().encode("password") ).roles("USER").build();
        UserDetails admin= User.withUsername("admin").password(passwordEncoder().encode("password")).roles("ADMIN").build();
        JdbcUserDetailsManager userDetailsService= new JdbcUserDetailsManager(dataSource);
        userDetailsService.createUser(user);
        userDetailsService.createUser(admin);
        return userDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker(){
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }
}
