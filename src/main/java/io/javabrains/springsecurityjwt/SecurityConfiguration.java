package io.javabrains.springsecurityjwt;

import io.javabrains.springsecurityjwt.filter.JwtRequestFilter;
import io.javabrains.springsecurityjwt.services.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// Basic Spring Security Setup
// Configure Web Security here
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private MyUserDetailsService myUserDetailsService;

    private JwtRequestFilter jwtRequestFilter;

    @Autowired
    SecurityConfiguration(MyUserDetailsService myUserDetailsService, JwtRequestFilter jwtRequestFilter) {
        this.myUserDetailsService = myUserDetailsService;
        this.jwtRequestFilter = jwtRequestFilter;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        // This tells Spring Security to add this user detail.
        auth.userDetailsService(myUserDetailsService);
    }

    // Setup PasswordEncoder here to encode your password
    // This is telling Spring Security to do not automatic hash the passwords when any requests coming into the application.
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    // Main thing. WL he just used XML format to write all these things
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable() // First, disable the cross-site request forgery
                .authorizeRequests().antMatchers("/authenticate").permitAll() // Allow /authenticate API to anyone.
                .anyRequest().authenticated() // SecurityContextHolder.getContext().getAuthentication()
        .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // Set session management to be stateless (don't create HTTP sessions! The whole point of JWT is stateless!)
         // Otherwise, access to other API will be authenticated.

        // Add this line to add the filter, and it needs to be before UsernamePasswordAuthenticationFilter
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
    }

    // Problem: https://stackoverflow.com/questions/52243774/consider-defining-a-bean-of-type-org-springframework-security-authentication-au
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
