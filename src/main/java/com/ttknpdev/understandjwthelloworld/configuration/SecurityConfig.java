package com.ttknpdev.understandjwthelloworld.configuration;

import com.ttknpdev.understandjwthelloworld.configuration.jwt.JwtAuthenticationEntryPoint;
import com.ttknpdev.understandjwthelloworld.configuration.jwt.JwtRequestFilter;
import com.ttknpdev.understandjwthelloworld.log.Logging;
import com.ttknpdev.understandjwthelloworld.configuration.jwt.JwtUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

/**
 * This class extends the WebSecurityConfigurerAdapter is a convenience class
 * that allows customization to both WebSecurity and HttpSecurity.
 */
@Configuration
@EnableWebSecurity// (debug = true)
// @EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    // private final JwtTokenUtil jwtTokenUtil;
    private final JwtRequestFilter jwtRequestFilter;
    private final JwtUserDetailsService jwtUserDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final Logging log;

    @Autowired // Initial all beans in container
    public SecurityConfig(@Qualifier("entryPoint") JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
                          // @Qualifier("tokenUtil") JwtTokenUtil jwtTokenUtil,
                          @Qualifier("requestFilter") JwtRequestFilter jwtRequestFilter,
                          // @Service is mark that class. it is bean too
                          @Qualifier("detailsService") JwtUserDetailsService jwtUserDetailsService,
                          @Qualifier("encoder") PasswordEncoder passwordEncoder) {
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        // this.jwtTokenUtil = jwtTokenUtil;
        this.jwtRequestFilter = jwtRequestFilter;
        this.jwtUserDetailsService = jwtUserDetailsService;
        this.passwordEncoder = passwordEncoder;
        log = new Logging(SecurityConfig.class);
    }


    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        // configure AuthenticationManager so that it knows from where to load user for matching credentials. Use BCryptPasswordEncoder
        log.logBack.debug("**** configureGlobal");
        auth
                .userDetailsService(jwtUserDetailsService)
                .passwordEncoder(passwordEncoder);
    }

    // this
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config
                .getAuthenticationManager();
    }


    // get error from // set @EnableWebSecurity(debug = true)
    // I noticed that the issue is related to changes in the WebMvcSecurityConfiguration class in spring-security-config:6.2.1. For reference, I have provided sample projects for both Spring Boot 3.2.0 and 3.2.1:
    // Error creating bean with name 'springSecurityFilterChain': Failed to instantiate [org.springframework.security.config.annotation.web.configuration.WebMvcSecurityConfiguration$CompositeFilterChainProxy]: Constructor threw exception
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        log.logBack.debug("Security Filter Chain");

        httpSecurity
                .csrf()
                .disable()
                .authorizeRequests((requests) -> {
                            // it won't authenticate this particular request (this way dont specify http method)
                            requests.requestMatchers(HttpMethod.POST, "/jwt/login").permitAll();
                            requests.anyRequest().authenticated();
                })
                .httpBasic()
                .and()
                // handle
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .and()
                // make sure we use stateless session;
                // session won't be used to
                // store user's state.
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                 // add a filter to validate the tokens with every request
                .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }

    // set cors config
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost","http://192.168.1.108"));
        // configuration.setAllowedMethods(Arrays.asList("GET","POST"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", configuration);
        return source;
    }
}
