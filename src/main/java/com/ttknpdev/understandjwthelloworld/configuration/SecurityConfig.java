package com.ttknpdev.understandjwthelloworld.configuration;

import com.ttknpdev.understandjwthelloworld.configuration.jwt.JwtAuthenticationEntryPoint;
import com.ttknpdev.understandjwthelloworld.configuration.jwt.JwtRequestFilter;
import com.ttknpdev.understandjwthelloworld.configuration.jwt.JwtTokenUtil;
import com.ttknpdev.understandjwthelloworld.log.Logging;
import com.ttknpdev.understandjwthelloworld.service.JwtUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/*
   This class extends the WebSecurityConfigurerAdapter is a convenience class
   that allows customization to both WebSecurity and HttpSecurity.
*/
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private JwtTokenUtil jwtTokenUtil;
    private JwtRequestFilter jwtRequestFilter;
    private JwtUserDetailsService jwtUserDetailsService;
    private PasswordEncoder passwordEncoder;
    private Logging logging;

    @Autowired // Initial all beans in container
    public SecurityConfig(@Qualifier("entryPoint") JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
                          @Qualifier("tokenUtil") JwtTokenUtil jwtTokenUtil,
                          @Qualifier("requestFilter") JwtRequestFilter jwtRequestFilter,
                          // @Service is mark that class. it is bean too
                          @Qualifier("detailsService") JwtUserDetailsService jwtUserDetailsService,
                          @Qualifier("encoder") PasswordEncoder passwordEncoder) {
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtTokenUtil = jwtTokenUtil;
        this.jwtRequestFilter = jwtRequestFilter;
        this.jwtUserDetailsService = jwtUserDetailsService;
        this.passwordEncoder = passwordEncoder;
        logging = new Logging(SecurityConfig.class);
    }


    /*@Autowired
    public SecurityConfig(JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint, UserDetailsService jwtUserDetailsService, JwtRequestFilter jwtRequestFilter ) {
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtUserDetailsService = jwtUserDetailsService;
        this.jwtRequestFilter = jwtRequestFilter;
        logging = new Logging(SecurityConfig.class);
    }*/

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        // configure AuthenticationManager so that it knows from where to load user for matching credentials. Use BCryptPasswordEncoder
        auth
            .userDetailsService(jwtUserDetailsService)
            .passwordEncoder(passwordEncoder);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config
                .getAuthenticationManager();
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.csrf().disable()
                // it won't authenticate this particular request (this way dont specify http method)
                .authorizeRequests()
                .requestMatchers("/jwt/authenticate")
                .permitAll()
                // and all other requests need to be authenticated
                .anyRequest().authenticated()
                .and()
                // make sure we use stateless session;
                // session won't be used to
                // store user's state.
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        // Add a filter to validate the tokens with every request
        http.addFilterBefore(jwtRequestFilter , UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
