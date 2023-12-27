package com.ttknpdev.understandjwthelloworld.configuration;

import com.ttknpdev.understandjwthelloworld.configuration.jwt.JwtAuthenticationEntryPoint;
import com.ttknpdev.understandjwthelloworld.configuration.jwt.JwtRequestFilter;
import com.ttknpdev.understandjwthelloworld.configuration.jwt.JwtTokenUtil;
import com.ttknpdev.understandjwthelloworld.service.JwtUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


/*
 this JwtConfiguration class it'll prepare any beans to spring container
 and again Any @Service is bean too
*/
@Configuration
public class JwtConfig {

    @Bean(name = "entryPoint")
    public JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint() {

        return new JwtAuthenticationEntryPoint();

    }

    @Bean(name = "requestFilter")
    public JwtRequestFilter jwtRequestFilter() {
        return new JwtRequestFilter(
                jwtUserDetailsService() ,
                jwtTokenUtil()
        );
    }

    @Bean(name = "tokenUtil")
    public JwtTokenUtil jwtTokenUtil() {

        return new JwtTokenUtil();

    }
    @Bean("detailsService")
    public JwtUserDetailsService jwtUserDetailsService() {

        return new JwtUserDetailsService();

    }
    @Bean("encoder")
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
