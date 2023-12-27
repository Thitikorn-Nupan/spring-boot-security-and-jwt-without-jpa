package com.ttknpdev.understandjwthelloworld.configuration.jwt;

import com.ttknpdev.understandjwthelloworld.log.Logging;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
/*
    This class will extend Spring's AuthenticationEntryPoint class and override its method commence.
    It rejects(v. ปฎิเสธ) every unauthenticated request and send error code 401
// @Component
*/
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint { // Serializable
    // private static final long serialVersionUID = -7858869558953243875L;
    private Logging logging;
    public JwtAuthenticationEntryPoint() {

        logging  = new Logging(JwtTokenUtil.class);

    }
    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        logging.logBack.warn("commence() override method works (rejects every unauthenticated request}");
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "unauthorized in this secure API");
    }
}
