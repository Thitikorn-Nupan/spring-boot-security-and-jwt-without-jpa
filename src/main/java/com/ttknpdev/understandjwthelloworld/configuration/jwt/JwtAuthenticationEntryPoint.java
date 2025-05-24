package com.ttknpdev.understandjwthelloworld.configuration.jwt;

import com.ttknpdev.understandjwthelloworld.log.Logging;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
/**
    This class will extend Spring's AuthenticationEntryPoint class and override its method commence.
    It rejects(v. ปฎิเสธ) every unauthenticated request and send error code 401
*/
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint { // Serializable
    // private static final long serialVersionUID = -7858869558953243875L;
    private final Logging logging;

    public JwtAuthenticationEntryPoint() {
        logging  = new Logging(JwtAuthenticationEntryPoint.class);
    }

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        logging.logBack.warn("*** commence() method works (rejects every unauthenticated request}");
        // when token is not correct do
        // when http header is not set auth type is do
        // when http method is wrong is do
        // so if i use this AuthenticationEntryPoint i dont want to set response as error doFilterInternal method
        // response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "unauthorized in this secure API");
        if (authException != null) {
            logging.logBack.debug("failed {}", authException.getMessage());
            StringBuilder stringBuilder = getErrorStringBuilder(request, new RuntimeException(),401 ,authException.getMessage());
            response.setStatus(401);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter()
                    .print(stringBuilder);
            response.getWriter()
                    .flush();
        }
    }

    private static StringBuilder getErrorStringBuilder(HttpServletRequest request, Exception e,int status , String message) {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("{");
        stringBuilder.append("\"requestURL\": \"" + request.getRequestURL().toString() + "\",");
        stringBuilder.append("\"requestMethod\": \"" + request.getMethod() + "\",");
        stringBuilder.append("\"errorMessage\": \"" + e.getMessage() + "\",");
        stringBuilder.append("\"errorClassName\": \"" + e.getClass().getName() + "\",");
        stringBuilder.append("\"status\":" + status + ",");
        stringBuilder.append("\"message\": \"" + message + "\"");
        stringBuilder.append("}");
        return stringBuilder;
    }
}
