package io.javabrains.springsecurityjwt.filter;

import io.javabrains.springsecurityjwt.services.MyUserDetailsService;
import io.javabrains.springsecurityjwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// Filter every request's filter to extract the header, especially JWT
// extends OncePerRequestFilter to send the request to here once every time when there's a request
@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    private MyUserDetailsService myUserDetailsService;

    private JwtUtil jwtUtil;

    @Autowired
    JwtRequestFilter(MyUserDetailsService myUserDetailsService, JwtUtil jwtUtil) {
        this.myUserDetailsService = myUserDetailsService;
        this.jwtUtil = jwtUtil;
    }

    // Main method to do the thing. Request, response and filter chain(to pass on to other filters or stops right here)
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authorizationHeader = request.getHeader("Authorization");

        String username = null;
        String jwt = null;

        // Extract the header out and authenticate whether it's in the Spring Security context or not
        if(!ObjectUtils.isEmpty(authorizationHeader) && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7); // Length of "Bearer " is 7.
            username = jwtUtil.extractUsername(jwt);
        }

        // SecurityContextHolder.getContext().getAuthentication() to check whether there are authenticated user in the current Spring Security context or not.
        if(!ObjectUtils.isEmpty(username) && ObjectUtils.isEmpty(SecurityContextHolder.getContext().getAuthentication())) {
            // Get userDetails
            UserDetails userDetails = this.myUserDetailsService.loadUserByUsername(username);

            // If Spring's UserDetails object username same with JWT's extracted username's value,
            if(jwtUtil.validateToken(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                // Get the details of the request object and set it into the Spring Security token
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Save it into the Spring Security context
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }

        // Need to Pass on whether there are any filter or not. Means: I have done my here return control to other filters.
        filterChain.doFilter(request, response);
    }
}
