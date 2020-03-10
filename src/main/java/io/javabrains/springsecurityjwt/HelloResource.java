package io.javabrains.springsecurityjwt;

import io.javabrains.springsecurityjwt.request.AuthenticationRequest;
import io.javabrains.springsecurityjwt.response.AuthenticationResponse;
import io.javabrains.springsecurityjwt.services.MyUserDetailsService;
import io.javabrains.springsecurityjwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloResource {

    // Spring Security (required as part of the authentication)
    private AuthenticationManager authenticationManager;

    private MyUserDetailsService myUserDetailsService;

    private JwtUtil jwtUtil;

    @Autowired
    HelloResource(AuthenticationManager authenticationManager,
                  MyUserDetailsService myUserDetailsService,
                  JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.myUserDetailsService = myUserDetailsService;
        this.jwtUtil = jwtUtil;
    }

    // http://localhost:8080/hello
    // Header:
    //  Authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmb28iLCJleHAiOjE1ODM4ODc5MjksImlhdCI6MTU4Mzg1MTkyOX0.nuludyufA3LgmfgKxbrygvYC2uN64tfQ5gpYURpTHN0"
    // The Spring Security will auto redirects the browser to http://localhost:8080/login, requires you to login.
    // Enter the username and password to enter
    @GetMapping("/hello")
    public String hello() {
        return "Hello World";
    }

    // An API to authenticate the user.
    // http://localhost:8080/authenticate
    // raw JSON body
    // {
    //	    "username": "foo",
    //	    "password": "foo"
    //  }
    // After response the JWT string back, the user can use that token string to access other resources that only authenticated user can access to.
    // But by default Spring Security will also authenticate the user in this API, so we need to tell Spring Security to not authenticate the user when calling this API. (Check SecurityConfiguration.java file)
    // And then, you need Spring Security to listen to your header and get it's value to get the JWT, and extract the user to authenticate the user.
    @PostMapping("/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
        try {
            // Check whether this use is within this Spring Security context or not. (Main thing)
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword()));
        } catch (BadCredentialsException e) {
            throw new Exception("Incorrect username or password", e);
        }

        // Use Spring Security to create and save new User(User object also created by Spring Security), all already self defined by Spring.****
        // Remember User also extends from UserDetail object, so it has been up casted before go back to here.
        final UserDetails userDetails = myUserDetailsService.loadUserByUsername(authenticationRequest.getUsername());

        // Generate the JWT
        final String jwt = jwtUtil.generateToken(userDetails);

        // Response Success.
        return ResponseEntity.ok(new AuthenticationResponse(jwt));
    }

    // {
    //     "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmb28iLCJleHAiOjE1ODM4ODc5MjksImlhdCI6MTU4Mzg1MTkyOX0.nuludyufA3LgmfgKxbrygvYC2uN64tfQ5gpYURpTHN0"
    // }

}
