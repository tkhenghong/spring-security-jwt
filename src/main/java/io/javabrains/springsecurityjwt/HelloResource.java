package io.javabrains.springsecurityjwt;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloResource {
    // http://localhost:8080/hello
    // The Spring Security will auto redirects the browser to http://localhost:8080/login, requires you to login.
    // Enter the username and password to enter
    @GetMapping("/hello")
    public String hello() {
        return "Hello World";
    }
}
