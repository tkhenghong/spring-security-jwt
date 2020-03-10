package io.javabrains.springsecurityjwt.services;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

// A service that will be managed by Spring Security to handle User Details.
@Service
public class MyUserDetailsService implements UserDetailsService {

    // This is just a static method to load user by default.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // If you want to have more users, you can start from here to save your User into the DB.*****
        // A Spring Security User is generated. Requires name, password, and what authorities that this user have.
        return new User("foo", "foo", new ArrayList<>());
    }
}
