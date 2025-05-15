package com.ja.Project_JA.controller;

import java.util.Collection;
import java.util.UUID;

import com.ja.Project_JA.config.JwtTokenProvider;
import com.ja.Project_JA.dto.request.LoginRequest;
import com.ja.Project_JA.dto.request.RegisterRequest;
import com.ja.Project_JA.dto.response.AuthResponse;
import com.ja.Project_JA.entity.User;
import com.ja.Project_JA.repository.UserRepository;
import com.ja.Project_JA.service.CustomerUserDetailsService;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@Log4j2
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtProvider;
    private final CustomerUserDetailsService customerUserDetailsService;

    public AuthController(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtTokenProvider jwtProvider, CustomerUserDetailsService customerUserDetailsService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtProvider = jwtProvider;
        this.customerUserDetailsService = customerUserDetailsService;
    }

    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> createUserHandler(@RequestBody RegisterRequest user) throws Exception {
        System.out.println("sign up called");
        log.info("Received signup request for email: {}", user.getUserEmail());
        User doesEmailExists = userRepository.findByUserEmail(user.getUserEmail());
        if (doesEmailExists != null) {
            throw new Exception("Email is already used with another account");
        }
        User createdUser = new User();
        createdUser.setUserId(UUID.randomUUID().toString());        createdUser.setUserEmail(user.getUserEmail());
        createdUser.setUserName(user.getUserName());
        createdUser.setUserPassword(passwordEncoder.encode(user.getUserPassword()));

        User savedUser = userRepository.save(createdUser);

        Authentication authentication = new UsernamePasswordAuthenticationToken(user.getUserEmail(), user.getUserPassword());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtProvider.generateToken(authentication);
        AuthResponse authResponse = new AuthResponse();
        authResponse.setUserName(savedUser.getUserName());
        authResponse.setJwt(jwt);
        authResponse.setMessage("Registration successful");
        return new ResponseEntity<>(authResponse, HttpStatus.CREATED);
    }

    @PostMapping("/signin")
    public ResponseEntity<AuthResponse> signin(@RequestBody LoginRequest req) {
        String username = req.getEmail();
        String password = req.getPassword();
        Authentication authentication = authenticate(username, password);
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        String role = authorities.isEmpty() ? null : authorities.iterator().next().getAuthority();

        String jwt = jwtProvider.generateToken(authentication);
        AuthResponse authResponse = new AuthResponse();
        authResponse.setJwt(jwt);
        authResponse.setMessage("Signin successful");
        authResponse.setUserName(username);
        return new ResponseEntity<>(authResponse, HttpStatus.OK);
    }

    /**
     * Authenticates a user based on the provided username and password.
     *
     * @param username the username of the user attempting to authenticate
     * @param password the password of the user attempting to authenticate
     * @return an Authentication object if the username and password are valid
     * @throws BadCredentialsException if the username is invalid or the password does not match
     */
    private Authentication authenticate(String username, String password) {
        UserDetails userDetails = customerUserDetailsService.loadUserByUsername(username);
        if (userDetails == null) {
            throw new BadCredentialsException("Invalid username..");
        }
        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException("Invalid password...");
        }
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }
}