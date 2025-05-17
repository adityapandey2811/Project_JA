package com.ja.Project_JA.controller;

import java.util.Collection;
import java.util.UUID;

import com.ja.Project_JA.config.JwtTokenProvider;
import com.ja.Project_JA.dto.request.LoginRequest;
import com.ja.Project_JA.dto.request.RegisterRequest;
import com.ja.Project_JA.dto.response.AuthResponse;
import com.ja.Project_JA.entity.USER_ROLE;
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

    public AuthController(UserRepository userRepository, PasswordEncoder passwordEncoder,
                          JwtTokenProvider jwtProvider, CustomerUserDetailsService customerUserDetailsService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtProvider = jwtProvider;
        this.customerUserDetailsService = customerUserDetailsService;
    }

    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> createUserHandler(@RequestBody RegisterRequest user) throws Exception {
        log.info("Received signup request for email: {}", user.getUserEmail());

        if (userRepository.findByUserEmail(user.getUserEmail()) != null) {
            throw new Exception("Email is already used with another account");
        }

        User createdUser = User.builder()
                .userId(UUID.randomUUID().toString())
                .userEmail(user.getUserEmail())
                .userName(user.getUserName())
                .userPassword(passwordEncoder.encode(user.getUserPassword()))
                .userRole(user.getUserRole() != null ? user.getUserRole() : USER_ROLE.USER) // default to USER
                .build();

        userRepository.save(createdUser);

        UserDetails userDetails = customerUserDetailsService.loadUserByUsername(user.getUserEmail());
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtProvider.generateToken(authentication);

        return new ResponseEntity<>(AuthResponse.builder()
                .jwt(jwt)
                .userName(createdUser.getUserName())
                .message("Registration successful")
                .build(), HttpStatus.CREATED);
    }

    @PostMapping("/signin")
    public ResponseEntity<AuthResponse> signin(@RequestBody LoginRequest req) {
        String email = req.getUserEmail();
        String password = req.getUserPassword();
        Authentication authentication = authenticate(email, password);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String jwt = jwtProvider.generateToken(authentication);

        User user = userRepository.findByUserEmail(email); // to get the name


        return new ResponseEntity<>(AuthResponse.builder()
                .jwt(jwt)
                .userName(user.getUserName())
                .message("Signin successful")
                .build(), HttpStatus.OK);
    }

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
