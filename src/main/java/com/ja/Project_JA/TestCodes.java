//// SPRING SECURITY IMPLEMENTATION GUIDE
//// This guide provides a comprehensive implementation of Spring Security
//// following OWASP security best practices
//
//// STEP 1: DEPENDENCIES
//// Add these to your pom.xml (for Maven)
//
///*
//<dependencies>
//    <!-- Spring Security -->
//    <dependency>
//        <groupId>org.springframework.boot</groupId>
//        <artifactId>spring-boot-starter-security</artifactId>
//    </dependency>
//
//    <!-- JWT Support -->
//    <dependency>
//        <groupId>io.jsonwebtoken</groupId>
//        <artifactId>jjwt-api</artifactId>
//        <version>0.11.5</version>
//    </dependency>
//    <dependency>
//        <groupId>io.jsonwebtoken</groupId>
//        <artifactId>jjwt-impl</artifactId>
//        <version>0.11.5</version>
//        <scope>runtime</scope>
//    </dependency>
//    <dependency>
//        <groupId>io.jsonwebtoken</groupId>
//        <artifactId>jjwt-jackson</artifactId>
//        <version>0.11.5</version>
//        <scope>runtime</scope>
//    </dependency>
//
//    <!-- For password hashing -->
//    <dependency>
//        <groupId>org.springframework.security</groupId>
//        <artifactId>spring-security-crypto</artifactId>
//    </dependency>
//
//    <!-- For validation -->
//    <dependency>
//        <groupId>org.springframework.boot</groupId>
//        <artifactId>spring-boot-starter-validation</artifactId>
//    </dependency>
//</dependencies>
//*/
//
//// STEP 2: CORE SECURITY CONFIGURATION
//
//package com.example.security.config;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
//import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//import org.springframework.web.cors.CorsConfiguration;
//import org.springframework.web.cors.CorsConfigurationSource;
//import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
//import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
//
//import com.example.security.jwt.JwtAuthenticationEntryPoint;
//import com.example.security.jwt.JwtAuthenticationFilter;
//
//import java.util.Arrays;
//
//@Configuration
//@EnableWebSecurity
//@EnableMethodSecurity
//public class SecurityConfig {
//
//    private final JwtAuthenticationEntryPoint jwtAuthEntryPoint;
//    private final JwtAuthenticationFilter jwtAuthFilter;
//
//    public SecurityConfig(JwtAuthenticationEntryPoint jwtAuthEntryPoint, JwtAuthenticationFilter jwtAuthFilter) {
//        this.jwtAuthEntryPoint = jwtAuthEntryPoint;
//        this.jwtAuthFilter = jwtAuthFilter;
//    }
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        // Configure security settings
//        http
//                .csrf(csrf -> csrf.disable())  // Disable CSRF for REST APIs with JWT authentication
//                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
//                .exceptionHandling(exception -> exception.authenticationEntryPoint(jwtAuthEntryPoint))
//                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .authorizeHttpRequests(authz -> authz
//                        // Public endpoints
//                        .requestMatchers("/api/auth/**", "/api/public/**", "/swagger-ui/**", "/v3/api-docs/**").permitAll()
//                        // Secure all other endpoints
//                        .anyRequest().authenticated()
//                )
//                // Add security headers (OWASP recommendations)
//                .headers(headers -> headers
//                        .xssProtection(xss -> xss.disable())  // Modern browsers use Content-Security-Policy instead
//                        .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'; frame-ancestors 'self'"))
//                        .frameOptions(frame -> frame.deny())
//                        .referrerPolicy(referrer -> referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.SAME_ORIGIN))
//                        .permissionsPolicy(permissions -> permissions.policy("camera=(), microphone=(), geolocation=()"))
//                );
//
//        // Add JWT filter
//        http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
//
//        return http.build();
//    }
//
//    @Bean
//    public CorsConfigurationSource corsConfigurationSource() {
//        CorsConfiguration configuration = new CorsConfiguration();
//        configuration.setAllowedOrigins(Arrays.asList("https://yourdomain.com")); // Restrict to your domains
//        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
//        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
//        configuration.setExposedHeaders(Arrays.asList("Authorization"));
//        configuration.setAllowCredentials(true);
//        configuration.setMaxAge(3600L);
//
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", configuration);
//        return source;
//    }
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        // Use BCrypt with strength factor 12 (OWASP recommendation)
//        return new BCryptPasswordEncoder(12);
//    }
//
//    @Bean
//    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
//        return authConfig.getAuthenticationManager();
//    }
//}
//
//// STEP 3: JWT CONFIGURATION
//
//package com.example.security.jwt;
//
//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.ExpiredJwtException;
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.MalformedJwtException;
//import io.jsonwebtoken.UnsupportedJwtException;
//import io.jsonwebtoken.security.Keys;
//import io.jsonwebtoken.security.SignatureException;
//
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.stereotype.Component;
//
//import java.security.Key;
//import java.util.Date;
//import java.util.HashMap;
//import java.util.Map;
//import java.util.function.Function;
//
//@Component
//public class JwtTokenProvider {
//
//    @Value("${app.jwt.secret}")
//    private String jwtSecret;
//
//    @Value("${app.jwt.expiration}")
//    private long jwtExpirationMs;
//
//    @Value("${app.jwt.refresh-expiration}")
//    private long jwtRefreshExpirationMs;
//
//    // Generate JWT token
//    public String generateToken(Authentication authentication) {
//        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
//        return generateToken(userDetails);
//    }
//
//    // Generate token for UserDetails
//    public String generateToken(UserDetails userDetails) {
//        Map<String, Object> claims = new HashMap<>();
//        return createToken(claims, userDetails.getUsername());
//    }
//
//    // Create token with claims, subject, and expiration
//    private String createToken(Map<String, Object> claims, String subject) {
//        Date now = new Date();
//        Date expiryDate = new Date(now.getTime() + jwtExpirationMs);
//
//        return Jwts.builder()
//                .setClaims(claims)
//                .setSubject(subject)
//                .setIssuedAt(now)
//                .setExpiration(expiryDate)
//                .signWith(getSigningKey())
//                .compact();
//    }
//
//    // Generate refresh token
//    public String generateRefreshToken(UserDetails userDetails) {
//        Date now = new Date();
//        Date expiryDate = new Date(now.getTime() + jwtRefreshExpirationMs);
//
//        return Jwts.builder()
//                .setSubject(userDetails.getUsername())
//                .setIssuedAt(now)
//                .setExpiration(expiryDate)
//                .signWith(getSigningKey())
//                .compact();
//    }
//
//    // Extract username from token
//    public String extractUsername(String token) {
//        return extractClaim(token, Claims::getSubject);
//    }
//
//    // Extract expiration date from token
//    public Date extractExpiration(String token) {
//        return extractClaim(token, Claims::getExpiration);
//    }
//
//    // Extract claim from token
//    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
//        final Claims claims = extractAllClaims(token);
//        return claimsResolver.apply(claims);
//    }
//
//    // Extract all claims from token
//    private Claims extractAllClaims(String token) {
//        return Jwts.parserBuilder()
//                .setSigningKey(getSigningKey())
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//    }
//
//    // Get signing key
//    private Key getSigningKey() {
//        byte[] keyBytes = jwtSecret.getBytes();
//        return Keys.hmacShaKeyFor(keyBytes);
//    }
//
//    // Check if token is expired
//    private Boolean isTokenExpired(String token) {
//        final Date expiration = extractExpiration(token);
//        return expiration.before(new Date());
//    }
//
//    // Validate token
//    public Boolean validateToken(String token, UserDetails userDetails) {
//        final String username = extractUsername(token);
//        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
//    }
//
//    // Validate token without UserDetails
//    public boolean validateToken(String token) {
//        try {
//            Jwts.parserBuilder()
//                    .setSigningKey(getSigningKey())
//                    .build()
//                    .parseClaimsJws(token);
//            return true;
//        } catch (SignatureException ex) {
//            // Invalid JWT signature
//            return false;
//        } catch (MalformedJwtException ex) {
//            // Invalid JWT token
//            return false;
//        } catch (ExpiredJwtException ex) {
//            // Expired JWT token
//            return false;
//        } catch (UnsupportedJwtException ex) {
//            // Unsupported JWT token
//            return false;
//        } catch (IllegalArgumentException ex) {
//            // JWT claims string is empty
//            return false;
//        }
//    }
//}
//
//// STEP 4: JWT AUTHENTICATION FILTER
//
//package com.example.security.jwt;
//
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.lang.NonNull;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
//import org.springframework.stereotype.Component;
//import org.springframework.util.StringUtils;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//
//@Component
//public class JwtAuthenticationFilter extends OncePerRequestFilter {
//
//    private final JwtTokenProvider jwtTokenProvider;
//    private final UserDetailsService userDetailsService;
//
//    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider, UserDetailsService userDetailsService) {
//        this.jwtTokenProvider = jwtTokenProvider;
//        this.userDetailsService = userDetailsService;
//    }
//
//    @Override
//    protected void doFilterInternal(@NonNull HttpServletRequest request,
//                                    @NonNull HttpServletResponse response,
//                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
//        try {
//            // Extract JWT token from request
//            String jwt = getJwtFromRequest(request);
//
//            // Validate token and set authentication
//            if (StringUtils.hasText(jwt) && jwtTokenProvider.validateToken(jwt)) {
//                String username = jwtTokenProvider.extractUsername(jwt);
//
//                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//
//                UsernamePasswordAuthenticationToken authentication =
//                        new UsernamePasswordAuthenticationToken(
//                                userDetails,
//                                null,
//                                userDetails.getAuthorities()
//                        );
//
//                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//
//                SecurityContextHolder.getContext().setAuthentication(authentication);
//            }
//        } catch (Exception ex) {
//            logger.error("Could not set user authentication in security context", ex);
//        }
//
//        filterChain.doFilter(request, response);
//    }
//
//    private String getJwtFromRequest(HttpServletRequest request) {
//        String bearerToken = request.getHeader("Authorization");
//        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
//            return bearerToken.substring(7);
//        }
//        return null;
//    }
//}
//
//// STEP 5: JWT AUTHENTICATION ENTRY POINT
//
//package com.example.security.jwt;
//
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.web.AuthenticationEntryPoint;
//import org.springframework.stereotype.Component;
//
//import java.io.IOException;
//
//@Component
//public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
//
//    @Override
//    public void commence(HttpServletRequest request,
//                         HttpServletResponse response,
//                         AuthenticationException authException) throws IOException {
//        // This is invoked when user tries to access a secured REST resource without supplying any credentials
//        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
//    }
//}
//
//// STEP 6: USER DETAILS SERVICE IMPLEMENTATION
//
//package com.example.security.service;
//
//import com.example.security.entity.User;
//import com.example.security.repository.UserRepository;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.stereotype.Service;
//import org.springframework.transaction.annotation.Transactional;
//
//import java.util.List;
//import java.util.stream.Collectors;
//
//@Service
//public class CustomUserDetailsService implements UserDetailsService {
//
//    private final UserRepository userRepository;
//
//    public CustomUserDetailsService(UserRepository userRepository) {
//        this.userRepository = userRepository;
//    }
//
//    @Override
//    @Transactional
//    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
//        // Allow login with either username or email
//        User user = userRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
//                .orElseThrow(() -> new UsernameNotFoundException("User not found with username or email: " + usernameOrEmail));
//
//        // Convert custom roles to Spring Security SimpleGrantedAuthority
//        List<SimpleGrantedAuthority> authorities = user.getRoles().stream()
//                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
//                .collect(Collectors.toList());
//
//        // Return Spring Security User object
//        return new org.springframework.security.core.userdetails.User(
//                user.getUsername(),
//                user.getPassword(),
//                user.isEnabled(),
//                true, // account non-expired
//                true, // credentials non-expired
//                !user.isLocked(), // account non-locked (note the negation)
//                authorities
//        );
//    }
//}
//
//// STEP 7: USER ENTITY
//
//package com.example.security.entity;
//
//import jakarta.persistence.*;
//        import jakarta.validation.constraints.Email;
//import jakarta.validation.constraints.NotBlank;
//import jakarta.validation.constraints.Size;
//
//import java.util.HashSet;
//import java.util.Set;
//
//@Entity
//@Table(name = "users", uniqueConstraints = {
//        @UniqueConstraint(columnNames = "username"),
//        @UniqueConstraint(columnNames = "email")
//})
//public class User {
//
//    @Id
//    @GeneratedValue(strategy = GenerationType.IDENTITY)
//    private Long id;
//
//    @NotBlank
//    @Size(max = 50)
//    private String username;
//
//    @NotBlank
//    @Size(max = 100)
//    @Email
//    private String email;
//
//    @NotBlank
//    @Size(max = 120)
//    private String password;
//
//    private boolean enabled = true;
//
//    private boolean locked = false;
//
//    private int failedAttempts = 0;
//
//    // For security improvements, consider adding fields like:
//    private String lastLoginIp;
//    private String lastLoginDate;
//    private String passwordResetToken;
//    private java.util.Date passwordResetExpiry;
//
//    @ManyToMany(fetch = FetchType.EAGER)
//    @JoinTable(name = "user_roles",
//            joinColumns = @JoinColumn(name = "user_id"),
//            inverseJoinColumns = @JoinColumn(name = "role_id"))
//    private Set<Role> roles = new HashSet<>();
//
//    // Constructors, getters, and setters
//    public User() {}
//
//    public User(String username, String email, String password) {
//        this.username = username;
//        this.email = email;
//        this.password = password;
//    }
//
//    // Getters and setters
//    public Long getId() {
//        return id;
//    }
//
//    public void setId(Long id) {
//        this.id = id;
//    }
//
//    public String getUsername() {
//        return username;
//    }
//
//    public void setUsername(String username) {
//        this.username = username;
//    }
//
//    public String getEmail() {
//        return email;
//    }
//
//    public void setEmail(String email) {
//        this.email = email;
//    }
//
//    public String getPassword() {
//        return password;
//    }
//
//    public void setPassword(String password) {
//        this.password = password;
//    }
//
//    public Set<Role> getRoles() {
//        return roles;
//    }
//
//    public void setRoles(Set<Role> roles) {
//        this.roles = roles;
//    }
//
//    public boolean isEnabled() {
//        return enabled;
//    }
//
//    public void setEnabled(boolean enabled) {
//        this.enabled = enabled;
//    }
//
//    public boolean isLocked() {
//        return locked;
//    }
//
//    public void setLocked(boolean locked) {
//        this.locked = locked;
//    }
//
//    public int getFailedAttempts() {
//        return failedAttempts;
//    }
//
//    public void setFailedAttempts(int failedAttempts) {
//        this.failedAttempts = failedAttempts;
//    }
//}
//
//// STEP 8: ROLE ENTITY
//
//package com.example.security.entity;
//
//import jakarta.persistence.*;
//
//@Entity
//@Table(name = "roles")
//public class Role {
//    @Id
//    @GeneratedValue(strategy = GenerationType.IDENTITY)
//    private Long id;
//
//    @Column(length = 20)
//    private String name;
//
//    // Constructors, getters, and setters
//    public Role() {}
//
//    public Role(String name) {
//        this.name = name;
//    }
//
//    public Long getId() {
//        return id;
//    }
//
//    public void setId(Long id) {
//        this.id = id;
//    }
//
//    public String getName() {
//        return name;
//    }
//
//    public void setName(String name) {
//        this.name = name;
//    }
//}
//
//// STEP 9: AUTHENTICATION CONTROLLER
//
//package com.example.security.controller;
//
//import com.example.security.entity.Role;
//import com.example.security.entity.User;
//import com.example.security.jwt.JwtTokenProvider;
//import com.example.security.payload.JwtAuthResponse;
//import com.example.security.payload.LoginRequest;
//import com.example.security.payload.RefreshTokenRequest;
//import com.example.security.payload.SignupRequest;
//import com.example.security.repository.RoleRepository;
//import com.example.security.repository.UserRepository;
//import com.example.security.util.RateLimiter;
//
//import jakarta.validation.Valid;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.annotation.AuthenticationPrincipal;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.web.bind.annotation.*;
//
//        import java.util.HashSet;
//import java.util.Set;
//
//@RestController
//@RequestMapping("/api/auth")
//public class AuthController {
//
//    private final AuthenticationManager authenticationManager;
//    private final UserRepository userRepository;
//    private final RoleRepository roleRepository;
//    private final PasswordEncoder passwordEncoder;
//    private final JwtTokenProvider jwtTokenProvider;
//    private final RateLimiter rateLimiter;
//
//    public AuthController(AuthenticationManager authenticationManager,
//                          UserRepository userRepository,
//                          RoleRepository roleRepository,
//                          PasswordEncoder passwordEncoder,
//                          JwtTokenProvider jwtTokenProvider,
//                          RateLimiter rateLimiter) {
//        this.authenticationManager = authenticationManager;
//        this.userRepository = userRepository;
//        this.roleRepository = roleRepository;
//        this.passwordEncoder = passwordEncoder;
//        this.jwtTokenProvider = jwtTokenProvider;
//        this.rateLimiter = rateLimiter;
//    }
//
//    @PostMapping("/login")
//    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest,
//                                   @RequestHeader(value = "X-Forwarded-For", required = false) String ipAddress) {
//        // Apply rate limiting for login attempts
//        String clientIp = (ipAddress != null) ? ipAddress : "unknown";
//        if (!rateLimiter.tryAcquire(clientIp + ":login")) {
//            return new ResponseEntity<>("Too many login attempts. Please try again later.", HttpStatus.TOO_MANY_REQUESTS);
//        }
//
//        Authentication authentication = authenticationManager.authenticate(
//                new UsernamePasswordAuthenticationToken(
//                        loginRequest.getUsernameOrEmail(),
//                        loginRequest.getPassword()
//                )
//        );
//
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//
//        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
//        String token = jwtTokenProvider.generateToken(userDetails);
//        String refreshToken = jwtTokenProvider.generateRefreshToken(userDetails);
//
//        return ResponseEntity.ok(new JwtAuthResponse(token, refreshToken, "Bearer"));
//    }
//
//    @PostMapping("/refresh")
//    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshTokenRequest refreshTokenRequest) {
//        String refreshToken = refreshTokenRequest.getRefreshToken();
//
//        // Validate refresh token
//        if (!jwtTokenProvider.validateToken(refreshToken)) {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
//        }
//
//        // Extract username from refresh token
//        String username = jwtTokenProvider.extractUsername(refreshToken);
//
//        // Load user details
//        UserDetails userDetails = userRepository.findByUsername(username)
//                .map(user -> new org.springframework.security.core.userdetails.User(
//                        user.getUsername(),
//                        user.getPassword(),
//                        user.isEnabled(),
//                        true,
//                        true,
//                        !user.isLocked(),
//                        user.getRoles().stream()
//                                .map(role -> new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_" + role.getName()))
//                                .collect(java.util.stream.Collectors.toList())
//                ))
//                .orElseThrow(() -> new RuntimeException("User not found with username: " + username));
//
//        // Generate new tokens
//        String newAccessToken = jwtTokenProvider.generateToken(userDetails);
//        String newRefreshToken = jwtTokenProvider.generateRefreshToken(userDetails);
//
//        return ResponseEntity.ok(new JwtAuthResponse(newAccessToken, newRefreshToken, "Bearer"));
//    }
//
//    @PostMapping("/signup")
//    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
//        // Check if username exists
//        if (userRepository.existsByUsername(signupRequest.getUsername())) {
//            return ResponseEntity.badRequest().body("Username is already taken");
//        }
//
//        // Check if email exists
//        if (userRepository.existsByEmail(signupRequest.getEmail())) {
//            return ResponseEntity.badRequest().body("Email is already in use");
//        }
//
//        // Apply password policy
//        if (!isPasswordStrong(signupRequest.getPassword())) {
//            return ResponseEntity.badRequest().body(
//                    "Password must be at least 12 characters long and include uppercase, lowercase, numbers, and special characters");
//        }
//
//        // Create user account
//        User user = new User(
//                signupRequest.getUsername(),
//                signupRequest.getEmail(),
//                passwordEncoder.encode(signupRequest.getPassword())
//        );
//
//        // Set user roles
//        Set<Role> roles = new HashSet<>();
//        Role userRole = roleRepository.findByName("USER")
//                .orElseThrow(() -> new RuntimeException("Error: Role USER is not found."));
//        roles.add(userRole);
//        user.setRoles(roles);
//
//        userRepository.save(user);
//
//        return ResponseEntity.ok("User registered successfully");
//    }
//
//    @PostMapping("/logout")
//    public ResponseEntity<?> logout(@AuthenticationPrincipal UserDetails userDetails) {
//        // For stateless JWT authentication, client-side should discard token
//        // Server-side you can implement a token blacklist if needed
//        return ResponseEntity.ok("Logged out successfully");
//    }
//
//    // Password strength validation
//    private boolean isPasswordStrong(String password) {
//        // At least 12 chars
//        if (password.length() < 12) return false;
//
//        // Check for uppercase, lowercase, digit, and special char
//        boolean hasUppercase = false;
//        boolean hasLowercase = false;
//        boolean hasDigit = false;
//        boolean hasSpecial = false;
//
//        for (char c : password.toCharArray()) {
//            if (Character.isUpperCase(c)) hasUppercase = true;
//            else if (Character.isLowerCase(c)) hasLowercase = true;
//            else if (Character.isDigit(c)) hasDigit = true;
//            else hasSpecial = true;
//        }
//
//        return hasUppercase && hasLowercase && hasDigit && hasSpecial;
//    }
//}
//
//// STEP 10: RATE LIMITER IMPLEMENTATION (OWASP DEFENSE)
//
//package com.example.security.util;
//
//import org.springframework.stereotype.Component;
//import java.util.Map;
//import java.util.concurrent.ConcurrentHashMap;
//import java.util.concurrent.Executors;
//import java.util.concurrent.ScheduledExecutorService;
//import java.util.concurrent.TimeUnit;
//import java.util.concurrent.atomic.AtomicInteger;
//
//@Component
//public class RateLimiter {
//    private final Map<String, AtomicInteger> attemptsMap = new ConcurrentHashMap<>();
//    private final Map<String, Long> blockMap = new ConcurrentHashMap<>();
//
//    private static final int MAX_ATTEMPTS = 5;
//    private static final long BLOCK_DURATION_MS = 15 * 60 * 1000; // 15 minutes
//    private static final long RESET_WINDOW_MS = 5 * 60 * 1000;     // 5 minutes
//
//    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
//
//    public RateLimiter() {
//        // Schedule cleanup of old entries
//        scheduler.scheduleAtFixedRate(this::cleanupExpiredEntries, 10, 10, TimeUnit.MINUTES);
//    }
//
//    public boolean tryAcquire(String key) {
//        // Check if client is blocked
//        if (blockMap.containsKey(key)) {
//            long blockExpiry = blockMap.get(key);
//            if (System.currentTimeMillis() < blockExpiry) {
//                return false; // Still blocked
//            } else {
//                // Block period expired
//                blockMap.remove(key);
//                attemptsMap.remove(key);
//            }
//        }
//
//        // Track attempt
//        AtomicInteger attempts = attemptsMap.computeIfAbsent(key, k -> new AtomicInteger(0));
//        int currentAttempts = attempts.incrementAndGet();
//
//        // Schedule reset of attempts counter
//        scheduler.schedule(() -> {
//            AtomicInteger counter = attemptsMap.get(key);
//            if (counter != null && counter.get() == currentAttempts) {
//                attemptsMap.remove(key);
//            }
//        }, RESET_WINDOW_MS, TimeUnit.MILLISECONDS);
//
//        // Check if limit exceeded
//        if (currentAttempts > MAX_ATTEMPTS) {
//            // Block the client
//            blockMap.put(key, System.currentTimeMillis() + BLOCK_DURATION_MS);
//            return false;
//        }
//
//        return true;
//    }
//
//    private void cleanupExpiredEntries() {
//        long now = System.currentTimeMillis();
//
//        // Remove expired blocks
//        blockMap.entrySet().removeIf(entry -> entry.getValue() < now);
//    }
//}
//
//// STEP 11: APPLICATION PROPERTIES
//// Create a file named application.properties (or application.yml) in src/main/resources:
//
///*
//# Server properties
//server.port=8080
//
//# Database properties
//spring.datasource.url=jdbc:postgresql://localhost:5432/myapp
//spring.datasource.username=postgres
//spring.datasource.password=securepassword
//spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect
//spring.jpa.hibernate.ddl-auto=update
//
//# JWT properties (use environment variables in production)
//app.jwt.secret=YourVeryLongAndSecureJwtSecretKeyThatIsAtLeast256BitsToBeConsideredSecure
//app.jwt.expiration=3600000        # 1 hour
//app.jwt.refresh-expiration=86400000  # 24 hours
//
//# Security properties
//spring.security.filter.order=10
//
//# Set secure flag for cookies
//server.servlet.session.cookie.secure=true
//server.servlet.session.cookie.http-only=true
//
//# XSS protection is enabled by default with mode block
//server.servlet.encoding.force=true
//
//# SSL configuration
//server.ssl.enabled=true
//server.ssl.key-store=classpath:keystore.p12
//server.ssl.key-store-password=your-keystore-password
//server.ssl.key-store-type=PKCS12
//server.ssl.key-alias=tomcat
//
//# OWASP recommended headers
//server.compression.enabled=true
//server.compression.mime-types=text/html,text/xml,text/plain,text/css,application/javascript,application/json
//server.compression.min-response-size=1024
//
//# Logging
//logging.level.org.springframework.security=INFO
//logging.level.com.example=DEBUG
//
//# Actuator endpoints
//management.endpoints.web.exposure.include=health,info
//management.endpoint.health.show-details=when_authorized
//*/
//
//// STEP 12: REPOSITORIES
//
//package com.example.security.repository;
//
//import com.example.security.entity.User;
//import org.springframework.data.jpa.repository.JpaRepository;
//import org.springframework.stereotype.Repository;
//
//import java.util.Optional;
//
//@Repository
//public interface UserRepository extends JpaRepository<User, Long> {
//    Optional<User> findByUsername(String username);
//    Optional<User> findByEmail(String email);
//    Optional<User> findByUsernameOrEmail(String username, String email);
//    Boolean existsByUsername(String username);
//    Boolean existsByEmail(String email);
//}
//
//package com.example.security.repository;
//
//import com.example.security.entity.Role;
//import org.springframework.data.jpa.repository.JpaRepository;
//import org.springframework.stereotype.Repository;
//
//import java.util.Optional;
//
//@Repository
//public interface RoleRepository extends JpaRepository<Role, Long> {
//    Optional<Role> findByName(String name);
//}
//
//// STEP 13: RESPONSE/REQUEST PAYLOADS
//
//package com.example.security.payload;
//
//import jakarta.validation.constraints.Email;
//import jakarta.validation.constraints.NotBlank;
//import jakarta.validation.constraints.Size;
//
//public class SignupRequest {
//    @NotBlank
//    @Size(min = 3, max = 50)
//    private String username;
//
//    @NotBlank
//    @Size(max = 100)
//    @Email
//    private String email;
//
//    @NotBlank
//    @Size(min = 12, max = 120)
//    private String password;
//
//    // Getters and Setters
//    public String getUsername() {
//        return username;
//    }
//
//    public void setUsername(String username) {
//        this.username = username;
//    }
//
//    public String getEmail() {
//        return email;
//    }
//
//    public void setEmail(String email) {
//        this.email = email;
//    }
//
//    public String getPassword() {
//        return password;
//    }
//
//    public void setPassword(String password) {
//        this.password = password;
//    }
//}
//
//package com.example.security.payload;
//
//import jakarta.validation.constraints.NotBlank;
//
//public class LoginRequest {
//    @NotBlank
//    private String usernameOrEmail;
//
//    @NotBlank
//    private String password;
//
//    // Getters and Setters
//    public String getUsernameOrEmail() {
//        return usernameOrEmail;
//    }
//
//    public void setUsernameOrEmail(String usernameOrEmail) {
//        this.usernameOrEmail = usernameOrEmail;
//    }
//
//    public String getPassword() {
//        return password;
//    }
//
//    public void setPassword(String password) {
//        this.password = password;
//    }
//}
//
//package com.example.security.payload;
//
//import jakarta.validation.constraints.NotBlank;
//
//public class RefreshTokenRequest {
//    @NotBlank
//    private String refreshToken;
//
//    // Getters and Setters
//    public String getRefreshToken() {
//        return refreshToken;
//    }
//
//    public void setRefreshToken(String refreshToken) {
//        this.refreshToken = refreshToken;
//    }
//}
//
//package com.example.security.payload;
//
//public class JwtAuthResponse {
//    private String accessToken;
//    private String refreshToken;
//    private String tokenType;
//
//    public JwtAuthResponse(String accessToken, String refreshToken, String tokenType) {
//        this.accessToken = accessToken;
//        this.refreshToken = refreshToken;
//        this.tokenType = tokenType;
//    }
//
//    // Getters and Setters
//    public String getAccessToken() {
//        return accessToken;
//    }
//
//    public void setAccessToken(String accessToken) {
//        this.accessToken = accessToken;
//    }
//
//    public String getRefreshToken() {
//        return refreshToken;
//    }
//
//    public void setRefreshToken(String refreshToken) {
//        this.refreshToken = refreshToken;
//    }
//
//    public String getTokenType() {
//        return tokenType;
//    }
//
//    public void setTokenType(String tokenType) {
//        this.tokenType = tokenType;
//    }
//}
//
//// STEP 14: PROTECTED RESOURCE EXAMPLE
//
//package com.example.security.controller;
//
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.access.prepost.PreAuthorize;
//import org.springframework.security.core.annotation.AuthenticationPrincipal;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RestController;
//
//@RestController
//@RequestMapping("/api/secure")
//public class SecureResourceController {
//
//    @GetMapping("/user")
//    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
//    public ResponseEntity<?> getUserContent(@AuthenticationPrincipal UserDetails userDetails) {
//        return ResponseEntity.ok("User content - Hello, " + userDetails.getUsername());
//    }
//
//    @GetMapping("/admin")
//    @PreAuthorize("hasRole('ADMIN')")
//    public ResponseEntity<?> getAdminContent() {
//        return ResponseEntity.ok("Admin content - Restricted area");
//    }
//}
//
//// STEP 15: DATABASE INITIALIZATION
//
//package com.example.security.config;
//
//import com.example.security.entity.Role;
//import com.example.security.repository.RoleRepository;
//import org.springframework.boot.CommandLineRunner;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//
//@Configuration
//public class DbInitializer {
//
//    @Bean
//    public CommandLineRunner initDatabase(RoleRepository roleRepository) {
//        return args -> {
//            // Initialize roles if they don't exist
//            if (roleRepository.count() == 0) {
//                roleRepository.save(new Role("USER"));
//                roleRepository.save(new Role("ADMIN"));
//                roleRepository.save(new Role("MODERATOR"));
//                System.out.println("Roles initialized");
//            }
//        };
//    }
//}
//
//// STEP 16: SECURITY AUDIT LOGGING
//
//package com.example.security.audit;
//
//import jakarta.servlet.http.HttpServletRequest;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.context.event.EventListener;
//import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
//import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.web.authentication.WebAuthenticationDetails;
//import org.springframework.stereotype.Component;
//import org.springframework.web.context.request.RequestContextHolder;
//import org.springframework.web.context.request.ServletRequestAttributes;
//
//@Component
//public class SecurityAuditListener {
//    private static final Logger logger = LoggerFactory.getLogger(SecurityAuditListener.class);
//
//    @EventListener
//    public void onSuccess(AuthenticationSuccessEvent success) {
//        Object principal = success.getAuthentication().getPrincipal();
//        String username = "";
//
//        if (principal instanceof UserDetails) {
//            username = ((UserDetails) principal).getUsername();
//        } else {
//            username = principal.toString();
//        }
//
//        String ipAddress = extractIpAddress();
//
//        logger.info("Successful authentication - Username: {}, IP: {}", username, ipAddress);
//    }
//
//    @EventListener
//    public void onFailure(AbstractAuthenticationFailureEvent failures) {
//        String username = failures.getAuthentication().getName();
//        String ipAddress = extractIpAddress();
//        String failureMessage = failures.getException().getMessage();
//
//        logger.warn("Failed authentication - Username: {}, IP: {}, Reason: {}",
//                username, ipAddress, failureMessage);
//    }
//
//    private String extractIpAddress() {
//        try {
//            ServletRequestAttributes attr = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
//            HttpServletRequest request = attr.getRequest();
//
//            // Check for proxied IP
//            String forwardedIp = request.getHeader("X-Forwarded-For");
//            if (forwardedIp != null) {
//                // The first IP in the list is the client IP
//                return forwardedIp.split(",")[0].trim();
//            }
//
//            // Direct IP
//            return request.getRemoteAddr();
//        } catch (Exception e) {
//            return "unknown";
//        }
//    }
//}
//
//// STEP 17: CUSTOM REMEMBER ME IMPLEMENTATION (OPTIONAL)
//
//package com.example.security.service;
//
//import jakarta.servlet.http.Cookie;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
//import org.springframework.security.web.authentication.rememberme.InvalidCookieException;
//import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationException;
//import org.springframework.stereotype.Service;
//
//import javax.crypto.SecretKeyFactory;
//import javax.crypto.spec.PBEKeySpec;
//import java.security.SecureRandom;
//import java.time.Duration;
//import java.util.Arrays;
//import java.util.Base64;
//import java.util.Optional;
//
//@Service
//public class EnhancedRememberMeService extends AbstractRememberMeServices {
//
//    private static final SecureRandom RANDOM = new SecureRandom();
//    private static final int TOKEN_LENGTH = 32;
//    private static final int ITERATIONS = 10000;
//    private static final int KEY_LENGTH = 256;
//    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
//
//    private final Duration tokenValidityDuration = Duration.ofDays(14); // 14 days
//
//    // Repository to store tokens securely
//    private final RememberMeTokenRepository tokenRepository;
//
//    public EnhancedRememberMeService(String key, UserDetailsService userDetailsService,
//                                     RememberMeTokenRepository tokenRepository) {
//        super(key, userDetailsService);
//        this.tokenRepository = tokenRepository;
//
//        // Configure cookie security
//        setCookieName("remember-me");
//        setParameter("remember-me");
//        setUseSecureCookie(true);
//        setTokenValiditySeconds((int) tokenValidityDuration.toSeconds());
//    }
//
//    @Override
//    protected void onLoginSuccess(HttpServletRequest request, HttpServletResponse response,
//                                  Authentication successfulAuthentication) {
//        UserDetails userDetails = (UserDetails) successfulAuthentication.getPrincipal();
//        String username = userDetails.getUsername();
//
//        // Generate a new token
//        String series = generateRandomString();
//        String token = generateRandomString();
//
//        // Hash the token for storage
//        String hashedToken = hashToken(token);
//
//        // Store token in repository
//        RememberMeToken rememberMeToken = new RememberMeToken();
//        rememberMeToken.setUsername(username);
//        rememberMeToken.setSeries(series);
//        rememberMeToken.setTokenValue(hashedToken);
//        rememberMeToken.setExpiryDate(new java.util.Date(System.currentTimeMillis() + tokenValidityDuration.toMillis()));
//
//        tokenRepository.save(rememberMeToken);
//
//        // Set cookie with series and token
//        String cookieValue = encodeCookie(new String[]{series, token});
//
//        // Create a secure cookie
//        Cookie cookie = new Cookie(getCookieName(), cookieValue);
//        cookie.setMaxAge(getTokenValiditySeconds());
//        cookie.setPath(getCookiePath(request));
//        cookie.setSecure(isUseSecureCookie());
//        cookie.setHttpOnly(true);
//
//        response.addCookie(cookie);
//    }
//
//    @Override
//    protected UserDetails processAutoLoginCookie(String[] cookieTokens, HttpServletRequest request,
//                                                 HttpServletResponse response) {
//        if (cookieTokens.length != 2) {
//            throw new InvalidCookieException("Cookie token did not contain 2 tokens");
//        }
//
//        String series = cookieTokens[0];
//        String token = cookieTokens[1];
//
//        // Retrieve the token from the repository
//        Optional<RememberMeToken> storedToken = tokenRepository.findBySeries(series);
//
//        if (storedToken.isEmpty()) {
//            throw new RememberMeAuthenticationException("No persistent token found for series: " + series);
//        }
//
//        RememberMeToken persistentToken = storedToken.get();
//
//        // Check token expiration
//        if (persistentToken.getExpiryDate().before(new java.util.Date())) {
//            tokenRepository.delete(persistentToken);
//            throw new RememberMeAuthenticationException("Remember-me token has expired");
//        }
//
//        // Verify the token
//        if (!verifyToken(token, persistentToken.getTokenValue())) {
//            // Potential security breach
//            tokenRepository.deleteBySeries(series);
//            throw new RememberMeAuthenticationException("Invalid remember-me token");
//        }
//
//        // Generate a new token
//        String newToken = generateRandomString();
//        String hashedNewToken = hashToken(newToken);
//
//        // Update token in repository
//        persistentToken.setTokenValue(hashedNewToken);
//        persistentToken.setExpiryDate(new java.util.Date(System.currentTimeMillis() + tokenValidityDuration.toMillis()));
//        tokenRepository.save(persistentToken);
//
//        // Update cookie
//        String cookieValue = encodeCookie(new String[]{series, newToken});
//        Cookie cookie = new Cookie(getCookieName(), cookieValue);
//        cookie.setMaxAge(getTokenValiditySeconds());
//        cookie.setPath(getCookiePath(request));
//        cookie.setSecure(isUseSecureCookie());
//        cookie.setHttpOnly(true);
//
//        response.addCookie(cookie);
//
//        // Return user details
//        return getUserDetailsService().loadUserByUsername(persistentToken.getUsername());
//    }
//
//    @Override
//    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//        super.logout(request, response, authentication);
//
//        // Extract series from cookies
//        Cookie[] cookies = request.getCookies();
//        if (cookies != null) {
//            Optional<Cookie> rememberMeCookie = Arrays.stream(cookies)
//                    .filter(cookie -> getCookieName().equals(cookie.getName()))
//                    .findFirst();
//
//            if (rememberMeCookie.isPresent()) {
//                try {
//                    String[] cookieTokens = decodeCookie(rememberMeCookie.get().getValue());
//                    if (cookieTokens.length == 2) {
//                        String series = cookieTokens[0];
//                        // Remove token from repository
//                        tokenRepository.deleteBySeries(series);
//                    }
//                } catch (Exception e) {
//                    // Ignore decoding errors
//                }
//            }
//        }
//    }
//
//    // Helper methods
//    private String generateRandomString() {
//        byte[] bytes = new byte[TOKEN_LENGTH];
//        RANDOM.nextBytes(bytes);
//        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
//    }
//
//    private String hashToken(String token) {
//        try {
//            byte[] salt = new byte[16];
//            RANDOM.nextBytes(salt);
//
//            PBEKeySpec spec = new PBEKeySpec(token.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
//            SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
//            byte[] hash = skf.generateSecret(spec).getEncoded();
//
//            byte[] combined = new byte[salt.length + hash.length];
//            System.arraycopy(salt, 0, combined, 0, salt.length);
//            System.arraycopy(hash, 0, combined, salt.length, hash.length);
//
//            return Base64.getEncoder().encodeToString(combined);
//        } catch (Exception e) {
//            throw new RuntimeException("Error hashing token", e);
//        }
//    }
//
//    private boolean verifyToken(String token, String hashedToken) {
//        try {
//            byte[] combined = Base64.getDecoder().decode(hashedToken);
//            byte[] salt = Arrays.copyOfRange(combined, 0, 16);
//            byte[] hash = Arrays.copyOfRange(combined, 16, combined.length);
//
//            PBEKeySpec spec = new PBEKeySpec(token.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
//            SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
//            byte[] testHash = skf.generateSecret(spec).getEncoded();
//
//            return Arrays.equals(hash, testHash);
//        } catch (Exception e) {
//            return false;
//        }
//    }
//}
//
//// STEP 18: MAIN APPLICATION CLASS
//
//package com.example.security;
//
//import org.springframework.boot.SpringApplication;
//import org.springframework.boot.autoconfigure.SpringBootApplication;
//import org.springframework.boot.web.servlet.ServletComponentScan;
//import org.springframework.context.annotation.Bean;
//import org.springframework.web.servlet.HandlerInterceptor;
//import org.springframework.web.servlet.config.annotation.CorsRegistry;
//import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
//import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
//
//@SpringBootApplication
//@ServletComponentScan
//public class SecureApplication {
//
//    public static void main(String[] args) {
//        SpringApplication.run(SecureApplication.class, args);
//    }
//
//    // Global CORS configuration
//    @Bean
//    public WebMvcConfigurer corsConfigurer() {
//        return new WebMvcConfigurer() {
//            @Override
//            public void addCorsMappings(CorsRegistry registry) {
//                registry.addMapping("/**")
//                        .allowedOrigins("https://yourdomain.com")
//                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
//                        .allowedHeaders("*")
//                        .allowCredentials(true)
//                        .maxAge(3600);
//            }
//
//            @Override
//            public void addInterceptors(InterceptorRegistry registry) {
//                // Add security headers to all responses
//                registry.addInterceptor(securityHeadersInterceptor());
//            }
//        };
//    }
//
//    // Security headers interceptor
//    @Bean
//    public HandlerInterceptor securityHeadersInterceptor() {
//        return new SecurityHeadersInterceptor();
//    }
//}
//
//// STEP 19: SECURITY HEADERS INTERCEPTOR
//
//package com.example.security;
//
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.web.servlet.HandlerInterceptor;
//
//public class SecurityHeadersInterceptor implements HandlerInterceptor {
//
//    @Override
//    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
//        // Add security headers to all responses
//
//        // Content Security Policy
//        response.setHeader("Content-Security-Policy",
//                "default-src 'self'; script-src 'self'; object-src 'none'; img-src 'self' data:; " +
//                        "style-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
//
//        // Prevent MIME type sniffing
//        response.setHeader("X-Content-Type-Options", "nosniff");
//
//        // XSS Protection
//        response.setHeader("X-XSS-Protection", "1; mode=block");
//
//        // Don't cache sensitive information
//        response.setHeader("Cache-Control", "no-store, max-age=0, must-revalidate");
//        response.setHeader("Pragma", "no-cache");
//        response.setHeader("Expires", "0");
//
//        // Strict Transport Security (HSTS)
//        response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
//
//        // Referrer Policy
//        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
//
//        // Feature Policy / Permissions Policy
//        response.setHeader("Permissions-Policy",
//                "accelerometer=(), camera=(), geolocation=(), gyroscope=(), " +
//                        "magnetometer=(), microphone=(), payment=(), usb=()");
//
//        return true;
//    }
//}
//charset=UTF-8
//server.servlet.encoding.enabled=true
//server.servlet.encoding.