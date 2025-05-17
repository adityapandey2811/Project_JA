///*
// * Spring Boot Security Authentication System
// * Features: Login, Registration, Logout
// */
//
//// First, let's add the necessary dependencies to your pom.xml
//// Add these dependencies to your existing pom.xml file
//
///*
//<dependencies>
//    <!-- Spring Boot Starter -->
//    <dependency>
//        <groupId>org.springframework.boot</groupId>
//        <artifactId>spring-boot-starter-web</artifactId>
//    </dependency>
//
//    <!-- Spring Security -->
//    <dependency>
//        <groupId>org.springframework.boot</groupId>
//        <artifactId>spring-boot-starter-security</artifactId>
//    </dependency>
//
//    <!-- Spring Data JPA -->
//    <dependency>
//        <groupId>org.springframework.boot</groupId>
//        <artifactId>spring-boot-starter-data-jpa</artifactId>
//    </dependency>
//
//    <!-- Thymeleaf for views -->
//    <dependency>
//        <groupId>org.springframework.boot</groupId>
//        <artifactId>spring-boot-starter-thymeleaf</artifactId>
//    </dependency>
//
//    <!-- Thymeleaf Spring Security integration -->
//    <dependency>
//        <groupId>org.thymeleaf.extras</groupId>
//        <artifactId>thymeleaf-extras-springsecurity6</artifactId>
//    </dependency>
//
//    <!-- H2 Database (for demonstration) -->
//    <dependency>
//        <groupId>com.h2database</groupId>
//        <artifactId>h2</artifactId>
//        <scope>runtime</scope>
//    </dependency>
//
//    <!-- Lombok to reduce boilerplate code -->
//    <dependency>
//        <groupId>org.projectlombok</groupId>
//        <artifactId>lombok</artifactId>
//        <optional>true</optional>
//    </dependency>
//
//    <!-- Validation -->
//    <dependency>
//        <groupId>org.springframework.boot</groupId>
//        <artifactId>spring-boot-starter-validation</artifactId>
//    </dependency>
//</dependencies>
//*/
//
//// 1. User Entity
//package com.example.security.model;
//
//import jakarta.persistence.*;
//import lombok.AllArgsConstructor;
//import lombok.Data;
//import lombok.NoArgsConstructor;
//
//import java.util.HashSet;
//import java.util.Set;
//
//@Entity
//@Table(name = "users")
//@Data
//@NoArgsConstructor
//@AllArgsConstructor
//public class User {
//    @Id
//    @GeneratedValue(strategy = GenerationType.IDENTITY)
//    private Long id;
//
//    @Column(nullable = false, unique = true)
//    private String username;
//
//    @Column(nullable = false)
//    private String password;
//
//    @Column(nullable = false, unique = true)
//    private String email;
//
//    @Column(nullable = false)
//    private String fullName;
//
//    @ElementCollection(fetch = FetchType.EAGER)
//    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
//    @Column(name = "role")
//    private Set<String> roles = new HashSet<>();
//
//    private boolean enabled = true;
//}
//
//// 2. User Repository
//package com.example.security.repository;
//
//import com.example.security.model.User;
//import org.springframework.data.jpa.repository.JpaRepository;
//
//import java.util.Optional;
//
//public interface UserRepository extends JpaRepository<User, Long> {
//    Optional<User> findByUsername(String username);
//    boolean existsByUsername(String username);
//    boolean existsByEmail(String email);
//}
//
//// 3. Registration DTO (Data Transfer Object)
//package com.example.security.dto;
//
//import jakarta.validation.constraints.Email;
//import jakarta.validation.constraints.NotBlank;
//import jakarta.validation.constraints.Size;
//import lombok.Data;
//
//@Data
//public class RegistrationDto {
//    @NotBlank(message = "Username is required")
//    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
//    private String username;
//
//    @NotBlank(message = "Password is required")
//    @Size(min = 6, max = 40, message = "Password must be between 6 and 40 characters")
//    private String password;
//
//    @NotBlank(message = "Confirm password is required")
//    private String confirmPassword;
//
//    @NotBlank(message = "Email is required")
//    @Email(message = "Email should be valid")
//    private String email;
//
//    @NotBlank(message = "Full name is required")
//    private String fullName;
//}
//
//// 4. User Service
//package com.example.security.service;
//
//import com.example.security.dto.RegistrationDto;
//import com.example.security.model.User;
//import com.example.security.repository.UserRepository;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Service;
//
//import java.util.Collections;
//
//@Service
//public class UserService {
//    @Autowired
//    private UserRepository userRepository;
//
//    @Autowired
//    private PasswordEncoder passwordEncoder;
//
//    public User registerNewUser(RegistrationDto registrationDto) {
//        if (userRepository.existsByUsername(registrationDto.getUsername())) {
//            throw new RuntimeException("Username is already taken");
//        }
//
//        if (userRepository.existsByEmail(registrationDto.getEmail())) {
//            throw new RuntimeException("Email is already in use");
//        }
//
//        if (!registrationDto.getPassword().equals(registrationDto.getConfirmPassword())) {
//            throw new RuntimeException("Passwords do not match");
//        }
//
//        User user = new User();
//        user.setUsername(registrationDto.getUsername());
//        user.setPassword(passwordEncoder.encode(registrationDto.getPassword()));
//        user.setEmail(registrationDto.getEmail());
//        user.setFullName(registrationDto.getFullName());
//        user.setRoles(Collections.singleton("ROLE_USER"));
//        user.setEnabled(true);
//
//        return userRepository.save(user);
//    }
//}
//
//// 5. Custom User Details Service
//package com.example.security.service;
//
//import com.example.security.model.User;
//import com.example.security.repository.UserRepository;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.stereotype.Service;
//
//import java.util.stream.Collectors;
//
//@Service
//public class CustomUserDetailsService implements UserDetailsService {
//    @Autowired
//    private UserRepository userRepository;
//
//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        User user = userRepository.findByUsername(username)
//                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
//
//        return org.springframework.security.core.userdetails.User.builder()
//                .username(user.getUsername())
//                .password(user.getPassword())
//                .authorities(user.getRoles().stream()
//                        .map(SimpleGrantedAuthority::new)
//                        .collect(Collectors.toList()))
//                .disabled(!user.isEnabled())
//                .build();
//    }
//}
//
//// 6. Security Configuration
//package com.example.security.config;
//
//import com.example.security.service.CustomUserDetailsService;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
//
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig {
//    @Autowired
//    private CustomUserDetailsService userDetailsService;
//
//    @Bean
//    public static PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//
//    @Autowired
//    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(userDetailsService)
//                .passwordEncoder(passwordEncoder());
//    }
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(authorize ->
//                        authorize
//                                .requestMatchers("/", "/register/**", "/css/**", "/js/**").permitAll()
//                                .requestMatchers("/admin/**").hasRole("ADMIN")
//                                .anyRequest().authenticated()
//                )
//                .formLogin(form ->
//                        form
//                                .loginPage("/login")
//                                .loginProcessingUrl("/login")
//                                .defaultSuccessUrl("/dashboard")
//                                .permitAll()
//                )
//                .logout(logout ->
//                        logout
//                                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
//                                .permitAll()
//                );
//
//        return http.build();
//    }
//}
//
//// 7. Authentication Controller
//package com.example.security.controller;
//
//import com.example.security.dto.RegistrationDto;
//import com.example.security.service.UserService;
//
//import jakarta.validation.Valid;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.stereotype.Controller;
//import org.springframework.ui.Model;
//import org.springframework.validation.BindingResult;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.ModelAttribute;
//import org.springframework.web.bind.annotation.PostMapping;
//
//@Controller
//public class AuthController {
//    @Autowired
//    private UserService userService;
//
//    // Login form
//    @GetMapping("/login")
//    public String login() {
//        return "login";
//    }
//
//    // Registration form
//    @GetMapping("/register")
//    public String showRegistrationForm(Model model) {
//        model.addAttribute("user", new RegistrationDto());
//        return "register";
//    }
//
//    // Registration processing
//    @PostMapping("/register")
//    public String registerUser(@Valid @ModelAttribute("user") RegistrationDto registrationDto,
//                               BindingResult result,
//                               Model model) {
//        if (result.hasErrors()) {
//            return "register";
//        }
//
//        try {
//            userService.registerNewUser(registrationDto);
//            model.addAttribute("successMessage", "Registration successful! Please login.");
//            return "redirect:/login?registered";
//        } catch (Exception e) {
//            model.addAttribute("errorMessage", e.getMessage());
//            return "register";
//        }
//    }
//
//    // Dashboard page (requires authentication)
//    @GetMapping("/dashboard")
//    public String dashboard() {
//        return "dashboard";
//    }
//
//    // Home page
//    @GetMapping("/")
//    public String home() {
//        return "index";
//    }
//}
//
//// 8. Thymeleaf Templates
//// 8.1 login.html (src/main/resources/templates/login.html)
///*
//<!DOCTYPE html>
//<html xmlns:th="http://www.thymeleaf.org">
//<head>
//    <meta charset="UTF-8">
//    <title>Login</title>
//    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css">
//</head>
//<body>
//    <div class="container mt-5">
//        <div class="row justify-content-center">
//            <div class="col-md-6">
//                <div class="card">
//                    <div class="card-header">
//                        <h3 class="text-center">Login</h3>
//                    </div>
//                    <div class="card-body">
//                        <div th:if="${param.error}" class="alert alert-danger">
//                            Invalid username or password.
//                        </div>
//                        <div th:if="${param.logout}" class="alert alert-success">
//                            You have been logged out.
//                        </div>
//                        <div th:if="${param.registered}" class="alert alert-success">
//                            Registration successful! Please login.
//                        </div>
//                        <form th:action="@{/login}" method="post">
//                            <div class="mb-3">
//                                <label for="username" class="form-label">Username</label>
//                                <input type="text" id="username" name="username" class="form-control" required>
//                            </div>
//                            <div class="mb-3">
//                                <label for="password" class="form-label">Password</label>
//                                <input type="password" id="password" name="password" class="form-control" required>
//                            </div>
//                            <div class="d-grid gap-2">
//                                <button type="submit" class="btn btn-primary">Login</button>
//                            </div>
//                        </form>
//                    </div>
//                    <div class="card-footer text-center">
//                        <p>Don't have an account? <a th:href="@{/register}">Register</a></p>
//                    </div>
//                </div>
//            </div>
//        </div>
//    </div>
//</body>
//</html>
//*/
//
//// 8.2 register.html (src/main/resources/templates/register.html)
///*
//<!DOCTYPE html>
//<html xmlns:th="http://www.thymeleaf.org">
//<head>
//    <meta charset="UTF-8">
//    <title>Registration</title>
//    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css">
//</head>
//<body>
//    <div class="container mt-5">
//        <div class="row justify-content-center">
//            <div class="col-md-6">
//                <div class="card">
//                    <div class="card-header">
//                        <h3 class="text-center">Registration</h3>
//                    </div>
//                    <div class="card-body">
//                        <div th:if="${errorMessage}" class="alert alert-danger" th:text="${errorMessage}"></div>
//                        <form th:action="@{/register}" th:object="${user}" method="post">
//                            <div class="mb-3">
//                                <label for="username" class="form-label">Username</label>
//                                <input type="text" id="username" th:field="*{username}" class="form-control"
//                                       th:classappend="${#fields.hasErrors('username')} ? 'is-invalid' : ''">
//                                <div class="invalid-feedback" th:if="${#fields.hasErrors('username')}"
//                                     th:errors="*{username}"></div>
//                            </div>
//                            <div class="mb-3">
//                                <label for="email" class="form-label">Email</label>
//                                <input type="email" id="email" th:field="*{email}" class="form-control"
//                                       th:classappend="${#fields.hasErrors('email')} ? 'is-invalid' : ''">
//                                <div class="invalid-feedback" th:if="${#fields.hasErrors('email')}"
//                                     th:errors="*{email}"></div>
//                            </div>
//                            <div class="mb-3">
//                                <label for="fullName" class="form-label">Full Name</label>
//                                <input type="text" id="fullName" th:field="*{fullName}" class="form-control"
//                                       th:classappend="${#fields.hasErrors('fullName')} ? 'is-invalid' : ''">
//                                <div class="invalid-feedback" th:if="${#fields.hasErrors('fullName')}"
//                                     th:errors="*{fullName}"></div>
//                            </div>
//                            <div class="mb-3">
//                                <label for="password" class="form-label">Password</label>
//                                <input type="password" id="password" th:field="*{password}" class="form-control"
//                                       th:classappend="${#fields.hasErrors('password')} ? 'is-invalid' : ''">
//                                <div class="invalid-feedback" th:if="${#fields.hasErrors('password')}"
//                                     th:errors="*{password}"></div>
//                            </div>
//                            <div class="mb-3">
//                                <label for="confirmPassword" class="form-label">Confirm Password</label>
//                                <input type="password" id="confirmPassword" th:field="*{confirmPassword}" class="form-control"
//                                       th:classappend="${#fields.hasErrors('confirmPassword')} ? 'is-invalid' : ''">
//                                <div class="invalid-feedback" th:if="${#fields.hasErrors('confirmPassword')}"
//                                     th:errors="*{confirmPassword}"></div>
//                            </div>
//                            <div class="d-grid gap-2">
//                                <button type="submit" class="btn btn-primary">Register</button>
//                            </div>
//                        </form>
//                    </div>
//                    <div class="card-footer text-center">
//                        <p>Already have an account? <a th:href="@{/login}">Login</a></p>
//                    </div>
//                </div>
//            </div>
//        </div>
//    </div>
//</body>
//</html>
//*/
//
//// 8.3 dashboard.html (src/main/resources/templates/dashboard.html)
///*
//<!DOCTYPE html>
//<html xmlns:th="http://www.thymeleaf.org"
//      xmlns:sec="http://www.thymeleaf.org/extras/spring-security">
//<head>
//    <meta charset="UTF-8">
//    <title>Dashboard</title>
//    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css">
//</head>
//<body>
//    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
//        <div class="container">
//            <a class="navbar-brand" href="#">My Application</a>
//            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
//                <span class="navbar-toggler-icon"></span>
//            </button>
//            <div class="collapse navbar-collapse" id="navbarNav">
//                <ul class="navbar-nav me-auto">
//                    <li class="nav-item">
//                        <a class="nav-link" th:href="@{/}">Home</a>
//                    </li>
//                    <li class="nav-item">
//                        <a class="nav-link active" th:href="@{/dashboard}">Dashboard</a>
//                    </li>
//                    <li class="nav-item" sec:authorize="hasRole('ADMIN')">
//                        <a class="nav-link" th:href="@{/admin}">Admin Panel</a>
//                    </li>
//                </ul>
//                <div class="d-flex">
//                    <span class="navbar-text me-3" sec:authentication="name"></span>
//                    <form th:action="@{/logout}" method="post">
//                        <button type="submit" class="btn btn-outline-light">Logout</button>
//                    </form>
//                </div>
//            </div>
//        </div>
//    </nav>
//
//    <div class="container mt-5">
//        <div class="row">
//            <div class="col-12">
//                <div class="alert alert-success">
//                    <h3>Welcome to your dashboard, <span sec:authentication="name"></span>!</h3>
//                    <p>You are successfully logged in.</p>
//                </div>
//
//                <div class="card">
//                    <div class="card-header">
//                        User Information
//                    </div>
//                    <div class="card-body">
//                        <p><strong>Username:</strong> <span sec:authentication="name"></span></p>
//                        <p><strong>Roles:</strong> <span sec:authentication="principal.authorities"></span></p>
//                    </div>
//                </div>
//            </div>
//        </div>
//    </div>
//
//    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
//</body>
//</html>
//*/
//
//// 8.4 index.html (src/main/resources/templates/index.html)
///*
//<!DOCTYPE html>
//<html xmlns:th="http://www.thymeleaf.org"
//      xmlns:sec="http://www.thymeleaf.org/extras/spring-security">
//<head>
//    <meta charset="UTF-8">
//    <title>Home</title>
//    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css">
//</head>
//<body>
//    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
//        <div class="container">
//            <a class="navbar-brand" href="#">My Application</a>
//            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
//                <span class="navbar-toggler-icon"></span>
//            </button>
//            <div class="collapse navbar-collapse" id="navbarNav">
//                <ul class="navbar-nav me-auto">
//                    <li class="nav-item">
//                        <a class="nav-link active" th:href="@{/}">Home</a>
//                    </li>
//                    <li class="nav-item" sec:authorize="isAuthenticated()">
//                        <a class="nav-link" th:href="@{/dashboard}">Dashboard</a>
//                    </li>
//                    <li class="nav-item" sec:authorize="hasRole('ADMIN')">
//                        <a class="nav-link" th:href="@{/admin}">Admin Panel</a>
//                    </li>
//                </ul>
//                <div class="d-flex">
//                    <div sec:authorize="!isAuthenticated()">
//                        <a th:href="@{/login}" class="btn btn-outline-light me-2">Login</a>
//                        <a th:href="@{/register}" class="btn btn-primary">Register</a>
//                    </div>
//                    <div sec:authorize="isAuthenticated()">
//                        <span class="navbar-text me-3" sec:authentication="name"></span>
//                        <form th:action="@{/logout}" method="post" class="d-inline">
//                            <button type="submit" class="btn btn-outline-light">Logout</button>
//                        </form>
//                    </div>
//                </div>
//            </div>
//        </div>
//    </nav>
//
//    <div class="container mt-5">
//        <div class="jumbotron">
//            <h1 class="display-4">Welcome to My Application</h1>
//            <p class="lead">This is a simple Spring Boot application with Spring Security.</p>
//            <hr class="my-4">
//            <p>It features user registration, login, and logout functionality.</p>
//            <div sec:authorize="!isAuthenticated()">
//                <a class="btn btn-primary btn-lg" th:href="@{/register}" role="button">Get Started</a>
//            </div>
//            <div sec:authorize="isAuthenticated()">
//                <a class="btn btn-primary btn-lg" th:href="@{/dashboard}" role="button">Go to Dashboard</a>
//            </div>
//        </div>
//    </div>
//
//    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
//</body>
//</html>
//*/
//
//// 9. Configuration for H2 Database
//// src/main/resources/application.properties
///*
//# Server port
//server.port=8080
//
//# H2 Database Configuration
//spring.datasource.url=jdbc:h2:mem:securitydb
//spring.datasource.driverClassName=org.h2.Driver
//spring.datasource.username=sa
//spring.datasource.password=
//spring.jpa.database-platform=org.hibernate.dialect.H2Dialect
//spring.h2.console.enabled=true
//spring.h2.console.path=/h2-console
//spring.h2.console.settings.web-allow-others=false
//
//# JPA/Hibernate Configuration
//spring.jpa.hibernate.ddl-auto=update
//spring.jpa.show-sql=true
//spring.jpa.properties.hibernate.format_sql=true
//
//# Thymeleaf Configuration
//spring.thymeleaf.cache=false
//
//# Spring Security Configuration
//logging.level.org.springframework.security=DEBUG
//*/
//
//// 10. Main Application Class
//package com.example.security;
//
//import org.springframework.boot.SpringApplication;
//import org.springframework.boot.autoconfigure.SpringBootApplication;
//
//@SpringBootApplication
//public class SecurityApplication {
//    public static void main(String[] args) {
//        SpringApplication.run(SecurityApplication.class, args);
//    }
//}