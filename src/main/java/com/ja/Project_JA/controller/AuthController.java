package com.ja.Project_JA.controller;

import com.ja.Project_JA.dto.RegistrationDto;
import com.ja.Project_JA.service.UserService;
import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class AuthController {
    @Autowired
    private UserService userService;

    // Login form
    @GetMapping("/login")
    public String login() {
        return "login";
    }

    // Registration form
    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        model.addAttribute("user", new RegistrationDto());
        return "register";
    }

    // Registration processing
    @PostMapping("/register")
    public String registerUser(@Valid @ModelAttribute("user") RegistrationDto registrationDto,
                               BindingResult result,
                               Model model) {
        if (result.hasErrors()) {
            return "register";
        }

        try {
            userService.registerNewUser(registrationDto);
            model.addAttribute("successMessage", "Registration successful! Please login.");
            return "redirect:/login?registered";
        } catch (Exception e) {
            model.addAttribute("errorMessage", e.getMessage());
            return "register";
        }
    }

    // Dashboard page (requires authentication)
    @GetMapping("/dashboard")
    public String dashboard() {
        return "dashboard";
    }

    // Home page
    @GetMapping("/")
    public String home() {
        return "index";
    }
}