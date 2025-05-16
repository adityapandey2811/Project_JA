package com.ja.Project_JA.service;

import com.ja.Project_JA.entity.User;
import com.ja.Project_JA.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomerUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomerUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUserEmail(username);
        if (user == null) {
            throw new UsernameNotFoundException("user not found with email " + username);
        }
        return new org.springframework.security.core.userdetails.User(user.getUserEmail(), user.getUserPassword(), null);
    }
}
