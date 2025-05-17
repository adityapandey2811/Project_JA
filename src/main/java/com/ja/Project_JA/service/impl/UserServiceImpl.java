package com.ja.Project_JA.service.impl;

import com.ja.Project_JA.config.JwtTokenProvider;
import com.ja.Project_JA.entity.User;
import com.ja.Project_JA.repository.UserRepository;
import com.ja.Project_JA.service.UserService;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final JwtTokenProvider jwtProvider;

    public UserServiceImpl(UserRepository userRepository, JwtTokenProvider jwtProvider) {
        this.userRepository = userRepository;
        this.jwtProvider = jwtProvider;
    }

    @Override
    public User findUserByJwtToken(String jwt) throws Exception {
        String email = jwtProvider.getEmailFromJwtToken(jwt);
        return findUserByEmail(email);
    }

    @Override
    public User findUserByEmail(String email) throws Exception {
        User user = userRepository.findByUserEmail(email);
        if (user == null) {
            throw new Exception("User not found.");
        }
        return user;
    }
}
