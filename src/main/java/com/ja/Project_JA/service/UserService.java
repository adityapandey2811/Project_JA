package com.ja.Project_JA.service;

import com.ja.Project_JA.entity.User;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

@Component
public interface UserService {
    public User findUserByJwtToken(String jwt) throws Exception;

    public User findUserByEmail(String email) throws Exception;
}
