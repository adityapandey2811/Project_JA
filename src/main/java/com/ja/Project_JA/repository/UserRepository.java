package com.ja.Project_JA.repository;

import com.ja.Project_JA.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, String> {
    // Custom query methods can be defined here if needed
    User findByUserEmail(String userEmail);
    User findByUserName(String userName);
}
