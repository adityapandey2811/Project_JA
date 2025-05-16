package com.ja.Project_JA.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @Column(nullable = false)
    private String userId;

    @Column(nullable = false)
    private String userName;

    @Column(nullable = false)
    private String userPassword;

    @Column(unique = true, nullable = false)
    private String userEmail;

    @Enumerated(EnumType.STRING)
    private USER_ROLE userRole;

    @OneToMany(mappedBy = "sender")
    private List<Message> sentMessages = new ArrayList<>();
}
