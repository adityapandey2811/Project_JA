package com.ja.Project_JA.entity;

import com.fasterxml.jackson.annotation.JsonManagedReference;
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
    private String userId;
    private String userName;
    private String userPassword;
    private String userEmail;
    @OneToMany(mappedBy = "sender")
    private List<Message> sentMessages=new ArrayList<>();
}
