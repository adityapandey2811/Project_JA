package com.ja.Project_JA.dto.request;

import com.ja.Project_JA.entity.USER_ROLE;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RegisterRequest {
    private String userName;
    private String userEmail;
    private String userPassword;
    private String userPasswordConfirm;
    private USER_ROLE userRole; // Added this
}
