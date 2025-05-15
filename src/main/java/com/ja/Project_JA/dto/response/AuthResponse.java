package com.ja.Project_JA.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {

    private String senderId;
    private String jwt;
    private String message;
    private String userName;
}
