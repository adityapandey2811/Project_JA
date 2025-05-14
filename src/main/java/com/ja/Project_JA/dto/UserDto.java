package com.ja.Project_JA.dto;

import com.ja.Project_JA.entity.Message;
import jakarta.persistence.OneToMany;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserDto {
    private Long userId;
    private String userName;
    private String userPassword;
    private String userRole;
    private String userStatus;
    private String userImage;
}
