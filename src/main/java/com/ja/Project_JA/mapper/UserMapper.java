package com.ja.Project_JA.mapper;

import com.ja.Project_JA.dto.UserDto;
import com.ja.Project_JA.entity.User;

public class UserMapper {

    public UserDto toDto(User user) {
        return UserDto.builder()
                .userId(user.getUserId())
                .userName(user.getUserName())
                .userPassword(user.getUserPassword())
                .userRole(user.getUserRole())
                .userStatus(user.getUserStatus())
                .userImage(user.getUserImage())
                .build();
    }
    public User toEntity(UserDto userDto) {
        return User.builder()
                .userId(userDto.getUserId())
                .userName(userDto.getUserName())
                .userPassword(userDto.getUserPassword())
                .userRole(userDto.getUserRole())
                .userStatus(userDto.getUserStatus())
                .userImage(userDto.getUserImage())
                .build();
    }
}
