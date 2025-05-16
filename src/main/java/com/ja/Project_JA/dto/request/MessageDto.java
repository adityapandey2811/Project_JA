package com.ja.Project_JA.dto.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MessageDto {
    private Long id;
    private String message;
    private LocalDateTime timestamp;
    private Long senderId;
    private Long receiverId;
}
