package com.ja.Project_JA.mapper;

import com.ja.Project_JA.dto.MessageDto;
import com.ja.Project_JA.entity.Message;
import com.ja.Project_JA.entity.User;

public class MessageMapper {
    public MessageDto toDto(Message message) {
        return MessageDto.builder()
                .id(message.getId())
                .message(message.getText())
                .timestamp(message.getTimestamp())
                .receiverId(message.getReceiver().getUserId())
                .senderId(message.getSender().getUserId())
                .build();
    }
    public Message toEntity(MessageDto messageDto, User sender, User receiver) {
        return Message.builder()
                .id(messageDto.getId())
                .text(messageDto.getMessage())
                .timestamp(messageDto.getTimestamp())
                .sender(sender)
                .receiver(receiver)
                .build();
    }
}
