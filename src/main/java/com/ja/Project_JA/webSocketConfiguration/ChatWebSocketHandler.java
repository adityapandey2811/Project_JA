package com.ja.Project_JA.webSocketConfiguration;

import org.springframework.stereotype.Component;
import org.springframework.web.socket.*;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.util.concurrent.ConcurrentHashMap;

@Component
public class ChatWebSocketHandler extends TextWebSocketHandler {

    private final ConcurrentHashMap<String, WebSocketSession> sessions = new ConcurrentHashMap<>();

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        String id = session.getId();
        sessions.put(id, session);
        System.out.println("User connected: " + id);
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        String payload = message.getPayload();
        String[] parts = payload.split("\\|", 2);

        if (parts.length == 2) {
            String targetId = parts[0];
            String msg = parts[1];

            WebSocketSession target = sessions.get(targetId);
            if (target != null && target.isOpen()) {
                target.sendMessage(new TextMessage("From " + session.getId() + ": " + msg));
            } else {
                session.sendMessage(new TextMessage("User " + targetId + " not available."));
            }
        } else {
            session.sendMessage(new TextMessage("Invalid format. Use: targetId|message"));
        }
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        sessions.remove(session.getId());
        System.out.println("User disconnected: " + session.getId());
    }
}
