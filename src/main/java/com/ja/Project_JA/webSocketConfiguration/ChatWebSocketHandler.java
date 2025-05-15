package com.ja.Project_JA.webSocketConfiguration;

import org.springframework.stereotype.Component;
import org.springframework.web.socket.*;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.util.concurrent.ConcurrentHashMap;

@Component
public class ChatWebSocketHandler extends TextWebSocketHandler {

    private final ConcurrentHashMap<String, WebSocketSession> sessions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> sessionIdToUsername = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, WebSocketSession> usernameToSession = new ConcurrentHashMap<>();

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        System.out.println("Connection established: " + session.getId());
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        String payload = message.getPayload();

        // If user hasn't registered a username yet
        if (!sessionIdToUsername.containsKey(session.getId())) {
            String username = payload.trim();
            if (usernameToSession.containsKey(username)) {
                session.sendMessage(new TextMessage("❌ Username already taken. Refresh and try again."));
                session.close();
                return;
            }
            sessionIdToUsername.put(session.getId(), username);
            usernameToSession.put(username, session);
            sessions.put(session.getId(), session);
            session.sendMessage(new TextMessage("✅ Welcome, " + username + "!"));
            return;
        }

        // Chat message expected in format: "targetUsername|message"
        String[] parts = payload.split("\\|", 2);
        if (parts.length == 2) {
            String targetUsername = parts[0];
            String msg = parts[1];

            WebSocketSession targetSession = usernameToSession.get(targetUsername);
            String sender = sessionIdToUsername.get(session.getId());

            if (targetSession != null && targetSession.isOpen()) {
                targetSession.sendMessage(new TextMessage("💬 From " + sender + ": " + msg));
            } else {
                session.sendMessage(new TextMessage("❌ User '" + targetUsername + "' not found or offline."));
            }
        } else {
            session.sendMessage(new TextMessage("⚠️ Invalid format. Use: targetUsername|message"));
        }
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        String sessionId = session.getId();
        String username = sessionIdToUsername.remove(sessionId);
        if (username != null) {
            usernameToSession.remove(username);
        }
        sessions.remove(sessionId);
        System.out.println("Disconnected: " + sessionId + " (" + username + ")");
    }
}
