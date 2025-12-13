package net.elbakay.backend.controller;

import net.elbakay.backend.dto.AuthRequest;
import net.elbakay.backend.dto.RegisterRequest;
import net.elbakay.backend.model.User;
import net.elbakay.backend.service.UserService;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
public class AuthController {

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {
        try {
            User user = userService.registerUser(registerRequest);
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Inscription réussie");
            response.put("user", Map.of(
                    "id", user.getId(),
                    "nom", user.getNom(),
                    "email", user.getEmail()
            ));
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody AuthRequest authRequest, HttpSession session) {
        try {
            User user = userService.authenticate(authRequest.getEmail(), authRequest.getPassword());

            session.setAttribute("userId", user.getId());
            session.setAttribute("userEmail", user.getEmail());
            session.setAttribute("userName", user.getNom());

            Map<String, Object> response = new HashMap<>();
            response.put("message", "Connexion réussie");
            response.put("user", Map.of(
                    "id", user.getId(),
                    "nom", user.getNom(),
                    "email", user.getEmail()
            ));
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(HttpSession session) {
        Long userId = (Long) session.getAttribute("userId");
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Non authentifié"));
        }

        try {
            User user = userService.findById(userId);
            Map<String, Object> userData = Map.of(
                    "id", user.getId(),
                    "nom", user.getNom(),
                    "email", user.getEmail()
            );
            return ResponseEntity.ok(userData);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpSession session) {
        session.invalidate();
        return ResponseEntity.ok(Map.of("message", "Déconnexion réussie"));
    }

    @GetMapping("/session-debug")
    public ResponseEntity<?> sessionDebug(HttpSession session) {
        Map<String, Object> debug = new HashMap<>();
        debug.put("sessionId", session.getId());
        debug.put("isNew", session.isNew());
        debug.put("userId", session.getAttribute("userId"));
        debug.put("creationTime", session.getCreationTime());
        debug.put("lastAccessedTime", session.getLastAccessedTime());

        // Vérifiez Security Context aussi
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            debug.put("securityUsername", auth.getName());
            debug.put("securityAuthenticated", auth.isAuthenticated());
        }

        return ResponseEntity.ok(debug);
    }
}