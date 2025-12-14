package net.elbakay.backend.controller;

import net.elbakay.backend.dto.AuthRequest;
import net.elbakay.backend.dto.RegisterRequest;
import net.elbakay.backend.model.User;
import net.elbakay.backend.service.UserService;
import net.elbakay.backend.security.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest,
                                      HttpSession session) {  // Gardé pour compatibilité
        try {
            User user = userService.registerUser(registerRequest);

            // Créer une session pour les clients qui utilisent encore les sessions
            session.setAttribute("userId", user.getId());
            session.setAttribute("userEmail", user.getEmail());
            session.setAttribute("userName", user.getNom());

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
    public ResponseEntity<?> login(@Valid @RequestBody AuthRequest authRequest,
                                   HttpServletRequest request) {
        try {
            User user = userService.authenticate(authRequest.getEmail(), authRequest.getPassword());

            // OPTION 1: Générer JWT
            UserDetails userDetails = org.springframework.security.core.userdetails.User
                    .withUsername(user.getEmail())
                    .password("")
                    .authorities("USER")
                    .build();

            String token = jwtUtil.generateToken(userDetails);

            // OPTION 2: Créer une session Spring Security (pour compatibilité)
            List<SimpleGrantedAuthority> authorities = Collections.singletonList(
                    new SimpleGrantedAuthority("USER")
            );

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    user.getEmail(),
                    null,
                    authorities
            );

            SecurityContext securityContext = SecurityContextHolder.getContext();
            securityContext.setAuthentication(authentication);

            // Créer une nouvelle session HTTP
            HttpSession session = request.getSession(true);
            session.setAttribute("userId", user.getId());
            session.setAttribute("userEmail", user.getEmail());
            session.setAttribute("userName", user.getNom());

            // IMPORTANT: Sauvegarder le SecurityContext dans la session
            session.setAttribute(
                    HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                    securityContext
            );

            Map<String, Object> response = new HashMap<>();
            response.put("message", "Connexion réussie");
            response.put("token", token); // JWT pour les nouveaux clients
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
    public ResponseEntity<?> getCurrentUser(HttpServletRequest request) {
        // Vérifier le token JWT d'abord
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            try {
                String email = jwtUtil.extractUsername(token);
                User user = userService.findByEmail(email);

                Map<String, Object> userData = Map.of(
                        "id", user.getId(),
                        "nom", user.getNom(),
                        "email", user.getEmail()
                );
                return ResponseEntity.ok(userData);
            } catch (Exception e) {
                System.out.println("JWT validation failed in /me: " + e.getMessage());
            }
        }

        // Fallback à la session pour compatibilité
        HttpSession session = request.getSession(false);
        if (session != null) {
            Long userId = (Long) session.getAttribute("userId");
            if (userId != null) {
                try {
                    User user = userService.findById(userId);
                    Map<String, Object> userData = Map.of(
                            "id", user.getId(),
                            "nom", user.getNom(),
                            "email", user.getEmail()
                    );
                    return ResponseEntity.ok(userData);
                } catch (RuntimeException e) {
                    System.out.println("User not found by ID: " + userId);
                }
            }
        }

        // Vérifier dans SecurityContext
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName())) {
            String email = auth.getName();
            try {
                User user = userService.findByEmail(email);
                Map<String, Object> userData = Map.of(
                        "id", user.getId(),
                        "nom", user.getNom(),
                        "email", user.getEmail()
                );
                return ResponseEntity.ok(userData);
            } catch (RuntimeException e) {
                System.out.println("User not found by email: " + email);
            }
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Non authentifié"));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpSession session) {
        // Pour JWT stateless, on ne fait rien côté serveur
        // Pour les sessions, on les invalide
        if (session != null) {
            session.invalidate();
        }
        SecurityContextHolder.clearContext();
        return ResponseEntity.ok(Map.of("message", "Déconnexion réussie"));
    }
}