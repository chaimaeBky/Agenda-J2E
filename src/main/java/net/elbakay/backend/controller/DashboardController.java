package net.elbakay.backend.controller;

import net.elbakay.backend.dto.DashboardStats;
import net.elbakay.backend.service.DashboardService;
import net.elbakay.backend.model.User;
import net.elbakay.backend.service.UserService;
import net.elbakay.backend.security.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/dashboard")
public class DashboardController {

    @Autowired
    private DashboardService dashboardService;

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    /**
     * Méthode duale pour récupérer l'ID utilisateur
     */
    private Long getUserIdFromRequest(HttpServletRequest request) {
        // 1. Vérifier JWT d'abord
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            try {
                String email = jwtUtil.extractUsername(token);
                User user = userService.findByEmail(email);
                System.out.println("User ID from JWT: " + user.getId() + " (email: " + email + ")");
                return user.getId();
            } catch (Exception e) {
                System.out.println("JWT validation failed: " + e.getMessage());
            }
        }

        // 2. Fallback à la session
        HttpSession session = request.getSession(false);
        if (session != null) {
            Long userId = (Long) session.getAttribute("userId");
            System.out.println("User ID from session: " + userId);

            if (userId != null) {
                return userId;
            }

            // Debug: afficher tous les attributs de session
            System.out.println("Session attributes:");
            session.getAttributeNames().asIterator()
                    .forEachRemaining(attr ->
                            System.out.println("  " + attr + ": " + session.getAttribute(attr))
                    );
        }

        // 3. Vérifier dans SecurityContext
        org.springframework.security.core.Authentication auth =
                org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName())) {
            String email = auth.getName();
            System.out.println("User email from SecurityContext: " + email);
            User user = userService.findByEmail(email);
            if (user != null) {
                // Stocker dans la session pour les prochaines requêtes
                if (session != null) {
                    session.setAttribute("userId", user.getId());
                }
                return user.getId();
            }
        }

        throw new RuntimeException("Non authentifié");
    }

    @GetMapping("/stats")
    public ResponseEntity<?> getStats(HttpServletRequest request) {
        System.out.println("=== DEBUG DASHBOARD STATS ===");

        try {
            Long userId = getUserIdFromRequest(request);
            System.out.println("Getting stats for user ID: " + userId);

            DashboardStats stats = dashboardService.getDashboardStats(userId);
            System.out.println("Stats retrieved successfully");
            return ResponseEntity.ok(stats);

        } catch (RuntimeException e) {
            System.out.println("Error getting user ID: " + e.getMessage());

            // Fallback: essayer avec la session directement
            HttpSession session = request.getSession(false);
            if (session != null) {
                Long userId = (Long) session.getAttribute("userId");
                if (userId != null) {
                    try {
                        DashboardStats stats = dashboardService.getDashboardStats(userId);
                        return ResponseEntity.ok(stats);
                    } catch (Exception ex) {
                        System.out.println("Fallback also failed: " + ex.getMessage());
                    }
                }
            }

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Non authentifié. Veuillez vous reconnecter."));
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Erreur serveur: " + e.getMessage()));
        }
    }
}