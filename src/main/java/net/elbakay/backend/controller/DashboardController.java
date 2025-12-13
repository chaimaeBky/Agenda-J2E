package net.elbakay.backend.controller;

import net.elbakay.backend.dto.DashboardStats;
import net.elbakay.backend.service.DashboardService;
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

    @GetMapping("/stats")
    public ResponseEntity<?> getStats(HttpSession session) {
        System.out.println("=== DEBUG DASHBOARD STATS ===");
        System.out.println("Session ID: " + (session != null ? session.getId() : "NULL SESSION"));

        if (session == null) {
            System.out.println("ERROR: No session found!");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Session non trouvée"));
        }

        Long userId = (Long) session.getAttribute("userId");
        System.out.println("User ID from session: " + userId);
        System.out.println("All session attributes: ");

        if (session.getAttributeNames() != null) {
            session.getAttributeNames().asIterator()
                    .forEachRemaining(attr ->
                            System.out.println("  " + attr + ": " + session.getAttribute(attr))
                    );
        }

        if (userId == null) {
            System.out.println("ERROR: User not logged in!");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Non authentifié. Veuillez vous reconnecter."));
        }

        System.out.println("Getting stats for user ID: " + userId);
        try {
            DashboardStats stats = dashboardService.getDashboardStats(userId);
            System.out.println("Stats retrieved successfully");
            return ResponseEntity.ok(stats);
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Erreur serveur: " + e.getMessage()));
        }
    }
}