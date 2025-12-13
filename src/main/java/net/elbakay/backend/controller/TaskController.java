package net.elbakay.backend.controller;

import net.elbakay.backend.model.User;
import net.elbakay.backend.service.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import net.elbakay.backend.dto.TaskDTO;
import net.elbakay.backend.service.TaskService;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/tasks")
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
public class TaskController {

    @Autowired
    private TaskService taskService;
    @Autowired
    private UserService userService;

    private Long getUserIdFromSession(HttpSession session) {
        Long userId = (Long) session.getAttribute("userId");

        if (userId == null) {
            // Vérifie aussi dans SecurityContext
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName())) {
                String email = auth.getName();
                User user = userService.findByEmail(email);
                if (user != null) {
                    userId = user.getId();
                    session.setAttribute("userId", userId);
                }
            }

            if (userId == null) {
                throw new RuntimeException("Non authentifié");
            }
        }

        return userId;
    }

    @PostMapping
    public ResponseEntity<?> createTask(@Valid @RequestBody TaskDTO taskDTO, HttpSession session) {
        try {
            Long userId = getUserIdFromSession(session);
            TaskDTO createdTask = taskService.createTask(taskDTO, userId);
            return ResponseEntity.ok(createdTask);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping
    public ResponseEntity<?> getAllTasks(HttpSession session) {
        try {
            Long userId = getUserIdFromSession(session);
            List<TaskDTO> tasks = taskService.getAllTasksByUser(userId);
            return ResponseEntity.ok(tasks);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getTask(@PathVariable Long id, HttpSession session) {
        try {
            Long userId = getUserIdFromSession(session);
            TaskDTO task = taskService.getTaskById(id, userId);
            return ResponseEntity.ok(task);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> updateTask(@PathVariable Long id,
                                        @Valid @RequestBody TaskDTO taskDTO,
                                        HttpSession session) {
        try {
            Long userId = getUserIdFromSession(session);

            // 1. Récupérez la tâche existante
            TaskDTO existingTask = taskService.getTaskById(id, userId);

            // 2. Fusionnez les modifications (seulement les champs non-nuls)
            if (taskDTO.getTitre() != null) {
                existingTask.setTitre(taskDTO.getTitre());
            }
            if (taskDTO.getDescription() != null) {
                existingTask.setDescription(taskDTO.getDescription());
            }
            if (taskDTO.getDate() != null) {
                existingTask.setDate(taskDTO.getDate());
            }
            if (taskDTO.getHeure() != null) {
                existingTask.setHeure(taskDTO.getHeure());
            }
            if (taskDTO.getPriorite() != null) {
                existingTask.setPriorite(taskDTO.getPriorite());
            }
            if (taskDTO.getStatut() != null) {
                existingTask.setStatut(taskDTO.getStatut());
            }

            // 3. Mettez à jour
            TaskDTO updatedTask = taskService.updateTask(id, existingTask, userId);
            return ResponseEntity.ok(updatedTask);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", e.getMessage()));
        }
    }
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteTask(@PathVariable Long id, HttpSession session) {
        try {
            Long userId = getUserIdFromSession(session);
            taskService.deleteTask(id, userId);
            return ResponseEntity.ok(Map.of("message", "Tâche supprimée avec succès"));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/date/{date}")
    public ResponseEntity<?> getTasksByDate(@PathVariable @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date,
                                            HttpSession session) {
        try {
            Long userId = getUserIdFromSession(session);
            List<TaskDTO> tasks = taskService.getTasksByDate(userId, date);
            return ResponseEntity.ok(tasks);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/calendar/{year}/{month}")
    public ResponseEntity<?> getTasksByMonth(@PathVariable int year,
                                             @PathVariable int month,
                                             HttpSession session) {
        try {
            Long userId = getUserIdFromSession(session);
            List<TaskDTO> tasks = taskService.getTasksByMonth(userId, year, month);
            return ResponseEntity.ok(tasks);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", e.getMessage()));
        }
    }
}