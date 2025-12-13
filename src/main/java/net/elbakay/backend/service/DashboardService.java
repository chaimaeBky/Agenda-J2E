package net.elbakay.backend.service;


import net.elbakay.backend.dto.DashboardStats;
import net.elbakay.backend.model.Task;
import net.elbakay.backend.model.User;
import net.elbakay.backend.repository.TaskRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.Arrays;
import java.util.List;
@Service
public class DashboardService {

    @Autowired
    private TaskRepository taskRepository;

    @Autowired
    private UserService userService;

    public DashboardStats getDashboardStats(Long userId) {
        User user = userService.findById(userId);
        LocalDate today = LocalDate.now();

        // Total tasks
        long totalTasks = taskRepository.findByUserOrderByDateDesc(user).size();

        // Today's tasks
        long todayTasks = taskRepository.countByUserAndDate(user, today);

        // Completed tasks
        long completedTasks = taskRepository.findByUserOrderByDateDesc(user)
                .stream()
                .filter(t -> t.getStatut() == Task.Statut.TERMINEE)
                .count();

        // In progress tasks
        long inProgressTasks = taskRepository.findByUserOrderByDateDesc(user)
                .stream()
                .filter(t -> t.getStatut() == Task.Statut.EN_COURS)
                .count();

        // To do tasks
        long todoTasks = taskRepository.findByUserOrderByDateDesc(user)
                .stream()
                .filter(t -> t.getStatut() == Task.Statut.A_FAIRE)
                .count();

        // Tâches en retard : date < aujourd'hui ET statut ≠ TERMINEE
        List<Task.Statut> notCompletedStatus = Arrays.asList(
                Task.Statut.A_FAIRE,
                Task.Statut.EN_COURS
                // Task.Statut.ANNULEE si vous voulez l'inclure
        );

        long lateTasks = taskRepository.findByUserOrderByDateDesc(user)
                .stream()
                .filter(t -> t.getDate().isBefore(today))  // Date PASSÉE
                .filter(t -> notCompletedStatus.contains(t.getStatut()))  // Pas terminée
                .count();

        // Tâches à venir (7 prochains jours)
        long upcomingTasks = taskRepository.findByUserAndDateBetweenOrderByDate(
                user,
                today.plusDays(1),  // À partir de DEMAIN
                today.plusDays(7)   // Jusqu'à 7 jours
        ).size();

        return new DashboardStats(
                totalTasks,
                todayTasks,
                lateTasks,
                upcomingTasks,
                completedTasks,
                inProgressTasks,
                todoTasks
        );
    }
}