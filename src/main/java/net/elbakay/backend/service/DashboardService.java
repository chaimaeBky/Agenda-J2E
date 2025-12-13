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

        long totalTasks = taskRepository.findByUserOrderByDateDesc(user).size();
        long todayTasks = taskRepository.countByUserAndDate(user, today);
        long completedTasks = taskRepository.findByUserOrderByDateDesc(user)
                .stream()
                .filter(t -> t.getStatut() == Task.Statut.TERMINEE)
                .count();
        long inProgressTasks = taskRepository.findByUserOrderByDateDesc(user)
                .stream()
                .filter(t -> t.getStatut() == Task.Statut.EN_COURS)
                .count();
        long todoTasks = taskRepository.findByUserOrderByDateDesc(user)
                .stream()
                .filter(t -> t.getStatut() == Task.Statut.A_FAIRE)
                .count();

        List<Task.Statut> notCompletedStatus = Arrays.asList(
                Task.Statut.A_FAIRE, Task.Statut.EN_COURS
        );
        long lateTasks = taskRepository.countLateTasks(user, today, notCompletedStatus);

        long upcomingTasks = taskRepository.findByUserAndDateBetweenOrderByDate(
                user,
                today.plusDays(1),
                today.plusDays(7)
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