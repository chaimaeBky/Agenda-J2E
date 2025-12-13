package net.elbakay.backend.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DashboardStats {

    private long totalTasks;
    private long todayTasks;
    private long lateTasks;
    private long upcomingTasks;
    private long completedTasks;
    private long inProgressTasks;
    private long todoTasks;
}