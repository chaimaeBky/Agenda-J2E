package net.elbakay.backend.repository;


import net.elbakay.backend.model.Task;
import net.elbakay.backend.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;

@Repository
public interface TaskRepository extends JpaRepository<Task, Long> {

    List<Task> findByUserOrderByDateDesc(User user);

    List<Task> findByUserAndDateOrderByDate(User user, LocalDate date);

    List<Task> findByUserAndDateBetweenOrderByDate(User user, LocalDate start, LocalDate end);

    List<Task> findByUserAndDateBeforeAndStatutNot(
            User user,
            LocalDate date,
            Task.Statut statut
    );

    @Query("SELECT COUNT(t) FROM Task t WHERE t.user = :user AND t.date = :date")
    long countByUserAndDate(@Param("user") User user, @Param("date") LocalDate date);

    @Query("SELECT COUNT(t) FROM Task t WHERE t.user = :user AND t.date < :date AND t.statut IN (:notCompletedStatus)")
    long countLateTasks(@Param("user") User user,
                        @Param("date") LocalDate date,
                        @Param("notCompletedStatus") List<Task.Statut> notCompletedStatus);
}