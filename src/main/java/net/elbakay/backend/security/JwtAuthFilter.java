package net.elbakay.backend.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        System.out.println("=== JWT FILTER DEBUG ===");
        System.out.println("Request URI: " + request.getRequestURI());
        System.out.println("Auth Header: " + request.getHeader("Authorization"));

        final String authHeader = request.getHeader("Authorization");
        String jwt = null;
        String username = null;

        // 1. Vérifier le header Authorization pour JWT
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7);
            try {
                username = jwtUtil.extractUsername(jwt);
                System.out.println("JWT Auth: Valid token for user: " + username);

                // Vérifier si le token est expiré
                if (jwtUtil.isTokenExpired(jwt)) {
                    System.out.println("JWT Auth: Token expired");
                    username = null;
                }
            } catch (Exception e) {
                System.out.println("JWT Auth: Invalid token - " + e.getMessage());
            }
        } else {
            System.out.println("JWT Auth: No Bearer token found");
        }

        // 2. Si JWT valide, créer l'authentification
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            System.out.println("JWT Auth: Setting authentication for user: " + username);

            List<SimpleGrantedAuthority> authorities = Collections.singletonList(
                    new SimpleGrantedAuthority("ROLE_USER")
            );

            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(username, null, authorities);

            SecurityContextHolder.getContext().setAuthentication(authToken);

            // Stocker dans la session pour compatibilité
            HttpSession session = request.getSession(true);
            session.setAttribute("userEmail", username);
            session.setAttribute("authenticated", true);

            System.out.println("JWT Auth: Authentication set successfully");
        } else if (username == null) {
            System.out.println("JWT Auth: No valid JWT, checking session...");

            // Vérifier la session existante
            HttpSession session = request.getSession(false);
            if (session != null) {
                String sessionUser = (String) session.getAttribute("userEmail");
                System.out.println("Session user: " + sessionUser);

                if (sessionUser != null) {
                    // Créer l'authentification à partir de la session
                    List<SimpleGrantedAuthority> authorities = Collections.singletonList(
                            new SimpleGrantedAuthority("ROLE_USER")
                    );

                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(sessionUser, null, authorities);

                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    System.out.println("Session Auth: Authentication set from session");
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}