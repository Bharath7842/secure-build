package com.acme.security;

import com.acme.model.User;
import com.acme.service.UserRepository;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class SessionAuthFilter extends OncePerRequestFilter {
    private final TokenVerifier tokens = new TokenVerifier();
    private final UserRepository users = new UserRepository();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String token = request.getHeader("X-Session-Token");
        String username = tokens.usernameFor(token);
        User user = username == null ? null : users.findByUsername(username);
        if (user != null && !user.isLocked()) {
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(user.getUsername(), null, java.util.List.of()));
        }
        chain.doFilter(request, response);
    }
}
