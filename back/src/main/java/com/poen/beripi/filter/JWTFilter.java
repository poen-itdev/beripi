package com.poen.beripi.filter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import com.poen.beripi.utils.JWTUtil;
import com.poen.beripi.utils.MessageUtil;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JWTFilter extends OncePerRequestFilter {
    
    private final JWTUtil jwtUtil;
    private final MessageUtil messageUtil;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    
    // JWT 검증을 하지 않을 공개 URL 패턴
    private static final String[] PUBLIC_URLS = {
        "/login",
        "/api/auth/refresh"
    };
    
    public JWTFilter(JWTUtil jwtUtil, MessageUtil messageUtil) {
        this.jwtUtil = jwtUtil;
        this.messageUtil = messageUtil;
    }
    
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        // 공개 URL은 JWT 필터를 건너뜀
        for (String publicUrl : PUBLIC_URLS) {
            if (pathMatcher.match(publicUrl, path)) {
                return true;
            }
        }
        return false;
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        try {
            // 헤더에서 Authorization 토큰 추출
            String authorization = request.getHeader("Authorization");
            
            // 토큰이 없다면 다음 필터로 (익명 사용자로 처리)
            if (authorization == null || authorization.isBlank()) {
                filterChain.doFilter(request, response);
                return;
            }
            
            // Bearer가 없거나 형식이 잘못된 경우
            if (!authorization.startsWith("Bearer ") || authorization.length() <= 7) {
                log.warn("Invalid Authorization header format: {}", authorization);
                sendUnauthorizedError(response, messageUtil.getMessage("error.jwt.invalid.header.format"));
                return;
            }
            
            // 토큰 파싱
            String accessToken = authorization.substring(7).trim();
            
            // 빈 토큰 체크
            if (accessToken.isEmpty()) {
                log.warn("Empty access token");
                sendUnauthorizedError(response, messageUtil.getMessage("error.jwt.empty.token"));
                return;
            }
            
            // 토큰 유효성 검증
            if (!jwtUtil.isValid(accessToken, true)) {
                log.warn("Invalid or expired JWT token");
                sendUnauthorizedError(response, messageUtil.getMessage("error.jwt.expired.or.invalid"));
                return;
            }
            
            // 토큰에서 사용자 정보 추출
            String memberId = jwtUtil.getMemberId(accessToken);
            String role = jwtUtil.getRole(accessToken);
            
            // ROLE_ 접두사 추가 (Spring Security 표준)
            List<GrantedAuthority> authorities = Collections.singletonList(
                new SimpleGrantedAuthority("ROLE_" + role)
            );
            
            // Authentication 객체 생성
            Authentication auth = new UsernamePasswordAuthenticationToken(memberId, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(auth);
            
            log.debug("JWT authentication successful - MemberId: {}, Role: {}", memberId, role);
            
            // 인증 성공 - 다음 필터로 진행
            filterChain.doFilter(request, response);
            
        } catch (Exception e) {
            // 예상치 못한 예외 처리
            log.error("JWT filter error: {}", e.getMessage(), e);
            sendUnauthorizedError(response, messageUtil.getMessage("error.jwt.authentication.failed"));
        }
    }
    
    /**
     * 401 Unauthorized 에러 응답 전송
     */
    private void sendUnauthorizedError(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(String.format("{\"error\":\"%s\"}", message));
    }
}
