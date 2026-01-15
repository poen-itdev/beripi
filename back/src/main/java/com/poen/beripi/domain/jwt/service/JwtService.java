package com.poen.beripi.domain.jwt.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.poen.beripi.domain.jwt.entity.RefreshToken;
import com.poen.beripi.domain.jwt.repository.RefreshRepository;
import com.poen.beripi.utils.JWTUtil;
import com.poen.beripi.utils.MessageUtil;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class JwtService {
    
    private final RefreshRepository refreshRepository;
    private final MessageUtil messageUtil;
    private final JWTUtil jwtUtil;
    
    @PersistenceContext
    private EntityManager entityManager;

    // Refresh 토큰으로 Access 토큰 재발급 로직(Rotate 포함)
    @Transactional
    public TokenRefreshResult refreshAccessToken(String refreshToken) {
        
        // 1. Refresh 토큰 유효성 검증
        if (!jwtUtil.isValid(refreshToken, false)) {
            throw new IllegalArgumentException(messageUtil.getMessage("error.jwt.invalid.refresh.token"));
        }
        
        // 2. DB에 저장된 토큰인지 확인
        if (!refreshRepository.existsByRefresh(refreshToken)) {
            throw new IllegalArgumentException(messageUtil.getMessage("error.jwt.not.found.refresh.token"));
        }
        
        // 3. 토큰에서 사용자 정보 추출
        String memberId = jwtUtil.getMemberId(refreshToken);
        String role = jwtUtil.getRole(refreshToken);
        
        // 4. 새로운 Access & Refresh 토큰 생성 (Rotate 방식)
        String newAccessToken = jwtUtil.createJwt(memberId, role, true);
        String newRefreshToken = jwtUtil.createJwt(memberId, role, false);
        
        // 5. 기존 Refresh 토큰 삭제
        refreshRepository.deleteByRefresh(refreshToken);
        
        // 6. 새 Refresh 토큰 저장
        addRefresh(memberId, newRefreshToken);
        
        return new TokenRefreshResult(newAccessToken, newRefreshToken);
    }
    
    // 토큰 재발급 결과 DTO
    public static class TokenRefreshResult {
        private final String accessToken;
        private final String refreshToken;
        
        public TokenRefreshResult(String accessToken, String refreshToken) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
        }
        
        public String getAccessToken() {
            return accessToken;
        }
        
        public String getRefreshToken() {
            return refreshToken;
        }
    }

    // Jwt Refresh 토큰 발급 후 저장 메소드
    @Transactional(readOnly = false)  // 명시적으로 readOnly = false 설정
    public void addRefresh(String memberId, String refresh) {
        
        log.info("addRefresh 호출 - MemberId: {}, Refresh Token: {}...", 
                memberId, refresh.substring(0, Math.min(20, refresh.length())));

        RefreshToken token = RefreshToken.builder()
            .memberId(memberId)
            .refresh(refresh)
            .build();

        RefreshToken savedToken = refreshRepository.save(token);
        
        // 명시적으로 플러시하여 즉시 DB에 반영 (필터 체인에서 트랜잭션이 제대로 커밋되지 않을 수 있음)
        entityManager.flush();
        
        log.info("Refresh Token 저장 완료 - ID: {}, MemberId: {}, CreatedDate: {}", 
                savedToken.getId(), savedToken.getMemberId(), savedToken.getCreatedDate());
    }

    // Jwt Refresh 토큰 기반 존재 확인 메소드
    public Boolean existsByRefresh(String refresh) {

        return refreshRepository.existsByRefresh(refresh);
    }

    // JWT Refresh 토큰 기반 삭제 메소드
    @Transactional
    public void removeRefresh(String refresh) {

        refreshRepository.deleteByRefresh(refresh);
    }

    // JWT 발급 memberId 기반 삭제 메소드 (탈퇴시)
    @Transactional
    public void removeRefreshMember(String memberId) {

        refreshRepository.deleteByMemberId(memberId);
    }
}
