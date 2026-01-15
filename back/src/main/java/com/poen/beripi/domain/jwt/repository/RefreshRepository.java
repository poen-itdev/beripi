package com.poen.beripi.domain.jwt.repository;

import java.time.LocalDateTime;

import org.springframework.data.jpa.repository.JpaRepository;

import com.poen.beripi.domain.jwt.entity.RefreshToken;

public interface RefreshRepository extends JpaRepository<RefreshToken, Long>{
    
    // refresh 토큰 존재 여부 확인
    Boolean existsByRefresh(String refresh);

    // refresh 토큰 기반 삭제
    void deleteByRefresh(String refresh);

    // JWT 발급 memberId 기반 삭제 메소드 (탈퇴시)
    void deleteByMemberId(String memberId);

    // 특정일 지난 refresh 토큰 삭제
    void deleteByCreatedDateBefore(LocalDateTime createdDate);
}
