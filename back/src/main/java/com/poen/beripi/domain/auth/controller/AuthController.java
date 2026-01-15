package com.poen.beripi.domain.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.poen.beripi.domain.auth.dto.RefreshRequestDto;
import com.poen.beripi.domain.auth.dto.TokenResponseDto;
import com.poen.beripi.domain.jwt.service.JwtService;
import com.poen.beripi.domain.jwt.service.JwtService.TokenRefreshResult;
import com.poen.beripi.utils.MessageUtil;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    
    private final JwtService jwtService;
    private final MessageUtil messageUtil;
    
    // 토큰 재발급
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponseDto> refresh(@Valid @RequestBody RefreshRequestDto request) {
        
        TokenRefreshResult result = jwtService.refreshAccessToken(request.getRefreshToken());
        
        TokenResponseDto response = TokenResponseDto.builder()
                .accessToken(result.getAccessToken())
                .refreshToken(result.getRefreshToken())
                .build();
        
        return ResponseEntity.ok(response);
    }
    
    // 로그아웃
    @PostMapping("/logout")
    public ResponseEntity<String> logout(Authentication authentication) {
        
        // SecurityContext에서 현재 로그인한 사용자 ID 추출
        String memberId = authentication.getName();
        
        // 해당 사용자의 모든 Refresh Token 삭제
        jwtService.removeRefreshMember(memberId);
        
        String message = messageUtil.getMessage("message.logout.success");
        return ResponseEntity.ok(String.format("{\"message\":\"%s\"}", message));
    }
}

