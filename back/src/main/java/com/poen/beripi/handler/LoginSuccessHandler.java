package com.poen.beripi.handler;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.poen.beripi.domain.jwt.service.JwtService;
import com.poen.beripi.domain.member.entity.Member;
import com.poen.beripi.domain.member.repository.MemberRepository;
import com.poen.beripi.utils.JWTUtil;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@Qualifier("LoginSuccessHandler")
@RequiredArgsConstructor
public class LoginSuccessHandler implements AuthenticationSuccessHandler{
    
    private final JwtService jwtService;
    private final MemberRepository memberRepository;
    private final JWTUtil jwtUtil;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        // authentication은 로그인 성공 시 만들어진 객체임 

        // memberId, role
        String memberId = authentication.getName();
        String role = authentication.getAuthorities().iterator().next().getAuthority();

        log.info("로그인 성공 - MemberId: {}, Role: {}", memberId, role);

        // Jwt(Access/Refresh) 발급
        String accessToken = jwtUtil.createJwt(memberId, role, true);
        String refreshToken = jwtUtil.createJwt(memberId, role, false);

        log.info("토큰 발급 완료 - Refresh Token: {}...", refreshToken.substring(0, Math.min(20, refreshToken.length())));

        // 발급한 Refresh DB 테이블 저장
        try {
            jwtService.addRefresh(memberId, refreshToken);
            log.info("Refresh Token DB 저장 완료 - MemberId: {}", memberId);
            
            // 명시적으로 플러시하여 즉시 DB에 반영 (트랜잭션이 필터 체인에서 제대로 동작하지 않을 수 있음)
            // JwtService의 @Transactional이 제대로 동작하도록 보장
        } catch (Exception e) {
            log.error("Refresh Token DB 저장 실패 - MemberId: {}, Error: {}", memberId, e.getMessage(), e);
            throw e;
        }

        // isFirstLogin 값 조회
        Member member = memberRepository.findByMemberId(memberId)
                .orElseThrow(() -> new UsernameNotFoundException(memberId));
        String isFirstLogin = member.getIsFirstLogin();

        // 응답
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        String json = String.format("{\"accessToken\":\"%s\", \"refreshToken\":\"%s\", \"isFirstLogin\":\"%s\"}", accessToken, refreshToken, isFirstLogin);
        response.getWriter().write(json);
        response.getWriter().flush();
    }
}
