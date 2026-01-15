package com.poen.beripi.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.poen.beripi.domain.member.repository.MemberRepository;
import com.poen.beripi.filter.JWTFilter;
import com.poen.beripi.filter.LoginFilter;
import com.poen.beripi.utils.JWTUtil;
import com.poen.beripi.utils.MessageUtil;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final AuthenticationSuccessHandler loginSuccessHandler;
    private final MemberRepository memberRepository;
    private final MessageUtil messageUtil;
    private final JWTUtil jwtUtil;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, 
        @Qualifier("LoginSuccessHandler") AuthenticationSuccessHandler loginSuccessHandler,
        MemberRepository memberRepository,
        MessageUtil messageUtil,
        JWTUtil jwtUtil) {

        this.authenticationConfiguration = authenticationConfiguration;
        this.loginSuccessHandler = loginSuccessHandler;
        this.memberRepository = memberRepository;
        this.messageUtil = messageUtil;
        this.jwtUtil = jwtUtil;

    }

    // 커스텀 자체 로그인 필터를 위한 AuthenticationManager Bean 수동 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        
        return new BCryptPasswordEncoder();
    }

    // Security FilterChain
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // csrf 보안 필터 disable
        http
                .csrf(AbstractHttpConfigurer::disable);

        //=================================== CORS 설정 ===================================//
        http
                .cors(cors -> cors
                        .configurationSource(corsConfigurationSource()));

        // 기본 Form 기반 인증 필터들 disable
        http
                .formLogin(AbstractHttpConfigurer::disable);

        // 기본 Basic 인증 필터 disable
        http
                .httpBasic(AbstractHttpConfigurer::disable);

        // 인가 설정
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/api/auth/refresh").permitAll() // 로그인, 토큰 재발급은 인증 불필요
                        .requestMatchers("/api/member", "/api/member/exists").permitAll() // 회원가입, 중복 체크는 인증 불필요
                        .requestMatchers("/api/admin/**").hasRole("ADMIN") // 관리자 API는 ADMIN 권한 필요 (ROLE_ 자동 추가)
                        .anyRequest().authenticated()); // 그 외 모든 요청은 인증 필요 (로그아웃 포함)

        // 예외 처리
        http
                .exceptionHandling(e -> e
                        .authenticationEntryPoint((request, response, exception) -> {
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED); // 401 응답
                        })
                        .accessDeniedHandler((request, response, exception) -> {
                            response.sendError(HttpServletResponse.SC_FORBIDDEN); // 403 응답
                        })
                );

        // 세션 필터 설정 (STATELESS)
        http
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // 커스텀 필터 추가
        LoginFilter loginFilter = new LoginFilter(
            authenticationManager(authenticationConfiguration), 
            loginSuccessHandler, 
            memberRepository, 
            messageUtil
        );
        JWTFilter jwtFilter = new JWTFilter(jwtUtil, messageUtil);
        
        http
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)  // JWT 필터를 먼저 추가
                .addFilterBefore(loginFilter, UsernamePasswordAuthenticationFilter.class); // 로그인 필터 추가

        return http.build();
    }

    // CORS 설정
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // 허용할 origin 설정 (프론트엔드 주소)
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000", "http://localhost:5173"));
        
        // 허용할 HTTP 메소드
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        
        // 허용할 헤더
        configuration.setAllowedHeaders(Arrays.asList("*"));
        
        // 인증 정보 허용
        configuration.setAllowCredentials(true);
        
        // preflight 요청 캐시 시간 (초)
        configuration.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        
        return source;
    }

}
