package com.poen.beripi.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StreamUtils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.poen.beripi.domain.member.entity.Member;
import com.poen.beripi.domain.member.repository.MemberRepository;
import com.poen.beripi.utils.MessageUtil;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class LoginFilter extends AbstractAuthenticationProcessingFilter { // 인증처리 필터
    
    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final MemberRepository memberRepository;
    private MessageUtil messageUtil;

    public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "memberId";
    public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "memberPw";

    private static final RequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = PathPatternRequestMatcher.withDefaults()
            .matcher(HttpMethod.POST, "/login");

    private String usernameParameter = SPRING_SECURITY_FORM_USERNAME_KEY;

    private String passwordParameter = SPRING_SECURITY_FORM_PASSWORD_KEY;

    public LoginFilter(AuthenticationManager authenticationManager, AuthenticationSuccessHandler authenticationSuccessHandler, MemberRepository memberRepository, MessageUtil messageUtil) {

        super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.memberRepository = memberRepository;
        this.messageUtil = messageUtil;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
                
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        Map<String, String> loginMap;

        try {
            ObjectMapper objectMapper = new ObjectMapper();
            ServletInputStream inputStream = request.getInputStream();
            String messageBody = StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);
            loginMap = objectMapper.readValue(messageBody, new TypeReference<>() {});

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        String username = loginMap.get(usernameParameter);
        username = (username != null) ? username.trim() : "";
        String password = loginMap.get(passwordParameter);
        password = (password != null) ? password : "";

        // useYn 체크 - 비활성화된 회원이면 로그인 불가
        Optional<Member> memberOpt = memberRepository.findByMemberId(username);
        if (memberOpt.isPresent()) {
            Member member = memberOpt.get();
            if ("N".equals(member.getUseYn())) {
                throw new BadCredentialsException(messageUtil.getMessage("error.member.deactivated"));
            }
        }

        UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken.unauthenticated(username,password);

        setDetails(request, authRequest);
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    protected void setDetails(HttpServletRequest request, UsernamePasswordAuthenticationToken authRequest) {
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

        authenticationSuccessHandler.onAuthenticationSuccess(request, response, authResult);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                             AuthenticationException failed) throws IOException, ServletException {
        
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json;charset=UTF-8");
        
        String errorType = "INVALID_CREDENTIALS"; // 기본: 아이디/비밀번호 틀림
        
        // 예외 체인을 재귀적으로 탐색하여 비활성화된 회원 메시지 찾기
        String deactivatedMessage = messageUtil.getMessage("error.member.deactivated");
        Throwable current = failed;
        int depth = 0;
        while (current != null && depth < 10) { // 무한 루프 방지
            String message = current.getMessage();
            
            if (message != null && message.contains(deactivatedMessage)) {
                errorType = "DEACTIVATED_USER"; // 비활성화된 회원
                break;
            }
            current = current.getCause();
            depth++;
        }
        
        String json = String.format("{\"errorType\":\"%s\"}", errorType);
        response.getWriter().write(json);
        response.getWriter().flush();
    }
}
