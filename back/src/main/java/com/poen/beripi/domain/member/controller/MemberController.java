package com.poen.beripi.domain.member.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.poen.beripi.domain.member.dto.MemberRequestDto;
import com.poen.beripi.domain.member.dto.RegisterResponseDto;
import com.poen.beripi.domain.member.service.MemberService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/member")
@RequiredArgsConstructor
public class MemberController {
    
    private final MemberService memberService;
    
    // 회원 중복 확인
    @GetMapping("/exists")
    public ResponseEntity<Boolean> checkMemberExists(@RequestParam String memberId) {
        
        MemberRequestDto dto = new MemberRequestDto();
        dto.setMemberId(memberId);
        
        boolean exists = memberService.existMember(dto);
        return ResponseEntity.ok(exists);
    }
    
    // 회원 등록
    @PostMapping
    public ResponseEntity<RegisterResponseDto> registerMember(
            @Validated(MemberRequestDto.addGroup.class) @RequestBody MemberRequestDto dto) {
        
        // 회원 등록 처리
        String memberId = memberService.addMember(dto);
        
        // 응답 DTO 생성
        RegisterResponseDto response = RegisterResponseDto.builder()
                .memberId(memberId)
                .memberEmail(dto.getMemberEmail())
                .memberName(dto.getMemberName())
                .message("회원가입이 완료되었습니다.")
                .build();
        
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
    
}
