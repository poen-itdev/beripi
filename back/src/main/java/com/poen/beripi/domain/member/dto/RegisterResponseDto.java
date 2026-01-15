package com.poen.beripi.domain.member.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterResponseDto {
    
    private String memberId;
    private String memberEmail;
    private String memberName;
    private String message;
}


