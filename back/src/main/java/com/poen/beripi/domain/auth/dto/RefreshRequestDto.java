package com.poen.beripi.domain.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RefreshRequestDto {
    
    @NotBlank(message = "리프레시 토큰을 입력해주세요")
    private String refreshToken;
}

