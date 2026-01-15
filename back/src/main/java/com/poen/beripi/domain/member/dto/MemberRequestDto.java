package com.poen.beripi.domain.member.dto;

import com.poen.beripi.domain.member.entity.RoleType;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class MemberRequestDto { // 회원 등록

    public interface existGroup {} // 회원 가입시 username 존재 확인
    public interface addGroup {} // 회원 가입시
    public interface passwordGroup {} // 비밀번호 변경시
    public interface updateGroup {} // 회원 수정시
    public interface deleteGroup {} // 회원 삭제시
    
    @NotBlank(groups = {existGroup.class, addGroup.class, deleteGroup.class}) @Size(min = 2)
    private String memberId;

    @Email(groups = {addGroup.class, updateGroup.class, existGroup.class})
    private String memberEmail;

    @NotBlank(groups = {addGroup.class, passwordGroup.class}) @Size(min = 4)
    private String memberPw;

    @NotBlank(groups = {addGroup.class, updateGroup.class})
    private String memberName;

    @NotBlank(groups = {addGroup.class, updateGroup.class})
    private String memberDepartment;

    @NotBlank(groups = {addGroup.class, updateGroup.class})
    private String memberPosition;

    @NotNull(groups = {addGroup.class, updateGroup.class})
    private RoleType role;
}
