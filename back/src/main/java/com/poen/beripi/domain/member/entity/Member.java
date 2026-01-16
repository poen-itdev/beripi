package com.poen.beripi.domain.member.entity;

import java.time.LocalDateTime;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.poen.beripi.domain.member.dto.MemberRequestDto;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@EntityListeners(AuditingEntityListener.class)
@Table(name = "member")
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Member {
    
    @Id
    @Column(name = "member_id")
    private String memberId;

    @Column(name = "member_pw")
    private String memberPw;

    @Column(name = "member_name")
    private String memberName;

    @Column(name = "member_email")
    private String memberEmail;

    @Column(name = "member_department")
    private String memberDepartment;

    @Column(name = "member_position")
    private String memberPosition;

    @Enumerated(EnumType.STRING)
    @Column(name = "role")
    private RoleType role;

    @Column(name = "is_first_login")
    private String isFirstLogin;

    @Column(name = "use_yn")
    private String useYn;

    @Column(name = "reg_id")
    private String regId;

    @CreatedDate
    @Column(name = "reg_dt")
    private LocalDateTime regDt;

    @Column(name = "chg_id")
    private String chgId;

    @Column(name = "chg_dt")
    @LastModifiedDate
    private LocalDateTime chgDt;

    //== 메서드 ==// 
    public void updateMember(MemberRequestDto dto) {

        this.memberEmail = dto.getMemberEmail();
        this.memberName = dto.getMemberName();
        this.memberDepartment = dto.getMemberDepartment();
        this.memberPosition = dto.getMemberPosition();
        this.role = dto.getRole();
    }
}
