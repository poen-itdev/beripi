package com.poen.beripi.domain.member.service;

import java.nio.file.AccessDeniedException;
import java.time.LocalDateTime;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.poen.beripi.domain.member.dto.MemberRequestDto;
import com.poen.beripi.domain.member.entity.Member;
import com.poen.beripi.domain.member.entity.RoleType;
import com.poen.beripi.domain.member.repository.MemberRepository;
import com.poen.beripi.utils.MessageUtil;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MemberService implements UserDetailsService{
    
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final MessageUtil messageUtil;

    // 존재 여부
    public Boolean existMember(MemberRequestDto dto) {

        return memberRepository.existsByMemberEmail(dto.getMemberId());
    }

    // 회원 등록
    @Transactional
    public String addMember(MemberRequestDto dto) {

        // 존재 여부 확인
        if(memberRepository.existsByMemberEmail(dto.getMemberId())) {

            throw new IllegalArgumentException(messageUtil.getMessage("error.member.already.exists"));
        }

        Member member = Member.builder()
            .memberId(dto.getMemberId())
            .memberEmail(dto.getMemberEmail())
            .memberPw(passwordEncoder.encode(dto.getMemberPw()))
            .memberName(dto.getMemberName())
            .memberDepartment(dto.getMemberDepartment())
            .useYn("Y")
            .regId("admin")
            .regDate(LocalDateTime.now())
            .updateId("admin")
            .updateDate(LocalDateTime.now())
            .role(RoleType.USER)
            .isFirstLogin("Y")
            .build();

        return memberRepository.save(member).getMemberId();
    }

    // 회원 정보 수정
    public String updateMember(String memberId, MemberRequestDto dto) throws AccessDeniedException {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean isAdmin = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));

        if (!isAdmin) {
            throw new AccessDeniedException(messageUtil.getMessage("error.access.admin.only"));
        }

        Member member = memberRepository.findByMemberId(memberId)
                .orElseThrow(() -> new EntityNotFoundException(messageUtil.getMessage("error.member.not.found") + " email=" + memberId));

        member.updateMember(dto);
        memberRepository.save(member);

        return member.getMemberId();
    }

    // 로그인
    @Override
    public UserDetails loadUserByUsername(String memberId) throws UsernameNotFoundException {

        // MemberId 와 MemberPw로 로그인하기 때문에 memberId로 파라미터를 받음. 
        Member member = memberRepository.findByMemberId(memberId)
                .orElseThrow(() -> new UsernameNotFoundException(memberId));

        // useYn이 N이면 비활성화된 회원 - 로그인 불가
        if ("N".equals(member.getUseYn())) {
            throw new UsernameNotFoundException(messageUtil.getMessage("error.member.deactivated"));
        }

        // 조회한 entity를 기반으로 UserDetails를 만들어서 반환
        return User.builder()
                .username(member.getMemberId())
                .password(member.getMemberPw())
                .authorities(member.getRole().name())
                .build();
    }
}
