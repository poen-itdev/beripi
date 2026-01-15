package com.poen.beripi.domain.member.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.poen.beripi.domain.member.entity.Member;

public interface MemberRepository extends JpaRepository<Member, String>{
    
    // 존재 여부
    Boolean existsByMemberEmail(String memberEmail);

    Optional<Member> findByMemberId(String memberId);

    Optional<Member> findByMemberEmail(String memberEmail);
}
