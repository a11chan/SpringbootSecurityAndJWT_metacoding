package com.cos.jwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.auth.PrincipalDetails;
import com.cos.jwt.model.Users;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

// 시큐리티의 필터 상속
// /login 경로 요청해서 username, password 전송하면(post)
// UsernamePasswordAuthenticationFilter 이 동작하지만 form login이 비활성화 상태면
// 시큐리티 필터체인에 직접 등록 필요
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // 로그인 요청을 하면, 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter.attemptAuthentication");

        // 1. DB에서 로그인 정보 받아서 정상 로그인 시도
        try {
//            BufferedReader br = request.getReader();
//            String input = null;
//            while ((input = br.readLine()) != null) {
//                System.out.println("input = " + input);
//            }
            ObjectMapper om = new ObjectMapper();
            Users user = om.readValue(request.getInputStream(), Users.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService.loadUserByUsername() 실행 후 정상이면
            // DB에 있는 username, password가 일치한다는 의미
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);

            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal(); // 로그인 정보 불러오기
            System.out.println("principalDetails(로그인 완료) = " + principalDetails.getUser().getUsername());
            // 여기까지 코드가 실행되었다면 로그인 성공의 뜻
            // 인증 정보를 세션에 저장하고 authentication 객체를 리턴
            // 스프링 시큐리티가 권한 관리를 대신 해주기 때문
            // 이를 위해 SecurityFilterChain에서 세션에 반환
            return authentication;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    // attemptAuthentication() 정상 실행 되면 아래 함수 실행됨
    // 이 메서드에서 JWT 토큰 만들어서 request 요청한 사용자아게 토큰 반환
    // Hash 암호 방식
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("JwtAuthenticationFilter.successfulAuthentication 실행됨(사용자 인증 완료)");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject("cos토큰") // 토큰 제목(이름)
                .withExpiresAt(new Date(System.currentTimeMillis()+(1000*60*10)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos")); //시크릿키 암호화

        response.addHeader("Authorization", "Bearer "+jwtToken);
    }
}
