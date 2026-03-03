package com.eswar.authenticationservice.service;

import com.eswar.authenticationservice.dto.AccessTokenResponseDto;
import com.eswar.authenticationservice.dto.AuthenticationResponseDto;
import com.eswar.authenticationservice.dto.LoginRequestDto;
import com.eswar.authenticationservice.dto.RefreshTokenRequestDto;
import com.eswar.grpc.user.UserResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationServiceImp implements IAuthenticationService {

    @Value("${jwt.access.expiration}")
    private long accessExpiration;

     private final JwtService jwtService;

    private final GrpcUserServiceClient client;

    private final PasswordEncoder passwordEncoder;

    @Override
    public AuthenticationResponseDto login(LoginRequestDto request) {

        UserResponse user = client.getUserByEmail(request.email());

log.info("Receive user from grpc of getByUserByEmail {}",user.getEmail());

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }

        Set<String> roles = new HashSet<>(user.getRolesList());

        String accessToken = jwtService.generateAccessToken(user.getEmail(), roles);
        String refreshToken = jwtService.generateRefreshToken(user.getEmail());

        return new AuthenticationResponseDto(
                accessToken,
                refreshToken,
                "JWT",
                accessExpiration,
                Instant.now(),
                user.getEmail(),
                roles
        );
    }

    @Override
    public AccessTokenResponseDto refresh(RefreshTokenRequestDto request) {

        return null;
    }
}
