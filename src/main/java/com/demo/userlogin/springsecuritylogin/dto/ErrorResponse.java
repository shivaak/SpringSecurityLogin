package com.demo.userlogin.springsecuritylogin.dto;

import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.util.Map;

@Getter
@Setter
@Builder
public class ErrorResponse {
    private String errorCode;
    private String errorMessage;
    private Map<String, String> errors;
}
