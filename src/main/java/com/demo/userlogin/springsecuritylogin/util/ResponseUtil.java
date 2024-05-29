package com.demo.userlogin.springsecuritylogin.util;

import com.demo.userlogin.springsecuritylogin.dto.StandardResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public class ResponseUtil {

    public static <T> ResponseEntity<StandardResponse<T>> buildResponse(T data, HttpStatus status) {
        StandardResponse<T> response = new StandardResponse<>(data);
        return new ResponseEntity<>(response, status);
    }

    public static <T> ResponseEntity<StandardResponse<T>> buildResponse(T data, String message, HttpStatus status) {
        StandardResponse<T> response = new StandardResponse<>(data, message);
        return new ResponseEntity<>(response, status);
    }

    public static <T> ResponseEntity<StandardResponse<T>> buildResponse(T data, String message, HttpStatus status, boolean success) {
        StandardResponse<T> response = new StandardResponse<>(data, message, success);
        return new ResponseEntity<>(response, status);
    }
}